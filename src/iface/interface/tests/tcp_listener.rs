use super::*;
use crate::iface::TcpListenRegistry;
use crate::socket::tcp;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicUsize, Ordering};

#[derive(Debug)]
struct Registry {
    endpoint: IpEndpoint,
    calls: AtomicUsize,
}

impl TcpListenRegistry for Registry {
    fn is_listening(&self, endpoint: IpEndpoint) -> bool {
        self.calls.fetch_add(1, Ordering::Relaxed);
        endpoint == self.endpoint
    }
}

fn syn() -> TcpRepr<'static> {
    TcpRepr {
        src_port: 4242,
        dst_port: 4243,
        control: TcpControl::Syn,
        seq_number: TcpSeqNumber(100),
        ack_number: None,
        window_len: 256,
        window_scale: None,
        max_seg_size: None,
        sack_permitted: false,
        sack_ranges: [None; 3],
        timestamp: None,
        payload: &[],
    }
}

fn emit(ip: &IpRepr, tcp: &TcpRepr) -> Vec<u8> {
    let mut bytes = vec![0; tcp.buffer_len()];
    tcp.emit(
        &mut TcpPacket::new_unchecked(&mut bytes),
        &ip.src_addr(),
        &ip.dst_addr(),
        &ChecksumCapabilities::default(),
    );
    bytes
}

#[test]
#[cfg(feature = "proto-ipv4")]
fn listener_fallback_ipv4() {
    listener_fallback(IpRepr::Ipv4(Ipv4Repr {
        src_addr: Ipv4Address::new(192, 168, 1, 2),
        dst_addr: Ipv4Address::new(192, 168, 1, 1),
        next_header: IpProtocol::Tcp,
        payload_len: 20,
        hop_limit: 64,
    }));
}
#[test]
#[cfg(feature = "proto-ipv6")]
fn listener_fallback_ipv6() {
    listener_fallback(IpRepr::Ipv6(Ipv6Repr {
        src_addr: Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 2),
        dst_addr: Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 1),
        next_header: IpProtocol::Tcp,
        payload_len: 20,
        hop_limit: 64,
    }));
}

fn listener_fallback(ip: IpRepr) {
    let (mut iface, mut sockets, _) = setup(Medium::Ip);
    let mut tcp = syn();
    let registry = Arc::new(Registry {
        endpoint: IpEndpoint::new(ip.dst_addr(), tcp.dst_port),
        calls: AtomicUsize::new(0),
    });
    let bytes = emit(&ip, &tcp);
    assert!(iface
        .inner
        .process_tcp(&mut sockets, ip.clone(), &bytes)
        .is_some());
    assert!(sockets
        .set_tcp_listen_registry(Some(registry.clone()))
        .is_none());
    assert!(iface
        .inner
        .process_tcp(&mut sockets, ip.clone(), &bytes)
        .is_none());
    assert_eq!(registry.calls.load(Ordering::Relaxed), 1);

    // A different port or destination address is not covered by the registry.
    tcp.dst_port += 1;
    assert!(iface
        .inner
        .process_tcp(&mut sockets, ip.clone(), &emit(&ip, &tcp))
        .is_some());
    tcp.dst_port -= 1;
    let other_ip = match ip.clone() {
        #[cfg(feature = "proto-ipv4")]
        IpRepr::Ipv4(mut repr) => {
            repr.dst_addr = repr.src_addr;
            IpRepr::Ipv4(repr)
        }
        #[cfg(feature = "proto-ipv6")]
        IpRepr::Ipv6(mut repr) => {
            repr.dst_addr = repr.src_addr;
            IpRepr::Ipv6(repr)
        }
    };
    assert!(iface
        .inner
        .process_tcp(&mut sockets, other_ip.clone(), &emit(&other_ip, &tcp))
        .is_some());
    let calls = registry.calls.load(Ordering::Relaxed);
    let mut corrupt = bytes.clone();
    corrupt[16] ^= 1;
    assert!(iface
        .inner
        .process_tcp(&mut sockets, ip.clone(), &corrupt)
        .is_none());
    assert!(iface
        .inner
        .process_tcp(&mut sockets, ip.clone(), &bytes[..10])
        .is_none());
    // SYN+ACK and ordinary ACK retain the closed-port reset; RST gets no reply.
    tcp.ack_number = Some(TcpSeqNumber(1));
    assert!(iface
        .inner
        .process_tcp(&mut sockets, ip.clone(), &emit(&ip, &tcp))
        .is_some());
    tcp.control = TcpControl::None;
    assert!(iface
        .inner
        .process_tcp(&mut sockets, ip.clone(), &emit(&ip, &tcp))
        .is_some());
    tcp.control = TcpControl::Rst;
    assert!(iface
        .inner
        .process_tcp(&mut sockets, ip.clone(), &emit(&ip, &tcp))
        .is_none());
    assert_eq!(registry.calls.load(Ordering::Relaxed), calls);
    assert!(sockets.set_tcp_listen_registry(None).is_some());
    assert!(iface
        .inner
        .process_tcp(&mut sockets, ip.clone(), &bytes)
        .is_some());
    assert_eq!(registry.calls.load(Ordering::Relaxed), calls);

    // A real listening socket, its SYN retransmission, and established data
    // take precedence over the registry, even though it matches the endpoint.
    sockets.set_tcp_listen_registry(Some(registry.clone()));
    let mut socket = tcp::Socket::new(
        tcp::SocketBuffer::new(vec![0; 128]),
        tcp::SocketBuffer::new(vec![0; 128]),
    );
    socket.listen(registry.endpoint).unwrap();
    let handle = sockets.add(socket);
    assert!(iface
        .inner
        .process_tcp(&mut sockets, ip.clone(), &bytes)
        .is_none());
    let mut server_seq = None;
    sockets
        .get_mut::<tcp::Socket>(handle)
        .dispatch(&mut iface.inner, |_, (_, repr)| {
            assert_eq!(repr.control, TcpControl::Syn);
            server_seq = Some(repr.seq_number);
            Ok::<(), ()>(())
        })
        .unwrap();
    let server_seq = server_seq.unwrap();
    assert_eq!(
        sockets.get::<tcp::Socket>(handle).state(),
        tcp::State::SynReceived
    );
    iface.inner.process_tcp(&mut sockets, ip.clone(), &bytes);
    tcp = syn();
    tcp.control = TcpControl::None;
    tcp.seq_number += 1;
    tcp.ack_number = Some(server_seq + 1);
    iface
        .inner
        .process_tcp(&mut sockets, ip.clone(), &emit(&ip, &tcp));
    assert_eq!(
        sockets.get::<tcp::Socket>(handle).state(),
        tcp::State::Established
    );
    tcp.payload = b"hello";
    iface
        .inner
        .process_tcp(&mut sockets, ip.clone(), &emit(&ip, &tcp));
    let mut received = [0; 5];
    assert_eq!(
        sockets
            .get_mut::<tcp::Socket>(handle)
            .recv_slice(&mut received),
        Ok(5)
    );
    assert_eq!(&received, b"hello");
    assert_eq!(registry.calls.load(Ordering::Relaxed), calls);
}

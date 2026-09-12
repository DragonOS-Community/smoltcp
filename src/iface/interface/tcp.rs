use super::*;

use crate::socket::tcp::{Socket, State};

impl InterfaceInner {
    pub fn process_tcp<'frame>(
        &mut self,
        sockets: &mut SocketSet,
        ip_repr: IpRepr,
        ip_payload: &'frame [u8],
    ) -> Option<Packet<'frame>> {
        let (src_addr, dst_addr) = (ip_repr.src_addr(), ip_repr.dst_addr());
        let tcp_packet = check!(TcpPacket::new_checked(ip_payload));
        let tcp_repr = check!(TcpRepr::parse(
            &tcp_packet,
            &src_addr,
            &dst_addr,
            &self.caps.checksum
        ));

        // Connected and half-open four-tuples must win even when a LISTEN slot
        // occurs earlier in the set (in particular for retransmitted SYNs).
        for tcp_socket in sockets
            .items_mut()
            .filter_map(|i| Socket::downcast_mut(&mut i.socket))
        {
            tcp_socket.rearm_listener();
            if tcp_socket.state() != State::Listen && tcp_socket.accepts(self, &ip_repr, &tcp_repr)
            {
                return tcp_socket
                    .process(self, &ip_repr, &tcp_repr)
                    .map(|(ip, tcp)| Packet::new(ip, IpPayload::Tcp(tcp)));
            }
        }

        let fresh_syn = tcp_repr.control == TcpControl::Syn && tcp_repr.ack_number.is_none();
        if fresh_syn {
            // Pending slots retain their original listen endpoint and identity, so
            // a full logical listener still participates in selection. Failed
            // pending slots were rearmed above; remaining Closed slots are excluded.
            let matches = |socket: &Socket| {
                socket.state() != State::Closed
                    && (socket.state() == State::Listen || socket.listener_id().is_some())
                    && socket.listener_enabled()
                    && socket.accepts_listener_endpoint(dst_addr, tcp_repr.dst_port)
            };
            // Exact address > family-qualified wildcard > unqualified wildcard.
            // The endpoint match above already excludes a different IP family.
            let specificity = |s: &Socket| match s.listen_endpoint().addr {
                Some(addr) if !addr.is_unspecified() => 2,
                Some(_) => 1,
                None => 0,
            };
            let tier = sockets
                .items()
                .filter_map(|i| Socket::downcast(&i.socket))
                .filter(|s| matches(s))
                .map(specificity)
                .max()
                .unwrap_or(0);
            let flow = listener_flow_hash(self.tcp_listener_seed, &ip_repr, &tcp_repr);
            // Registered logical listeners take precedence over legacy unregistered
            // slots within this address tier. With no IDs, retain first-match behavior.
            let selected = sockets
                .items()
                .filter_map(|i| Socket::downcast(&i.socket))
                .filter(|s| matches(s) && specificity(s) == tier)
                .filter_map(|s| s.listener_id())
                .max_by_key(|id| (listener_score(flow, *id), *id));
            for socket in sockets
                .items_mut()
                .filter_map(|i| Socket::downcast_mut(&mut i.socket))
            {
                if socket.state() == State::Listen
                    && matches(socket)
                    && specificity(socket) == tier
                    && socket.listener_id() == selected
                {
                    return socket
                        .process(self, &ip_repr, &tcp_repr)
                        .map(|(ip, tcp)| Packet::new(ip, IpPayload::Tcp(tcp)));
                }
            }
            if selected.is_some() {
                // The chosen logical listener is full. Never spill into a sibling
                // listener (or the less-specific address tier), and never send RST.
                return None;
            }
        } else {
            // Preserve ordinary smoltcp handling of non-SYN traffic to LISTEN.
            for socket in sockets
                .items_mut()
                .filter_map(|i| Socket::downcast_mut(&mut i.socket))
            {
                if socket.accepts(self, &ip_repr, &tcp_repr) {
                    return socket
                        .process(self, &ip_repr, &tcp_repr)
                        .map(|(ip, tcp)| Packet::new(ip, IpPayload::Tcp(tcp)));
                }
            }
        }

        if tcp_repr.control == TcpControl::Rst
            || ip_repr.dst_addr().is_unspecified()
            || ip_repr.src_addr().is_unspecified()
        {
            // Never reply to a TCP RST packet with another TCP RST packet. We also never want to
            // send a TCP RST packet with unspecified addresses.
            None
        } else {
            // The packet wasn't handled by a socket, send a TCP RST packet.
            let (ip, tcp) = tcp::Socket::rst_reply(&ip_repr, &tcp_repr);
            Some(Packet::new(ip, IpPayload::Tcp(tcp)))
        }
    }
}

// Allocation-free, deterministic hashing. The interface seed is independent of
// the mutable RNG used for sequence numbers. Hash the complete flow once and
// avalanche each opaque member ID for rendezvous ranking.
fn listener_flow_hash(seed: u64, ip: &IpRepr, tcp: &TcpRepr) -> u64 {
    use core::hash::{Hash, Hasher};
    struct FlowHasher(u64);
    impl Hasher for FlowHasher {
        fn finish(&self) -> u64 {
            self.0
        }
        fn write(&mut self, bytes: &[u8]) {
            for byte in bytes {
                self.0 = (self.0 ^ u64::from(*byte)).wrapping_mul(0x100000001b3);
            }
        }
    }
    let mut hash = FlowHasher(seed ^ 0xcbf29ce484222325);
    (ip.src_addr(), ip.dst_addr(), tcp.src_port, tcp.dst_port).hash(&mut hash);
    hash.finish()
}

fn listener_score(flow: u64, id: u64) -> u64 {
    let mut value = flow ^ id;
    value = (value ^ (value >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94d049bb133111eb);
    value ^ (value >> 31)
}

#[cfg(all(test, feature = "medium-ip"))]
mod tests {
    use super::*;
    use crate::socket::tcp::{SocketBuffer, State};
    use std::vec::Vec;

    fn listener(addr: Option<IpAddress>) -> Socket<'static> {
        let mut socket = Socket::new(
            SocketBuffer::new(vec![0; 256]),
            SocketBuffer::new(vec![0; 256]),
        );
        socket.listen(IpListenEndpoint { addr, port: 80 }).unwrap();
        socket
    }

    fn syn(
        iface: &mut Interface,
        sockets: &mut SocketSet,
        src: IpAddress,
        dst: IpAddress,
        port: u16,
    ) -> bool {
        let repr = TcpRepr {
            src_port: port,
            dst_port: 80,
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
        };
        send(iface, sockets, src, dst, repr).is_some()
    }

    fn send(
        iface: &mut Interface,
        sockets: &mut SocketSet,
        src: IpAddress,
        dst: IpAddress,
        repr: TcpRepr,
    ) -> Option<TcpControl> {
        let ip = IpRepr::new(src, dst, IpProtocol::Tcp, repr.buffer_len(), 64);
        let mut bytes = vec![0; repr.buffer_len()];
        repr.emit(
            &mut TcpPacket::new_unchecked(&mut bytes),
            &src,
            &dst,
            &iface.inner.caps.checksum,
        );
        let reply = iface.inner.process_tcp(sockets, ip, &bytes);
        reply.as_ref().map(|p| match p.payload() {
            IpPayload::Tcp(tcp) => tcp.control,
            _ => panic!("expected TCP reply"),
        })
    }

    #[test]
    fn listener_exact_precedes_wildcard() {
        for (src, dst) in addresses() {
            let (mut iface, mut sockets, _) = crate::tests::setup(Medium::Ip);
            let wildcard = sockets.add(listener(None));
            let exact = sockets.add(listener(Some(dst)));
            syn(&mut iface, &mut sockets, src, dst, 1000);
            assert_eq!(sockets.get::<Socket>(exact).state(), State::SynReceived);
            assert_eq!(sockets.get::<Socket>(wildcard).state(), State::Listen);
        }
    }
    fn addresses() -> Vec<(IpAddress, IpAddress)> {
        vec![
            #[cfg(feature = "proto-ipv4")]
            (IpAddress::v4(192, 168, 1, 2), IpAddress::v4(192, 168, 1, 1)),
            #[cfg(feature = "proto-ipv6")]
            (
                IpAddress::v6(0xfe80, 0, 0, 0, 0, 0, 0, 2),
                IpAddress::v6(0xfe80, 0, 0, 0, 0, 0, 0, 1),
            ),
        ]
    }

    fn identified(addr: Option<IpAddress>, id: u64) -> Socket<'static> {
        let mut socket = listener(addr);
        socket.set_listener_id(Some(id));
        socket
    }

    #[test]
    fn listener_rendezvous_slot_count_and_order_independent() {
        for (src, dst) in addresses() {
            let mut wins = [0usize; 2];
            for port in 1000..1128 {
                let mut winners = Vec::new();
                for ids in [&[1, 2][..], &[2, 1][..], &[2, 1, 1, 1, 1, 1][..]] {
                    let (mut iface, mut sockets, _) = crate::tests::setup(Medium::Ip);
                    for _ in 0..ids.len() {
                        iface.inner.rand.rand_u32();
                    }
                    for id in ids {
                        sockets.add(identified(Some(dst), *id));
                    }
                    syn(&mut iface, &mut sockets, src, dst, port);
                    let winner = sockets
                        .items()
                        .filter_map(|i| Socket::downcast(&i.socket))
                        .find(|s| s.state() == State::SynReceived)
                        .unwrap()
                        .listener_id()
                        .unwrap();
                    winners.push(winner);
                }
                assert_eq!(winners, vec![winners[0]; 3]);
                wins[(winners[0] - 1) as usize] += 1;
            }
            assert!(
                wins.iter().all(|count| (40..=88).contains(count)),
                "{wins:?}"
            );
        }
    }

    #[test]
    fn listener_full_drops_without_sibling_or_wildcard_fallback() {
        for (src, dst) in addresses() {
            let (mut iface, mut sockets, _) = crate::tests::setup(Medium::Ip);
            let first = sockets.add(identified(Some(dst), 1));
            let second = sockets.add(identified(Some(dst), 2));
            let wildcard = sockets.add(identified(None, 3));
            syn(&mut iface, &mut sockets, src, dst, 1000);
            let busy = if sockets.get::<Socket>(first).state() == State::SynReceived {
                first
            } else {
                second
            };
            let idle = if busy == first { second } else { first };
            // Retransmission must route to the half-open tuple, not consume a free slot.
            syn(&mut iface, &mut sockets, src, dst, 1000);
            assert_eq!(sockets.get::<Socket>(idle).state(), State::Listen);
            let mut dropped = false;
            for port in 1001..1100 {
                // Reset the unselected member after any connections it receives.
                if sockets.get::<Socket>(idle).state() != State::Listen {
                    let id = sockets.get::<Socket>(idle).listener_id();
                    let s = sockets.get_mut::<Socket>(idle);
                    s.abort();
                    s.listen((dst, 80)).unwrap();
                    s.set_listener_id(id);
                }
                let replied = syn(&mut iface, &mut sockets, src, dst, port);
                if sockets.get::<Socket>(idle).state() == State::Listen {
                    assert!(!replied);
                    dropped = true;
                    break;
                }
            }
            assert!(dropped);
            assert_eq!(sockets.get::<Socket>(wildcard).state(), State::Listen);
        }
    }

    #[test]
    fn listener_legacy_mixed_and_unmatched() {
        for (src, dst) in addresses() {
            let (mut iface, mut sockets, _) = crate::tests::setup(Medium::Ip);
            assert!(syn(&mut iface, &mut sockets, src, dst, 1000)); // unmatched RST
            let legacy = sockets.add(listener(Some(dst)));
            let registered = sockets.add(identified(Some(dst), 1));
            syn(&mut iface, &mut sockets, src, dst, 1000);
            assert_eq!(sockets.get::<Socket>(legacy).state(), State::Listen);
            assert_eq!(
                sockets.get::<Socket>(registered).state(),
                State::SynReceived
            );
            assert!(!syn(&mut iface, &mut sockets, src, dst, 1001));
            assert_eq!(sockets.get::<Socket>(legacy).state(), State::Listen);
            sockets.get_mut::<Socket>(registered).abort();
            assert_eq!(sockets.get::<Socket>(registered).listener_id(), None);
            syn(&mut iface, &mut sockets, src, dst, 1001);
            assert_eq!(sockets.get::<Socket>(legacy).state(), State::SynReceived);
        }
    }

    #[test]
    fn listener_identity_close_and_reinitialize() {
        let mut socket = identified(None, 7);
        socket.close();
        assert_eq!(socket.listener_id(), None);
        socket.set_listener_id(Some(8));
        socket.listen(80).unwrap();
        assert_eq!(socket.listener_id(), None);
    }

    #[test]
    fn listener_pending_reset_and_established_tuple_priority() {
        for (src, dst) in addresses() {
            let (mut iface, mut sockets, _) = crate::tests::setup(Medium::Ip);
            // Exact pending connection is inserted after a wildcard listener.
            let spare = sockets.add(identified(None, 2));
            let pending = sockets.add(identified(Some(dst), 1));
            syn(&mut iface, &mut sockets, src, dst, 1000);
            let ack = sockets.get::<Socket>(pending).local_seq_no() + 1;
            let mut packet = TcpRepr {
                src_port: 1000,
                dst_port: 80,
                control: TcpControl::Rst,
                seq_number: TcpSeqNumber(101),
                ack_number: Some(ack),
                window_len: 256,
                window_scale: None,
                max_seg_size: None,
                sack_permitted: false,
                sack_ranges: [None; 3],
                timestamp: None,
                payload: &[],
            };
            send(&mut iface, &mut sockets, src, dst, packet);
            assert_eq!(sockets.get::<Socket>(pending).state(), State::Listen);
            assert_eq!(sockets.get::<Socket>(pending).listener_id(), Some(1));
            syn(&mut iface, &mut sockets, src, dst, 1000);
            packet.control = TcpControl::None;
            packet.ack_number = Some(sockets.get::<Socket>(pending).local_seq_no() + 1);
            send(&mut iface, &mut sockets, src, dst, packet);
            assert_eq!(sockets.get::<Socket>(pending).state(), State::Established);
            assert_eq!(sockets.get::<Socket>(pending).listener_id(), Some(1));
            // Accepted connections no longer count as listener members, but retain tuple priority.
            sockets.get_mut::<Socket>(pending).set_listener_id(None);
            syn(&mut iface, &mut sockets, src, dst, 1000);
            assert_eq!(sockets.get::<Socket>(spare).state(), State::Listen);
            sockets.get_mut::<Socket>(pending).set_listener_id(Some(1));
            packet.control = TcpControl::Rst;
            send(&mut iface, &mut sockets, src, dst, packet);
            assert_eq!(sockets.get::<Socket>(pending).state(), State::Closed);
            assert_eq!(sockets.get::<Socket>(pending).listener_id(), Some(1));
        }
    }
    #[test]
    #[cfg(all(feature = "proto-ipv4", feature = "proto-ipv6"))]
    fn listener_family_wildcards_do_not_cross_match() {
        for (src, dst) in addresses() {
            let (mut iface, mut sockets, _) = crate::tests::setup(Medium::Ip);
            let v4 = sockets.add(identified(Some(IpAddress::v4(0, 0, 0, 0)), 1));
            let v6 = sockets.add(identified(Some(IpAddress::v6(0, 0, 0, 0, 0, 0, 0, 0)), 2));
            syn(&mut iface, &mut sockets, src, dst, 1000);
            let (matching, other) = if dst.version() == IpVersion::Ipv4 {
                (v4, v6)
            } else {
                (v6, v4)
            };
            assert_eq!(sockets.get::<Socket>(matching).state(), State::SynReceived);
            assert_eq!(sockets.get::<Socket>(other).state(), State::Listen);
            // An exact listener takes precedence over the same-family wildcard,
            // even when that wildcard already has pending connections.
            let exact = sockets.add(identified(Some(dst), 3));
            syn(&mut iface, &mut sockets, src, dst, 1001);
            assert_eq!(sockets.get::<Socket>(exact).state(), State::SynReceived);
        }
    }

    #[test]
    fn listener_activation_preserves_identity_and_existing_tuple() {
        for (src, dst) in addresses() {
            let (mut iface, mut sockets, _) = crate::tests::setup(Medium::Ip);
            let member = sockets.add(identified(Some(dst), 1));
            let slot = sockets.get_mut::<Socket>(member);
            slot.set_listener_enabled(false);
            assert!(!slot.listener_enabled());
            assert_eq!(slot.listener_id(), Some(1));
            assert!(syn(&mut iface, &mut sockets, src, dst, 1000));
            assert_eq!(sockets.get::<Socket>(member).state(), State::Listen);
            sockets.get_mut::<Socket>(member).set_listener_enabled(true);
            syn(&mut iface, &mut sockets, src, dst, 1000);
            assert_eq!(sockets.get::<Socket>(member).state(), State::SynReceived);
            sockets
                .get_mut::<Socket>(member)
                .set_listener_enabled(false);
            let packet = TcpRepr {
                src_port: 1000,
                dst_port: 80,
                control: TcpControl::None,
                seq_number: TcpSeqNumber(101),
                ack_number: Some(sockets.get::<Socket>(member).local_seq_no() + 1),
                window_len: 256,
                window_scale: None,
                max_seg_size: None,
                sack_permitted: false,
                sack_ranges: [None; 3],
                timestamp: None,
                payload: &[],
            };
            send(&mut iface, &mut sockets, src, dst, packet);
            assert_eq!(sockets.get::<Socket>(member).state(), State::Established);
            sockets.get_mut::<Socket>(member).abort();
            assert!(sockets.get::<Socket>(member).listener_enabled());
            assert_eq!(sockets.get::<Socket>(member).listener_id(), None);
        }
    }
    #[test]
    fn listener_pending_reset_rearms_before_next_syn() {
        for (src, dst) in addresses() {
            for with_wildcard in [false, true] {
                let (mut iface, mut sockets, _) = crate::tests::setup(Medium::Ip);
                let spare = with_wildcard.then(|| sockets.add(identified(None, 2)));
                let member = sockets.add(identified(Some(dst), 1));
                syn(&mut iface, &mut sockets, src, dst, 1000);
                let mut packet = TcpRepr {
                    src_port: 1000,
                    dst_port: 80,
                    control: TcpControl::None,
                    seq_number: TcpSeqNumber(101),
                    ack_number: Some(sockets.get::<Socket>(member).local_seq_no() + 1),
                    window_len: 256,
                    window_scale: None,
                    max_seg_size: None,
                    sack_permitted: false,
                    sack_ranges: [None; 3],
                    timestamp: None,
                    payload: &[],
                };
                send(&mut iface, &mut sockets, src, dst, packet);
                assert_eq!(sockets.get::<Socket>(member).state(), State::Established);
                packet.control = TcpControl::Rst;
                send(&mut iface, &mut sockets, src, dst, packet);
                // No application/consumer notification between the RST and SYN.
                syn(&mut iface, &mut sockets, src, dst, 1001);
                assert_eq!(sockets.get::<Socket>(member).state(), State::SynReceived);
                assert_eq!(sockets.get::<Socket>(member).listener_id(), Some(1));
                if let Some(spare) = spare {
                    assert_eq!(sockets.get::<Socket>(spare).state(), State::Listen);
                }
                packet.src_port = 1001;
                packet.control = TcpControl::None;
                packet.ack_number = Some(sockets.get::<Socket>(member).local_seq_no() + 1);
                send(&mut iface, &mut sockets, src, dst, packet);
                assert_eq!(sockets.get::<Socket>(member).state(), State::Established);
                sockets.get_mut::<Socket>(member).set_listener_id(None); // accept handoff
                packet.control = TcpControl::Rst;
                send(&mut iface, &mut sockets, src, dst, packet);
                syn(&mut iface, &mut sockets, src, dst, 1002);
                assert_eq!(sockets.get::<Socket>(member).state(), State::Closed);
                assert_eq!(sockets.get::<Socket>(member).listener_id(), None);
            }
        }
    }

    #[test]
    fn listener_timeout_rearm_preserves_activation_and_explicit_teardown() {
        for (src, dst) in addresses() {
            for abort in [false, true] {
                let (mut iface, mut sockets, _) = crate::tests::setup(Medium::Ip);
                let member = sockets.add(identified(Some(dst), 1));
                sockets
                    .get_mut::<Socket>(member)
                    .set_timeout(Some(crate::time::Duration::from_millis(1)));
                syn(&mut iface, &mut sockets, src, dst, 1000);
                sockets
                    .get_mut::<Socket>(member)
                    .set_listener_enabled(false);
                iface.inner.set_now(crate::time::Instant::from_millis(10));
                sockets
                    .get_mut::<Socket>(member)
                    .dispatch(&mut iface.inner, |_, (_, tcp)| {
                        assert_eq!(tcp.control, TcpControl::Rst);
                        Ok::<_, ()>(())
                    })
                    .unwrap();
                assert_eq!(sockets.get::<Socket>(member).state(), State::Closed);
                assert_eq!(sockets.get::<Socket>(member).listener_id(), Some(1));
                syn(&mut iface, &mut sockets, src, dst, 1001);
                assert_eq!(sockets.get::<Socket>(member).state(), State::Listen);
                assert!(!sockets.get::<Socket>(member).listener_enabled());
                sockets.get_mut::<Socket>(member).set_listener_enabled(true);
                syn(&mut iface, &mut sockets, src, dst, 1001);
                assert_eq!(sockets.get::<Socket>(member).state(), State::SynReceived);
                // Explicit teardown clears the ownership token, unlike an internal timeout.
                if abort {
                    sockets.get_mut::<Socket>(member).abort();
                } else {
                    sockets.get_mut::<Socket>(member).close();
                }
                assert_eq!(sockets.get::<Socket>(member).listener_id(), None);
                syn(&mut iface, &mut sockets, src, dst, 1002);
                assert!(!matches!(
                    sockets.get::<Socket>(member).state(),
                    State::Listen | State::SynReceived
                ));
            }
        }
    }
    #[test]
    fn listener_family_wildcard_precedes_unqualified_wildcard() {
        for (src, dst) in addresses() {
            let (mut iface, mut sockets, _) = crate::tests::setup(Medium::Ip);
            let family_address = match dst {
                #[cfg(feature = "proto-ipv4")]
                IpAddress::Ipv4(_) => IpAddress::v4(0, 0, 0, 0),
                #[cfg(feature = "proto-ipv6")]
                IpAddress::Ipv6(_) => IpAddress::v6(0, 0, 0, 0, 0, 0, 0, 0),
            };
            let unqualified = sockets.add(identified(None, 2));
            let family = sockets.add(identified(Some(family_address), 1));
            syn(&mut iface, &mut sockets, src, dst, 1000);
            assert_eq!(sockets.get::<Socket>(family).state(), State::SynReceived);
            assert_eq!(sockets.get::<Socket>(unqualified).state(), State::Listen);
            // A full family-specific tier must not spill into the unqualified tier,
            // regardless of the flow's rendezvous score for the latter's identity.
            for port in 1001..1032 {
                assert!(!syn(&mut iface, &mut sockets, src, dst, port));
                assert_eq!(sockets.get::<Socket>(unqualified).state(), State::Listen);
            }
            for (other_src, other_dst) in addresses() {
                if other_dst.version() != dst.version() {
                    syn(&mut iface, &mut sockets, other_src, other_dst, 1000);
                    assert_eq!(
                        sockets.get::<Socket>(unqualified).state(),
                        State::SynReceived
                    );
                }
            }
        }
    }
}

use core::fmt;
use managed::ManagedSlice;

#[cfg(all(feature = "alloc", feature = "socket-udp"))]
use alloc::sync::Arc;

use super::socket_meta::Meta;
#[cfg(all(feature = "alloc", feature = "socket-udp"))]
use crate::phy::PacketMeta;
use crate::socket::{AnySocket, Socket};
#[cfg(all(feature = "alloc", feature = "socket-udp"))]
use crate::wire::{IpRepr, UdpRepr};

/// Result of offering a validated UDP datagram to an external ingress handler.
#[cfg(all(feature = "alloc", feature = "socket-udp"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpIngressResult {
    /// Continue with smoltcp's UDP and DNS socket demultiplexing.
    NotHandled,
    /// The handler consumed or deliberately dropped the datagram.
    ///
    /// smoltcp will not offer it to UDP/DNS sockets and will not emit an ICMP
    /// port-unreachable response.
    Consumed,
}

/// Optional external consumer for validated UDP ingress.
///
/// The callback runs after IP reassembly and UDP length/checksum validation,
/// but before smoltcp UDP and DNS socket demultiplexing.
/// `is_broadcast` reports limited or interface-directed IPv4 broadcast; it is
/// always false for IPv6.
#[cfg(all(feature = "alloc", feature = "socket-udp"))]
pub trait UdpIngressHandler: fmt::Debug + Send + Sync {
    fn handle_udp_ingress(
        &self,
        meta: PacketMeta,
        ip_repr: &IpRepr,
        udp_repr: &UdpRepr,
        is_broadcast: bool,
        payload: &[u8],
    ) -> UdpIngressResult;
}

/// Opaque struct with space for storing one socket.
///
/// This is public so you can use it to allocate space for storing
/// sockets when creating an Interface.
#[derive(Debug, Default)]
pub struct SocketStorage<'a> {
    inner: Option<Item<'a>>,
}

impl<'a> SocketStorage<'a> {
    pub const EMPTY: Self = Self { inner: None };
}

/// An item of a socket set.
#[derive(Debug)]
pub struct Item<'a> {
    pub meta: Meta,
    pub socket: Socket<'a>,
}

/// A handle, identifying a socket in an Interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct SocketHandle(usize);

impl fmt::Display for SocketHandle {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "#{}", self.0)
    }
}

/// An extensible set of sockets.
///
/// The lifetime `'a` is used when storing a `Socket<'a>`.  If you're using
/// owned buffers for your sockets (passed in as `Vec`s) you can use
/// `SocketSet<'static>`.
#[derive(Debug)]
pub struct SocketSet<'a> {
    sockets: ManagedSlice<'a, SocketStorage<'a>>,
    #[cfg(all(feature = "alloc", feature = "socket-udp"))]
    udp_ingress_handler: Option<Arc<dyn UdpIngressHandler>>,
}

impl<'a> SocketSet<'a> {
    /// Create a socket set using the provided storage.
    pub fn new<SocketsT>(sockets: SocketsT) -> SocketSet<'a>
    where
        SocketsT: Into<ManagedSlice<'a, SocketStorage<'a>>>,
    {
        let sockets = sockets.into();
        SocketSet {
            sockets,
            #[cfg(all(feature = "alloc", feature = "socket-udp"))]
            udp_ingress_handler: None,
        }
    }

    /// Install or remove the external UDP ingress handler.
    #[cfg(all(feature = "alloc", feature = "socket-udp"))]
    pub fn set_udp_ingress_handler(
        &mut self,
        handler: Option<Arc<dyn UdpIngressHandler>>,
    ) -> Option<Arc<dyn UdpIngressHandler>> {
        core::mem::replace(&mut self.udp_ingress_handler, handler)
    }

    #[cfg(all(feature = "alloc", feature = "socket-udp"))]
    pub(crate) fn handle_udp_ingress(
        &self,
        meta: PacketMeta,
        ip_repr: &IpRepr,
        udp_repr: &UdpRepr,
        is_broadcast: bool,
        payload: &[u8],
    ) -> UdpIngressResult {
        self.udp_ingress_handler
            .as_ref()
            .map_or(UdpIngressResult::NotHandled, |handler| {
                handler.handle_udp_ingress(meta, ip_repr, udp_repr, is_broadcast, payload)
            })
    }

    /// Add a socket to the set, and return its handle.
    ///
    /// # Panics
    /// This function panics if the storage is fixed-size (not a `Vec`) and is full.
    pub fn add<T: AnySocket<'a>>(&mut self, socket: T) -> SocketHandle {
        fn put<'a>(index: usize, slot: &mut SocketStorage<'a>, socket: Socket<'a>) -> SocketHandle {
            net_trace!("[{}]: adding", index);
            let handle = SocketHandle(index);
            let mut meta = Meta::default();
            meta.handle = handle;
            *slot = SocketStorage {
                inner: Some(Item { meta, socket }),
            };
            handle
        }

        let socket = socket.upcast();

        for (index, slot) in self.sockets.iter_mut().enumerate() {
            if slot.inner.is_none() {
                return put(index, slot, socket);
            }
        }

        match &mut self.sockets {
            ManagedSlice::Borrowed(_) => panic!("adding a socket to a full SocketSet"),
            #[cfg(feature = "alloc")]
            ManagedSlice::Owned(sockets) => {
                sockets.push(SocketStorage { inner: None });
                let index = sockets.len() - 1;
                put(index, &mut sockets[index], socket)
            }
        }
    }

    /// Get a socket from the set by its handle, as mutable.
    ///
    /// # Panics
    /// This function may panic if the handle does not belong to this socket set
    /// or the socket has the wrong type.
    pub fn get<T: AnySocket<'a>>(&self, handle: SocketHandle) -> &T {
        match self.sockets[handle.0].inner.as_ref() {
            Some(item) => {
                T::downcast(&item.socket).expect("handle refers to a socket of a wrong type")
            }
            None => panic!("handle does not refer to a valid socket"),
        }
    }

    /// Get a mutable socket from the set by its handle, as mutable.
    ///
    /// # Panics
    /// This function may panic if the handle does not belong to this socket set
    /// or the socket has the wrong type.
    pub fn get_mut<T: AnySocket<'a>>(&mut self, handle: SocketHandle) -> &mut T {
        match self.sockets[handle.0].inner.as_mut() {
            Some(item) => T::downcast_mut(&mut item.socket)
                .expect("handle refers to a socket of a wrong type"),
            None => panic!("handle does not refer to a valid socket"),
        }
    }

    /// Remove a socket from the set, without changing its state.
    ///
    /// # Panics
    /// This function may panic if the handle does not belong to this socket set.
    pub fn remove(&mut self, handle: SocketHandle) -> Socket<'a> {
        net_trace!("[{}]: removing", handle.0);
        match self.sockets[handle.0].inner.take() {
            Some(item) => item.socket,
            None => panic!("handle does not refer to a valid socket"),
        }
    }

    /// Get an iterator to the inner sockets.
    pub fn iter(&self) -> impl Iterator<Item = (SocketHandle, &Socket<'a>)> {
        self.items().map(|i| (i.meta.handle, &i.socket))
    }

    /// Get a mutable iterator to the inner sockets.
    pub fn iter_mut(&mut self) -> impl Iterator<Item = (SocketHandle, &mut Socket<'a>)> {
        self.items_mut().map(|i| (i.meta.handle, &mut i.socket))
    }

    /// Iterate every socket in this set.
    pub fn items(&self) -> impl Iterator<Item = &Item<'a>> + '_ {
        self.sockets.iter().filter_map(|x| x.inner.as_ref())
    }

    /// Iterate every socket in this set.
    pub fn items_mut(&mut self) -> impl Iterator<Item = &mut Item<'a>> + '_ {
        self.sockets.iter_mut().filter_map(|x| x.inner.as_mut())
    }
}

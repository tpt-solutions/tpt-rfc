// SPDX-License-Identifier: MIT OR Apache-2.0
//! Transport abstraction for SIP and a dependency-free UDP
//! implementation (RFC 3261 §18). The transaction layer is completely
//! transport-agnostic; a caller wires [`TxAction::Transmit`] bytes to
//! [`Transport::send_to`] and feeds received datagrams back as
//! [`crate::transaction::TxEvent::Request`] / [`crate::transaction::TxEvent::Response`].

use std::io;
use std::net::{SocketAddr, UdpSocket};

/// A datagram-oriented SIP transport (UDP-style: messages are sent and
/// received as whole datagrams).
pub trait Transport {
    /// Send `data` to `dest`.
    fn send_to(&mut self, dest: SocketAddr, data: &[u8]) -> io::Result<usize>;
    /// Receive a single datagram, returning the source address and bytes.
    fn recv_from(&mut self) -> io::Result<(SocketAddr, Vec<u8>)>;
    /// The local address this transport is bound to.
    fn local_addr(&self) -> io::Result<SocketAddr>;
}

/// A UDP-backed SIP transport.
pub struct UdpTransport {
    socket: UdpSocket,
}

impl UdpTransport {
    /// Bind a UDP socket to `bind_addr` (e.g. `127.0.0.1:5060`).
    pub fn bind(bind_addr: &str) -> io::Result<UdpTransport> {
        let socket = UdpSocket::bind(bind_addr)?;
        socket.set_read_timeout(Some(std::time::Duration::from_millis(500)))?;
        Ok(UdpTransport { socket })
    }
}

impl Transport for UdpTransport {
    fn send_to(&mut self, dest: SocketAddr, data: &[u8]) -> io::Result<usize> {
        self.socket.send_to(data, dest)
    }

    fn recv_from(&mut self) -> io::Result<(SocketAddr, Vec<u8>)> {
        let mut buf = vec![0u8; 65535];
        let (n, addr) = self.socket.recv_from(&mut buf)?;
        buf.truncate(n);
        Ok((addr, buf))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }
}

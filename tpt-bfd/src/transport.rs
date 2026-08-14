//! UDP transport for asynchronous-mode BFD (RFC 5881 encapsulation).
//!
//! [`UdpTransport`] wraps a [`Session`] and a [`std::net::UdpSocket`],
//! driving the periodic transmission and reception of BFD control
//! packets. It is synchronous and relies only on the standard library,
//! so it works in any runtime.

use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use crate::error::BfdError;
use crate::session::Session;

/// Default socket read timeout used to interleave reception with the
/// periodic transmission timer.
const READ_TIMEOUT: Duration = Duration::from_millis(100);

/// Drives a [`Session`] over a UDP socket toward a single peer
/// (RFC 5881: BFD control packets are sent to UDP port 3784).
pub struct UdpTransport {
    session: Session,
    socket: UdpSocket,
    peer: SocketAddr,
    last_send: Instant,
}

impl UdpTransport {
    /// Bind `socket` (already created and optionally `connect`ed) to
    /// drive `session` toward `peer`.
    pub fn new(session: Session, socket: UdpSocket, peer: SocketAddr) -> Result<Self, BfdError> {
        socket.set_read_timeout(Some(READ_TIMEOUT))?;
        Ok(Self {
            session,
            socket,
            peer,
            last_send: Instant::now() - Duration::from_secs(1000),
        })
    }

    /// A shared reference to the underlying session.
    pub fn session(&self) -> &Session {
        &self.session
    }

    /// A mutable reference to the underlying session.
    pub fn session_mut(&mut self) -> &mut Session {
        &mut self.session
    }

    /// The peer address this transport exchanges packets with.
    pub fn peer(&self) -> SocketAddr {
        self.peer
    }

    /// Transmit the next periodic packet (if the session permits), and
    /// update the send timestamp.
    pub fn send_packet(&mut self) -> Result<(), BfdError> {
        if let Some(pkt) = self.session.next_periodic_packet() {
            let bytes = self.session.encode_packet(&pkt);
            self.socket.send_to(&bytes, self.peer)?;
            self.last_send = Instant::now();
        }
        Ok(())
    }

    /// Receive and process a single packet if one is available before
    /// the read timeout. Returns `Ok(Some(()))` when a packet was
    /// received and an immediate Final (F) response was produced and
    /// transmitted, `Ok(None)` when nothing was received or the packet
    /// was accepted without a response.
    pub fn recv_packet(&mut self) -> Result<Option<()>, BfdError> {
        let mut buf = [0u8; 1500];
        match self.socket.recv_from(&mut buf) {
            Ok((n, _addr)) => {
                if let Some(resp) = self.session.process_bytes(&buf[..n])? {
                    let bytes = self.session.encode_packet(&resp);
                    self.socket.send_to(&bytes, self.peer)?;
                    self.last_send = Instant::now();
                }
                Ok(Some(()))
            }
            Err(e)
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut =>
            {
                Ok(None)
            }
            Err(e) => Err(e.into()),
        }
    }

    /// Perform one iteration of the async-mode loop: receive (and reply
    /// if needed), then send periodically if the interval has elapsed,
    /// then check the detection timer.
    pub fn step(&mut self) -> Result<(), BfdError> {
        self.recv_packet()?;
        if self.session.should_send_periodic() {
            let interval = self.session.transmit_interval();
            if self.last_send.elapsed() >= interval {
                self.send_packet()?;
            }
        }
        self.session.check_timeout();
        Ok(())
    }

    /// Run the transport loop until `stop` is set. Intended to be
    /// spawned on its own thread (one per BFD session / peer).
    pub fn run(&mut self, stop: &AtomicBool) -> Result<(), BfdError> {
        while !stop.load(Ordering::Relaxed) {
            self.step()?;
            std::thread::sleep(Duration::from_millis(10));
        }
        Ok(())
    }
}

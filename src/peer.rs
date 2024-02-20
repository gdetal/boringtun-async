use std::{
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use boringtun::{
    noise::{
        self, errors::WireGuardError, handshake::parse_handshake_anon, rate_limiter::RateLimiter,
        Tunn, TunnResult,
    },
    x25519::{self, PublicKey, StaticSecret},
};
use futures::{ready, Sink, Stream};
use ip_network::IpNetwork;
use ip_network_table::IpNetworkTable;
use pin_project::pin_project;
use tokio::{io::ReadBuf, net::UdpSocket, time};
use tokio_util::bytes::BytesMut;

use crate::{packet::Packet, MAX_UDP_SIZE};

pub struct Endpoint {
    addr: SocketAddr,
    sock: Option<UdpSocket>,
    raw_sock: Arc<UdpSocket>,
}

impl Endpoint {
    fn try_send(&self, pkt: &[u8]) -> std::io::Result<()> {
        let sock = self.sock.as_ref().unwrap_or(self.raw_sock.as_ref());
        if self.sock.is_some() {
            sock.try_send(pkt)?;
        } else {
            sock.try_send_to(pkt, self.addr)?;
        }
        Ok(())
    }
}

#[pin_project]
pub struct Peer {
    tunnel: Tunn,
    endpoint: Endpoint,
    allowed_ips: IpNetworkTable<()>,
    update_interval: time::Interval,
    buffer: [u8; MAX_UDP_SIZE],
}

impl Peer {
    pub(crate) fn new(
        index: u32,
        private_key: StaticSecret,
        public_key: PublicKey,
        endpoint: SocketAddr,
        raw_sock: Arc<UdpSocket>,
        allowed_ips: &[IpNetwork],
    ) -> Self {
        let mut allowed_ips_set = IpNetworkTable::new();

        for ips in allowed_ips {
            allowed_ips_set.insert(*ips, ());
        }

        let mut update_interval = time::interval(Duration::from_millis(250));
        update_interval.set_missed_tick_behavior(time::MissedTickBehavior::Delay);

        Self {
            tunnel: Tunn::new(private_key, public_key, None, None, index, None).unwrap(),
            endpoint: Endpoint {
                addr: endpoint,
                sock: None,
                raw_sock,
            },
            allowed_ips: allowed_ips_set,
            update_interval,
            buffer: [0; MAX_UDP_SIZE],
        }
    }

    pub(crate) fn set_endpoint(&mut self, addr: SocketAddr) {
        if self.endpoint.addr != addr {
            self.shutdown_endpoint();
        }

        self.endpoint.addr = addr;
    }

    pub(crate) fn shutdown_endpoint(&mut self) {
        self.endpoint.sock.take();
    }

    pub(crate) fn connect_endpoint(&mut self, port: u16) -> std::io::Result<()> {
        if self.endpoint.sock.is_some() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "already connected",
            ));
        }

        let udp_conn = socket2::Socket::new(
            socket2::Domain::for_address(self.endpoint.addr),
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )?;
        udp_conn.set_reuse_address(true)?;

        #[cfg(not(target_os = "windows"))]
        udp_conn.set_reuse_port(true)?;
        let bind_addr = if self.endpoint.addr.is_ipv4() {
            SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port).into()
        } else {
            SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, port, 0, 0).into()
        };
        udp_conn.bind(&bind_addr)?;
        udp_conn.connect(&self.endpoint.addr.into())?;
        udp_conn.set_nonblocking(true)?;

        let udp_conn = std::net::UdpSocket::from(udp_conn);
        let conn = UdpSocket::from_std(udp_conn)?;

        self.endpoint.sock = Some(conn);

        Ok(())
    }

    pub(crate) fn encapsulate(&mut self, pkt: &[u8]) {
        match self.tunnel.encapsulate(pkt, &mut self.buffer) {
            TunnResult::Done => {}
            TunnResult::Err(e) => {
                eprintln!("encapsulate error: {e:?}")
            }
            TunnResult::WriteToNetwork(packet) => {
                self.endpoint.try_send(packet).ok();
            }
            _ => panic!("Unexpected result from encapsulate"),
        }
    }

    pub(crate) fn decapsulate<'a>(
        self: Pin<&mut Self>,
        packet: &[u8],
        dst_buf: &'a mut [u8],
    ) -> Poll<&'a mut [u8]> {
        let this = self.project();

        let mut flush = false;
        match this
            .tunnel
            .decapsulate(Some(this.endpoint.addr.ip()), packet, &mut dst_buf[..])
        {
            TunnResult::Done => {}
            TunnResult::Err(e) => eprintln!("decapsulate error {:?}", e),
            TunnResult::WriteToNetwork(packet) => {
                flush = true;
                this.endpoint.try_send(packet).ok();
            }
            TunnResult::WriteToTunnelV4(packet, addr) => {
                if this.allowed_ips.longest_match(addr).is_some() {
                    return Poll::Ready(packet);
                }
            }
            TunnResult::WriteToTunnelV6(packet, addr) => {
                if this.allowed_ips.longest_match(addr).is_some() {
                    return Poll::Ready(packet);
                }
            }
        }

        if flush {
            // Flush pending queue
            while let TunnResult::WriteToNetwork(packet) =
                this.tunnel.decapsulate(None, &[], this.buffer)
            {
                this.endpoint.try_send(packet).ok();
            }
        }
        Poll::Pending
    }

    fn update_timers(&mut self) {
        match self.tunnel.update_timers(&mut self.buffer) {
            TunnResult::Done => {}
            TunnResult::Err(WireGuardError::ConnectionExpired) => {
                self.shutdown_endpoint();
            }
            TunnResult::Err(e) => {
                eprintln!("update_timers error: {e:?}")
            }
            TunnResult::WriteToNetwork(packet) => {
                self.endpoint.try_send(packet).ok();
            }
            _ => panic!("Unexpected result from update_timers"),
        }
    }

    fn poll_recv(&mut self, cx: &mut Context<'_>, buf: &mut BytesMut) -> Poll<usize> {
        let mut read_buf = ReadBuf::new(buf);

        if let Some(ref conn) = self.endpoint.sock {
            return match conn.poll_recv(cx, &mut read_buf) {
                Poll::Ready(Ok(_)) => Poll::Ready(read_buf.filled().len()),
                Poll::Ready(Err(e)) => {
                    eprintln!("unable to receive packets: {e}");
                    self.shutdown_endpoint();
                    Poll::Pending
                }
                Poll::Pending => Poll::Pending,
            };
        }

        Poll::Pending
    }
}

use std::ops::DerefMut;

impl Stream for Peer {
    type Item = Result<Packet, std::io::Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut buf = BytesMut::zeroed(MAX_UDP_SIZE);
        let mut read_buf = BytesMut::zeroed(MAX_UDP_SIZE);

        if self.update_interval.poll_tick(cx).is_ready() {
            self.update_timers();
        }

        let len = ready!(self.deref_mut().poll_recv(cx, &mut read_buf));

        let len = ready!(self.decapsulate(read_buf.split_to(len).as_ref(), &mut buf)).len();
        match Packet::parse(buf.split_to(len)) {
            None => {
                eprintln!("unable to parse receive packet");
                Poll::Pending
            }
            Some(pkt) => {
                // eprintln!("pkt -> {}", pkt.len());
                Poll::Ready(Some(Ok(pkt)))
            }
        }
    }
}

impl Sink<Packet> for Peer {
    type Error = std::io::Error;

    fn poll_ready(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn start_send(mut self: Pin<&mut Self>, pkt: Packet) -> Result<(), Self::Error> {
        self.encapsulate(pkt.get_bytes());
        Ok(())
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }
}

#[pin_project]
struct PeerSocketInner {
    inner: Option<(StaticSecret, PublicKey, RateLimiter)>,
    reset_interval: time::Interval,
    sock: Arc<UdpSocket>,
    port: u16,
    buffer: [u8; MAX_UDP_SIZE],
}

impl PeerSocketInner {
    pub(crate) fn bind(addr: SocketAddr) -> std::io::Result<Self> {
        let sock = socket2::Socket::new(
            socket2::Domain::for_address(addr),
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )?;

        sock.set_reuse_address(true)?;
        #[cfg(not(target_os = "windows"))]
        sock.set_reuse_port(true)?;
        let bind_addr = addr.into();
        sock.bind(&bind_addr)?;
        sock.set_nonblocking(true)?;

        let sock = std::net::UdpSocket::from(sock);
        let sock = Arc::new(UdpSocket::from_std(sock)?);

        let port = sock.local_addr()?.port();

        Ok(Self {
            inner: None,
            reset_interval: time::interval(Duration::from_secs(1)),
            sock,
            port,
            buffer: [0; MAX_UDP_SIZE],
        })
    }

    pub(crate) fn set_key(&mut self, private_key: StaticSecret) {
        let public_key = PublicKey::from(&private_key);
        let rate_limiter = RateLimiter::new(&public_key, 100);

        self.inner = Some((private_key, public_key, rate_limiter));
    }

    pub(crate) fn port(&mut self) -> u16 {
        self.port
    }
}

#[derive(Debug)]
pub(crate) enum PeerId {
    PublicKey(PublicKey),
    Index(usize),
}

impl Stream for PeerSocketInner {
    type Item = std::io::Result<(PeerId, BytesMut, SocketAddr)>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut dst_buf_mut = BytesMut::zeroed(MAX_UDP_SIZE);

        let mut buf = [0; MAX_UDP_SIZE];
        let mut dst_buf = ReadBuf::new(&mut dst_buf_mut);

        let this = self.project();

        let (private_key, public_key, rate_limiter) = match this.inner {
            Some(r) => r,
            None => return Poll::Pending,
        };

        if this.reset_interval.poll_tick(cx).is_ready() {
            rate_limiter.reset_count();
        }

        let addr = ready!(this.sock.poll_recv_from(cx, &mut dst_buf))?;

        let len = dst_buf.filled().len();
        let parsed_packet =
            match rate_limiter
                .verify_packet(Some(addr.ip()), dst_buf.filled(), &mut buf)
            {
                Ok(packet) => packet,
                Err(TunnResult::WriteToNetwork(cookie)) => {
                    this.sock.try_send_to(cookie, addr).ok();
                    return Poll::Pending;
                }
                Err(_) => return Poll::Pending,
            };

        let peer = match &parsed_packet {
            noise::Packet::HandshakeInit(p) => {
                parse_handshake_anon(private_key, public_key, p)
                    .ok()
                    .map(|hh| PeerId::PublicKey(x25519::PublicKey::from(hh.peer_static_public)))
            }
            noise::Packet::HandshakeResponse(p) => {
                Some(PeerId::Index((p.receiver_idx >> 8) as usize))
            }
            noise::Packet::PacketCookieReply(p) => {
                Some(PeerId::Index((p.receiver_idx >> 8) as usize))
            }
            noise::Packet::PacketData(p) => Some(PeerId::Index((p.receiver_idx >> 8) as usize)),
        };

        let peer = match peer {
            None => return Poll::Pending,
            Some(peer) => peer,
        };

        Poll::Ready(Some(Ok((peer, dst_buf_mut.split_to(len), addr))))
    }
}

#[pin_project]
pub(crate) struct PeerSocket {
    #[pin]
    v4: PeerSocketInner,
    #[pin]
    v6: PeerSocketInner,
    pub(crate) port: u16,
    v4_first: bool,
}

impl PeerSocket {
    pub(crate) fn new(port: u16) -> std::io::Result<Self> {
        let mut v4 = PeerSocketInner::bind(
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port)),
        )?;
        let port = v4.port();

        let v6 = PeerSocketInner::bind(
            SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, port, 0, 0)),
        )?;

        Ok(Self {
            v4,
            v6,
            port,
            v4_first: true,
        })
    }

    pub(crate) fn udpsock_for(&self, addr: SocketAddr) -> Arc<UdpSocket> {
        match addr {
            SocketAddr::V4(_) => self.v4.sock.clone(),
            SocketAddr::V6(_) => self.v6.sock.clone(),
        }
    }

    pub(crate) fn set_key(&mut self, private_key: StaticSecret) {
        self.v4.set_key(private_key.clone());
        self.v6.set_key(private_key);
    }
}

impl Stream for PeerSocket {
    type Item = std::io::Result<(PeerId, BytesMut, SocketAddr)>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.project();
        let v4_first = *this.v4_first;

        *this.v4_first = !v4_first;

        let (first, second) = if v4_first {
            (this.v4, this.v6)
        } else {
            (this.v6, this.v4)
        };

        if let Poll::Ready(v) = first.poll_next(cx) {
            return Poll::Ready(v);
        }

        if let Poll::Ready(v) = second.poll_next(cx) {
            return Poll::Ready(v);
        }

        Poll::Pending
    }
}

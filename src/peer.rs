use std::{
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    pin::Pin,
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

#[pin_project]
pub struct Peer {
    tunnel: Tunn,
    endpoint: SocketAddr,
    conn: UdpSocket,
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
        port: u16,
        allowed_ips: &[IpNetwork],
    ) -> Self {
        // TODO handle error:
        let udp_conn = socket2::Socket::new(
            socket2::Domain::for_address(endpoint),
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )
        .unwrap();
        udp_conn.set_reuse_address(true).unwrap();

        #[cfg(not(target_os = "windows"))]
        udp_conn.set_reuse_port(true).unwrap();
        let bind_addr = if endpoint.is_ipv4() {
            SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port).into()
        } else {
            SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, port, 0, 0).into()
        };

        udp_conn.bind(&bind_addr).unwrap();
        udp_conn.connect(&endpoint.into()).unwrap();
        udp_conn.set_nonblocking(true).unwrap();

        let udp_conn = std::net::UdpSocket::from(udp_conn);
        let conn = UdpSocket::from_std(udp_conn).unwrap();

        let mut allowed_ips_set = IpNetworkTable::new();

        for ips in allowed_ips {
            allowed_ips_set.insert(*ips, ());
        }

        let mut update_interval = time::interval(Duration::from_millis(250));
        update_interval.set_missed_tick_behavior(time::MissedTickBehavior::Delay);

        Self {
            endpoint,
            tunnel: Tunn::new(private_key, public_key, None, None, index, None).unwrap(),
            conn,
            allowed_ips: allowed_ips_set,
            update_interval,
            buffer: [0; MAX_UDP_SIZE],
        }
    }

    pub(crate) fn encapsulate(&mut self, pkt: &[u8]) {
        match self.tunnel.encapsulate(pkt, &mut self.buffer) {
            TunnResult::Done => {
                println!("peer done")
            }
            TunnResult::Err(e) => eprintln!("encapsulate error: {e:?}"),
            TunnResult::WriteToNetwork(packet) => {
                self.conn.try_send(packet).ok();
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
            .decapsulate(Some(this.endpoint.ip()), packet, &mut dst_buf[..])
        {
            TunnResult::Done => {
                println!("peer done");
            }
            TunnResult::Err(e) => eprintln!("decapsulate error {:?}", e),
            TunnResult::WriteToNetwork(packet) => {
                flush = true;
                println!("peer write to network");

                this.conn.try_send(packet).ok();
            }
            TunnResult::WriteToTunnelV4(packet, addr) => {
                if this.allowed_ips.longest_match(addr).is_some() {
                    // println!("peer ready packet");
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
                println!("peer flush packet: {packet:?}");
                this.conn.try_send(packet).ok();
            }
        }
        Poll::Pending
    }

    fn update_timers(&mut self) {
        match self.tunnel.update_timers(&mut self.buffer) {
            TunnResult::Done => {}
            TunnResult::Err(WireGuardError::ConnectionExpired) => {
                // Should close connection:
                println!("connection expired")
            }
            TunnResult::Err(e) => {
                eprintln!("update_timers error: {e:?}")
            }
            TunnResult::WriteToNetwork(packet) => {
                self.conn.try_send(packet).ok();
            }
            _ => panic!("Unexpected result from update_timers"),
        }
    }

    fn poll_recv<'a>(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        dst_buf: &'a mut [u8],
    ) -> Poll<&'a mut [u8]> {
        let this = self.project();

        let mut buf = ReadBuf::new(this.buffer);

        let packet = match this.conn.poll_recv(cx, &mut buf) {
            Poll::Ready(Ok(_)) => buf.filled(),
            Poll::Ready(Err(e)) => {
                // TODO close conn ??
                eprintln!("unable to receive packets: {e}");
                return Poll::Pending;
            }
            Poll::Pending => {
                return Poll::Pending;
            }
        };

        // TODO avoid duplication with decapsulate().

        let mut flush = false;
        match this
            .tunnel
            .decapsulate(Some(this.endpoint.ip()), packet, &mut dst_buf[..])
        {
            TunnResult::Done => {
                println!("peer done");
            }
            TunnResult::Err(e) => eprintln!("decapsulate error {:?}", e),
            TunnResult::WriteToNetwork(packet) => {
                flush = true;
                println!("peer write to network");

                this.conn.try_send(packet).ok();
            }
            TunnResult::WriteToTunnelV4(packet, addr) => {
                if this.allowed_ips.longest_match(addr).is_some() {
                    // println!("peer ready packet");
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
                println!("peer flush packet: {packet:?}");
                this.conn.try_send(packet).ok();
            }
        }
        Poll::Pending
    }
}

impl Stream for Peer {
    type Item = Result<Packet, std::io::Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut buf = BytesMut::zeroed(MAX_UDP_SIZE);

        if self.update_interval.poll_tick(cx).is_ready() {
            self.update_timers();
        }

        let len = ready!(self.poll_recv(cx, &mut buf)).len();
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
pub(crate) struct PeerListener {
    private_key: StaticSecret,
    public_key: PublicKey,
    rate_limiter: RateLimiter,
    reset_interval: time::Interval,
    sock: Option<UdpSocket>,
    buffer: [u8; MAX_UDP_SIZE],
}

impl PeerListener {
    pub(crate) fn new(private_key: StaticSecret) -> Self {
        let public_key = PublicKey::from(&private_key);
        let rate_limiter = RateLimiter::new(&public_key, 100);

        Self {
            private_key,
            public_key,
            rate_limiter,
            reset_interval: time::interval(Duration::from_secs(1)),
            sock: None,
            buffer: [0; MAX_UDP_SIZE],
        }
    }

    pub(crate) fn listen_v4(&mut self, mut port: u16) -> std::io::Result<u16> {
        let sock = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )?;
        sock.set_reuse_address(true)?;
        sock.bind(&SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port).into())?;
        sock.set_nonblocking(true)?;

        if port == 0 {
            // Random port was assigned
            port = sock.local_addr()?.as_socket().unwrap().port();
        }

        let sock = std::net::UdpSocket::from(sock);
        let sock = UdpSocket::from_std(sock).unwrap();

        self.sock = Some(sock);
        Ok(port)
    }

    pub(crate) fn listen_v6(&mut self, mut port: u16) -> std::io::Result<u16> {
        let sock = socket2::Socket::new(
            socket2::Domain::IPV6,
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )?;
        sock.set_reuse_address(true)?;
        sock.bind(&SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, port, 0, 0).into())?;
        sock.set_nonblocking(true)?;

        if port == 0 {
            // Random port was assigned
            port = sock.local_addr()?.as_socket().unwrap().port();
        }

        let sock = std::net::UdpSocket::from(sock);
        let sock = UdpSocket::from_std(sock).unwrap();

        self.sock = Some(sock);
        Ok(port)
    }
}

pub(crate) enum PeerId {
    PublicKey(PublicKey),
    Index(usize),
}

impl Stream for PeerListener {
    type Item = std::io::Result<(PeerId, Packet)>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut dst_buf_mut = BytesMut::zeroed(MAX_UDP_SIZE);

        let mut buf = [0; MAX_UDP_SIZE];
        let mut dst_buf = ReadBuf::new(&mut dst_buf_mut);

        let this = self.project();

        if this.reset_interval.poll_tick(cx).is_ready() {
            this.rate_limiter.reset_count();
        }

        let sock = match this.sock {
            None => return Poll::Pending,
            Some(sock) => sock,
        };

        let addr = ready!(sock.poll_recv_from(cx, &mut dst_buf))?;

        let parsed_packet =
            match this
                .rate_limiter
                .verify_packet(Some(addr.ip()), dst_buf.filled(), &mut buf)
            {
                Ok(packet) => packet,
                Err(TunnResult::WriteToNetwork(cookie)) => {
                    sock.try_send_to(cookie, addr).ok();
                    return Poll::Pending;
                }
                Err(_) => return Poll::Pending,
            };

        let peer = match &parsed_packet {
            noise::Packet::HandshakeInit(p) => {
                parse_handshake_anon(this.private_key, this.public_key, p)
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

        let packet = match Packet::parse(dst_buf_mut) {
            Some(packet) => packet,
            None => return Poll::Pending,
        };

        Poll::Ready(Some(Ok((peer, packet))))
    }
}

#[pin_project]
pub(crate) struct PeerListeners {
    #[pin]
    v4: PeerListener,
    #[pin]
    v6: PeerListener,
    pub(crate) port: u16,
    v4_first: bool,
}

impl PeerListeners {
    pub(crate) fn new(private_key: StaticSecret, port: u16) -> std::io::Result<Self> {
        let mut v4: PeerListener = PeerListener::new(private_key.clone());
        let port = v4.listen_v4(port)?;

        let mut v6 = PeerListener::new(private_key);
        v6.listen_v6(port)?;

        Ok(Self {
            v4,
            v6,
            port,
            v4_first: true,
        })
    }
}

impl Stream for PeerListeners {
    type Item = std::io::Result<(PeerId, Packet)>;

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

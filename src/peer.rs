use std::{
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    task::{Context, Poll},
};

use boringtun::{
    noise::{errors::WireGuardError, Tunn, TunnResult},
    x25519::{PublicKey, StaticSecret},
};
use ip_network::IpNetwork;
use ip_network_table::IpNetworkTable;
use tokio::{io::ReadBuf, net::UdpSocket};

const MAX_UDP_SIZE: usize = (1 << 16) - 1;

#[derive(Debug)]
pub(crate) enum PeerError {
    WireguardError(WireGuardError),
    IO(std::io::Error),
}

pub struct Peer {
    pub(crate) tunnel: Tunn,
    endpoint: SocketAddr,
    conn: UdpSocket,
    allowed_ips: IpNetworkTable<()>,
}

impl Peer {
    pub(crate) fn new(
        index: u32,
        private_key: StaticSecret,
        public_key: PublicKey,
        endpoint: SocketAddr,
        allowed_ips: &[IpNetwork]
    ) -> Self {
        // TODO handle error:
        let udp_conn = socket2::Socket::new(
            socket2::Domain::for_address(endpoint),
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )
        .unwrap();
        udp_conn.set_reuse_address(true).unwrap();
        let bind_addr = if endpoint.is_ipv4() {
            SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0).into()
        } else {
            SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0).into()
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

        Self {
            endpoint,
            tunnel: Tunn::new(private_key, public_key, None, None, index, None).unwrap(),
            conn,
            allowed_ips: allowed_ips_set,
        }
    }

    pub(crate) fn encapsulate(&mut self, pkt: &[u8]) {
        // TODO improve:
        let mut buf = [0; MAX_UDP_SIZE];

        match self.tunnel.encapsulate(pkt, &mut buf) {
            TunnResult::Done => {},
            TunnResult::Err(e) => eprintln!("encapsulate error: {e:?}"),
            TunnResult::WriteToNetwork(packet) => {
                self.conn.try_send(packet).ok();
            },
            _ => panic!("Unexpected result from encapsulate"),
        }
    }

    pub(crate) fn update_timers(&mut self) {
        // TODO improve:
        let mut buf = [0; MAX_UDP_SIZE];

        match self.tunnel.update_timers(&mut buf) {
            TunnResult::Done => {},
            TunnResult::Err(WireGuardError::ConnectionExpired) => {
                // Should close connection:
                println!("connection expired")
            }
            TunnResult::Err(e) => {
                eprintln!("update_timers error: {e:?}")
            },
            TunnResult::WriteToNetwork(packet) => {
                self.conn.try_send(packet).ok();
            },
            _ => panic!("Unexpected result from update_timers"),
        }
    }

    pub(crate) fn poll_recv<'a>(
        &mut self,
        cx: &mut Context<'_>,
        dst_buf: &'a mut [u8],
    ) -> Poll<&'a mut [u8]> {
        // TODO improve:
        let mut buf = [0; MAX_UDP_SIZE];
        let mut buf = ReadBuf::new(&mut buf);

        let packet = match self.conn.poll_recv(cx, &mut buf) {
            Poll::Ready(Ok(_)) => buf.filled(),
            Poll::Ready(Err(e)) => {
                // TODO close conn ??
                eprintln!("unable to receive packets: {e}");
                return Poll::Pending;
            }
            Poll::Pending => {
                println!("not ready to receive packets");
                return Poll::Pending;
            }
        };

        println!("peer received packet: {packet:?}");

        let mut flush = false;
        match self
            .tunnel
            .decapsulate(Some(self.endpoint.ip()), packet, &mut dst_buf[..])
        {
            TunnResult::Done => {
                println!("peer done");
            },
            TunnResult::Err(e) => eprintln!("decapsulate error {:?}", e),
            TunnResult::WriteToNetwork(packet) => {
                flush = true;
                println!("peer write to network");

                self.conn.try_send(packet).ok();
            }
            TunnResult::WriteToTunnelV4(packet, addr) => {
                println!("peer ready {addr}");
                if self.allowed_ips.longest_match(addr).is_some() {
                    return Poll::Ready(packet)
                }
            }
            TunnResult::WriteToTunnelV6(packet, addr) => {
                println!("peer ready");
                if self.allowed_ips.longest_match(addr).is_some() {
                    return Poll::Ready(packet)
                }
            }
        }

        if flush {
            // TODO improve:
            let mut buf = [0; MAX_UDP_SIZE];
            // Flush pending queue
            while let TunnResult::WriteToNetwork(packet) =
                self.tunnel.decapsulate(None, &[], &mut buf)
            {
                println!("peer flush packet: {packet:?}");
                self.conn.try_send(packet).ok();
            }
        }
        Poll::Pending
    }
}

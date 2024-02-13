use std::{net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6}, task::{Context, Poll}};

use boringtun::{
    noise::{errors::WireGuardError, Tunn, TunnResult},
    x25519::{PublicKey, StaticSecret},
};
use tokio::{io::ReadBuf, net::UdpSocket};

const MAX_UDP_SIZE: usize = (1 << 16) - 1;

pub struct Peer {
    index: u32,
    pub(crate) tunnel: Tunn,
    endpoint: SocketAddr,
    conn: UdpSocket,

    src_buf: [u8; MAX_UDP_SIZE],
    dst_buf: [u8; MAX_UDP_SIZE],
}

impl Peer {
    pub(crate) fn new(
        index: u32,
        private_key: StaticSecret,
        public_key: PublicKey,
        endpoint: SocketAddr,
    ) -> Self {
        // TODO handle error:
        let udp_conn = socket2::Socket::new(
            socket2::Domain::for_address(endpoint),
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        ).unwrap();
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

        Self {
            index,
            endpoint,
            tunnel: Tunn::new(private_key, public_key, None, None, index, None).unwrap(),
            conn,
            src_buf: [0u8; MAX_UDP_SIZE],
            dst_buf: [0u8; MAX_UDP_SIZE],
        }
    }

    pub(crate) fn encapsulate(&mut self, pkt: &[u8]) {
        match self.tunnel.encapsulate(pkt, &mut self.dst_buf[..]) {
            TunnResult::Done => {
                println!("done?");
            }
            TunnResult::Err(e) => {
                println!("Encapsulate error {e:?}")
            }
            TunnResult::WriteToNetwork(packet) => {
                match self.conn.try_send(packet) {
                    Ok(_) => println!("send packet {packet:?}"),
                    Err(_) => println!("unable to send {packet:?}"),
                }
            }
            _ => panic!("Unexpected result from encapsulate"),
        };
    }

    pub(crate) fn tick(&mut self) {
        match self.tunnel.update_timers(&mut self.src_buf[..]) {
            TunnResult::Done => {}
            TunnResult::Err(WireGuardError::ConnectionExpired) => {
                // TODO
                //self.shutdown_endpoint(); // close open udp socket
            }
            TunnResult::Err(e) => println!("Timer error: {e:?}"),
            TunnResult::WriteToNetwork(packet) => {
                match self.conn.try_send(packet) {
                    Ok(_) => println!("send packet {packet:?}"),
                    Err(_) => println!("unable to send {packet:?}"),
                }
            }
            _ => panic!("Unexpected result from update_timers"),
        };
    }

    pub(crate) fn poll_recv<'a>(&mut self, cx: &mut Context<'_>, dst_buf: &'a mut [u8]) -> Poll<&'a mut [u8]> {
        let mut buf = ReadBuf::new(&mut self.src_buf);

        let packet = match self.conn.poll_recv(cx, &mut buf) {
            Poll::Ready(Ok(_)) => buf.filled(),
            Poll::Ready(Err(_)) => {
                println!("unable to receive packets");
                return Poll::Pending
            },
            Poll::Pending => {
                println!("not ready to receive packets");
                return Poll::Pending
            }
        };

        println!("peer received packet: {packet:?}");

        match self.tunnel.decapsulate(
            Some(self.endpoint.ip()),
            packet,
            &mut dst_buf[..],
        ) {
            TunnResult::Done => {}
            TunnResult::Err(e) => eprintln!("Decapsulate error {:?}", e),
            TunnResult::WriteToNetwork(packet) => {
                println!("peer write to network");

                match self.conn.try_send(packet) {
                    Ok(_) => println!("send packet {packet:?}"),
                    Err(_) => println!("unable to send {packet:?}"),
                }
            }
            TunnResult::WriteToTunnelV4(packet, _) => {
                // if p.is_allowed_ip(addr) {
                //     iface.write4(packet);
                // }
                
                return Poll::Ready(packet)
            }
            TunnResult::WriteToTunnelV6(packet, _) => {
                // if p.is_allowed_ip(addr) {
                //     iface.write4(packet);
                // }
                return Poll::Ready(packet)
            }
        };

        Poll::Pending
    }
}

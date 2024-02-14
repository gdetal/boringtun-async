extern crate tun;

use std::{net::Ipv4Addr, time::Duration};

use boringtun::x25519::{PublicKey, StaticSecret};
use boringtun_async::Tunnel;
use futures::{AsyncRead, AsyncWrite};
use ip_network::IpNetwork;

struct KeyBytes(pub [u8; 32]);

impl std::str::FromStr for KeyBytes {
    type Err = &'static str;

    /// Can parse a secret key from a hex or base64 encoded string.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut internal = [0u8; 32];

        match s.len() {
            64 => {
                // Try to parse as hex
                for i in 0..32 {
                    internal[i] = u8::from_str_radix(&s[i * 2..=i * 2 + 1], 16)
                        .map_err(|_| "Illegal character in key")?;
                }
            }
            43 | 44 => {
                // Try to parse as base64
                if let Ok(decoded_key) = base64::decode(s) {
                    if decoded_key.len() == internal.len() {
                        internal[..].copy_from_slice(&decoded_key);
                    } else {
                        return Err("Illegal character in key");
                    }
                }
            }
            _ => return Err("Illegal key size"),
        }

        Ok(KeyBytes(internal))
    }
}

struct Pinger {
    src: Ipv4Addr,
    dst: Ipv4Addr,
    timer: tokio::time::Interval,
}

impl AsyncRead for Pinger {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        mut buf: &mut [u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        if self.timer.poll_tick(cx).is_ready() {
            let payload = [0x42,0x42,0x42,0x42,0x42,0x42,0x42];

            let builder = etherparse::PacketBuilder::ipv4(self.src.octets(), self.dst.octets(), 255).icmpv4_echo_request(1, 1);
            let len = builder.size(payload.len());

            builder.write(&mut buf, &payload).unwrap();

            let parsed_pkt = etherparse::SlicedPacket::from_ip(buf).unwrap();
            println!("send: {:#?}", parsed_pkt);

            std::task::Poll::Ready(Ok(len))
        } else {
            std::task::Poll::Pending
        }
    }
}

impl AsyncWrite for Pinger {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {

        let parsed_pkt = etherparse::SlicedPacket::from_ip(buf).unwrap();
        println!("response: {:#?}", parsed_pkt);

        std::task::Poll::Ready(Ok(0))
    }

    fn poll_flush(self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_close(self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
}

#[tokio::main]
async fn main() {

    let ping = Pinger {
        src: "10.2.0.2".parse().unwrap(),
        dst: "8.8.8.8".parse().unwrap(),
        timer: tokio::time::interval(Duration::from_secs(3))
    };

    let private_key = "aCyyrK5JeEPNkCs4fm92YcYnefQSvekUeJUGl1Kh5UE="
        .parse::<KeyBytes>()
        .unwrap();
    let mut tunnel = Tunnel::new(StaticSecret::from(private_key.0), ping);

    let peer_public_key = "MK3425tJbRhEz+1xQLxlL+l6GNl52zKNwo5V0fHEwj4="
        .parse::<KeyBytes>()
        .unwrap();
    let peer_endpoint = "195.181.167.193:51820".parse().unwrap();
    let allowed_ips = vec![IpNetwork::from_str_truncate("0.0.0.0/0").unwrap()];

    tunnel.add_peer(
        PublicKey::from(peer_public_key.0),
        peer_endpoint,
        &allowed_ips,
    );

    tokio::select! {
        _ = tokio::signal::ctrl_c() => {},
        _ = tunnel => {},
    };
}

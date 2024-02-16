use std::{net::SocketAddr, pin::Pin};

use boringtun::x25519::{PublicKey, StaticSecret};
use futures::{Sink, Stream, StreamExt};

use crate::{packet::Packet, peers::Peers};

pub struct Tunnel<D> {
    device: D,
    peers: Peers,
}

impl<D> Tunnel<D>
where
    D: Stream + Sink<Packet>,
{
    pub fn new(private_key: StaticSecret, device: D) -> std::io::Result<Self> {
        Ok(Self {
            device,
            peers: Peers::new(private_key, 0)?,
        })
    }

    pub fn add_peer(
        &mut self,
        public_key: PublicKey,
        endpoint: SocketAddr,
        allowed_ips: &[ip_network::IpNetwork],
    ) {
        Pin::new(&mut self.peers)
            .get_mut()
            .add_peer(public_key, endpoint, allowed_ips)
    }
}

impl<D> Tunnel<D>
where
    D: Stream<Item = Result<Packet, std::io::Error>> + Sink<Packet, Error = std::io::Error> + Unpin,
{
    pub async fn run(self) -> Result<(), std::io::Error> {
        let (dev_sink, dev_stream) = self.device.split();
        let (peers_sink, peers_stream) = self.peers.split();

        futures::select! {
            r  = dev_stream.forward(peers_sink) => {
                println!("done dev -> peers: {r:?}");
            },
            r  = peers_stream.forward(dev_sink) => {
                println!("done peers -> dev: {r:?}");
            }
        }

        Ok(())
    }
}

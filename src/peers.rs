use std::{
    collections::HashMap,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use boringtun::x25519::{PublicKey, StaticSecret};
use futures::{Sink, Stream};
use ip_network_table::IpNetworkTable;
use parking_lot::Mutex;
use tokio::time;
use tokio_util::bytes::BytesMut;

use crate::{packet::Packet, peer::Peer};

const MAX_UDP_SIZE: usize = (1 << 16) - 1;

pub struct Peers {
    private_key: StaticSecret,

    peers: HashMap<PublicKey, Arc<Mutex<Peer>>>,
    peers_by_ip: IpNetworkTable<Arc<Mutex<Peer>>>,
    peers_by_idx: HashMap<u32, Arc<Mutex<Peer>>>,

    refresh_interval: time::Interval,
}

impl Peers {
    pub fn new(private_key: StaticSecret) -> Self {
        let mut refresh_interval = time::interval(Duration::from_millis(250));
        refresh_interval.set_missed_tick_behavior(time::MissedTickBehavior::Delay);

        Self {
            private_key,
            peers: Default::default(),
            peers_by_ip: IpNetworkTable::new(),
            peers_by_idx: Default::default(),
            refresh_interval,
        }
    }

    pub fn add_peer(
        &mut self,
        public_key: PublicKey,
        endpoint: SocketAddr,
        allowed_ips: &[ip_network::IpNetwork],
    ) {
        // TODO fix index:
        let index = 0;

        let peer = Peer::new(
            index,
            self.private_key.clone(),
            public_key,
            endpoint,
            allowed_ips,
        );
        let peer = Arc::new(Mutex::new(peer));

        self.peers.insert(public_key, Arc::clone(&peer));
        self.peers_by_idx.insert(index, Arc::clone(&peer));

        for ips in allowed_ips {
            self.peers_by_ip.insert(*ips, Arc::clone(&peer));
        }
    }
}

impl Unpin for Peers {}

impl Stream for Peers {
    type Item = Result<Packet, std::io::Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut buf = BytesMut::zeroed(MAX_UDP_SIZE);

        if self.refresh_interval.poll_tick(cx).is_ready() {
            for peer in self.peers.values() {
                let mut p = peer.lock();
                p.update_timers();
            }
        }

        for peer in self.peers.values() {
            let mut peer = peer.lock();

            let len = match peer.poll_recv(cx, &mut buf) {
                Poll::Ready(pkt) => pkt.len(),
                Poll::Pending => continue,
            };

            match Packet::parse(buf.split_to(len)) {
                None => {
                    eprintln!("unable to parse receive packet ");
                    return Poll::Ready(None);
                }
                Some(pkt) => {
                    eprintln!("pkt -> {}", pkt.len());

                    return Poll::Ready(Some(Ok(pkt)));
                }
            }
        }

        Poll::Pending
    }
}

impl Sink<Packet> for Peers {
    type Error = std::io::Error;

    fn poll_ready(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn start_send(self: Pin<&mut Self>, pkt: Packet) -> Result<(), Self::Error> {
        let mut peer = match self
            .peers_by_ip
            .longest_match(pkt.get_dst_address())
            .map(|(_, d)| d)
        {
            Some(peer) => peer.lock(),
            None => {
                eprintln!("peers: received a packet for an unknown peer");
                return Ok(());
            }
        };

        println!("send to {}", pkt.get_dst_address());

        peer.encapsulate(pkt.get_bytes());

        Ok(())
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }
}

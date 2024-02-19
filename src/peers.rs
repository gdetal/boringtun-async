use std::{
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
};

use boringtun::x25519::{PublicKey, StaticSecret};
use futures::{ready, Sink, Stream};
use indexmap::IndexMap;
use ip_network_table::IpNetworkTable;
use pin_project::pin_project;
use tokio_util::bytes::BytesMut;

use crate::{
    packet::Packet,
    peer::{Peer, PeerId, PeerSocket},
    MAX_UDP_SIZE,
};

#[pin_project]
pub struct Peers {
    private_key: StaticSecret,
    peers: IndexMap<PublicKey, Peer>,
    peers_by_ip: IpNetworkTable<usize>,
    listen_port: u16,
    peers_socket: PeerSocket,
}

impl Peers {
    pub fn new(private_key: StaticSecret, port: u16) -> std::io::Result<Self> {
        let peers_socket = PeerSocket::new(private_key.clone(), port)?;

        Ok(Self {
            private_key,
            peers: Default::default(),
            peers_by_ip: IpNetworkTable::new(),
            listen_port: port,
            peers_socket,
        })
    }

    pub fn add_peer(
        &mut self,
        public_key: PublicKey,
        endpoint: SocketAddr,
        allowed_ips: &[ip_network::IpNetwork],
    ) -> std::io::Result<()> {
        // TODO fix index:
        let index = 0;

        let peer = Peer::new(
            index,
            self.private_key.clone(),
            public_key,
            endpoint,
            self.peers_socket.udpsock_for(endpoint),
            allowed_ips,
        );

        let (idx, _) = self.peers.insert_full(public_key, peer);

        for ips in allowed_ips {
            self.peers_by_ip.insert(*ips, idx);
        }

        Ok(())
    }

    pub(crate) fn poll_peers_next(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<std::io::Result<Packet>>> {
        let start = fastrand::usize(0..self.peers.len());
        let mut index = start;

        for _ in 0..self.peers.len() {
            let (_, mut peer) = self.peers.get_index_mut(index).unwrap();

            if let Poll::Ready(Some(pkt)) = Pin::new(&mut peer).poll_next(cx) {
                return Poll::Ready(Some(pkt));
            }

            index = index.wrapping_add(1) % self.peers.len();
        }

        Poll::Pending
    }

    pub(crate) fn poll_listener_next(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<std::io::Result<Packet>>> {
        let this = self.project();

        let peer_packet = ready!(Pin::new(this.peers_socket).poll_next(cx));
        let (peer, packet, addr) = match peer_packet {
            Some(Err(e)) => return Poll::Ready(Some(Err(e))),
            None => return Poll::Ready(None),
            Some(Ok(p)) => p,
        };

        let peer = match peer {
            PeerId::Index(index) => this.peers.get_index_mut(index).map(|(_, p)| p),
            PeerId::PublicKey(key) => this.peers.get_mut(&key),
        };

        let mut peer = match peer {
            None => return Poll::Pending,
            Some(peer) => Pin::new(peer),
        };

        let mut buf = BytesMut::zeroed(MAX_UDP_SIZE);

        let len = ready!(peer.as_mut().decapsulate(packet.as_ref(), &mut buf)).len();
        let buf = buf.split_to(len);

        match Packet::parse(buf) {
            None => {
                eprintln!("unable to parse receive packet");
                Poll::Pending
            }
            Some(pkt) => {
                peer.set_endpoint(addr);
                if let Err(e) = peer.connect_endpoint(*this.listen_port) {
                    eprintln!("unable to connect peer endpoint: {e}");
                }

                Poll::Ready(Some(Ok(pkt)))
            }
        }
    }
}

impl Stream for Peers {
    type Item = Result<Packet, std::io::Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if let Poll::Ready(r) = self.as_mut().poll_peers_next(cx) {
            return Poll::Ready(r);
        }

        self.poll_listener_next(cx)
    }
}

impl Sink<Packet> for Peers {
    type Error = std::io::Error;

    fn poll_ready(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn start_send(self: Pin<&mut Self>, pkt: Packet) -> Result<(), Self::Error> {
        let this = self.project();

        let index = match this
            .peers_by_ip
            .longest_match(pkt.get_dst_address())
            .map(|(_, d)| *d)
        {
            Some(index) => index,
            None => {
                eprintln!("peers: received a packet for an unknown peer");
                return Ok(());
            }
        };

        let (_, peer) = this.peers.get_index_mut(index).unwrap();
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

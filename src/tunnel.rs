use std::{collections::HashMap, net::SocketAddr, pin::{pin, Pin}, sync::Arc, task::{Context, Poll}, time::Duration};

use futures::{Future, SinkExt, StreamExt};
use boringtun::{device::{allowed_ips::AllowedIps, peer::{self, AllowedIP}}, noise::{Tunn, TunnResult}, x25519::{PublicKey, StaticSecret}};
use tokio::{io::{AsyncRead, AsyncWrite, ReadBuf}, time};
use parking_lot::Mutex;


use crate::{device::Device, peer::Peer};

// The number of handshakes per second we can tolerate before using cookies
// const HANDSHAKE_RATE_LIMIT: u64 = 100;
const MAX_UDP_SIZE: usize = (1 << 16) - 1;

// look here for inspiration: https://github.com/firezone/firezone/blob/main/rust/connlib/tunnel/src/lib.rs


pub struct Tunnel<D> {
    device: Device<D>,
    public_key: PublicKey,
    private_key: StaticSecret,
    peers: HashMap<PublicKey, Arc<Mutex<Peer>>>,
    peers_by_ip: AllowedIps<Arc<Mutex<Peer>>>,
    peers_by_idx: HashMap<u32, Arc<Mutex<Peer>>>,
    
    refresh_interval: time::Interval,


    src_buf: [u8; MAX_UDP_SIZE],
    dst_buf: [u8; MAX_UDP_SIZE]
}

impl<D> Tunnel<D>
where D: AsyncRead + AsyncWrite
{
    pub fn new(private_key: StaticSecret, device: D) -> Self {
        let public_key = (&private_key).into();

        // let mut refresh_interval = time::interval(Duration::from_millis(250));
        let mut refresh_interval = time::interval(Duration::from_secs(1));
        refresh_interval.set_missed_tick_behavior(time::MissedTickBehavior::Delay);

        Self {
            device: Device::new(device, true, 1504),
            public_key,
            private_key,
            peers: Default::default(),
            peers_by_ip: AllowedIps::new(),
            peers_by_idx: Default::default(),
            refresh_interval,
            src_buf: [0u8; MAX_UDP_SIZE],
            dst_buf: [0u8; MAX_UDP_SIZE],
        }
    }

    pub fn add_peer(&mut self, public_key: PublicKey, endpoint: SocketAddr, allowed_ips: &[AllowedIP]) {
        // TODO fix index:
        let index = 0;

        let peer = Peer::new(index, self.private_key.clone(), public_key, endpoint);
        let peer = Arc::new(Mutex::new(peer));

        self.peers.insert(public_key, Arc::clone(&peer));
        self.peers_by_idx.insert(index, Arc::clone(&peer));

        for AllowedIP { addr, cidr } in allowed_ips {
            self.peers_by_ip.insert(*addr, *cidr as _, Arc::clone(&peer));
        }
    }
}

impl<D> Tunnel<D>
where D: AsyncRead + AsyncWrite + Unpin
{
    fn poll_device(&mut self, cx: &mut Context<'_>) -> Poll<()> {

        let peers = &self.peers_by_ip;

        for _ in 0..100 {
            let pkt = match self.device.poll_next_unpin(cx) {
                Poll::Ready(Some(Ok(pkt))) => {
                    pkt
                },
                Poll::Ready(Some(Err(e))) => {
                    eprintln!("error device {e}");
                    return Poll::Pending
                },
                Poll::Ready(None) => {
                    eprintln!("device done");
                    return Poll::Pending
                },
                Poll::Pending => {
                    println!("data -> pending");
                    return Poll::Pending
                },
            };


            println!("pkt {pkt:?}");
            println!("dst_addr {}", pkt.address());

            let mut peer = match peers.find(pkt.address()) {
                Some(peer) => peer.lock(),
                None => continue,
            };
            peer.encapsulate(pkt.bytes());
        }

        Poll::Pending
    }

    fn poll_next_event(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        loop {
            if self.poll_device(cx).is_ready() {
                continue
            }

            if self.refresh_interval.poll_tick(cx).is_ready() {
                for peer in self.peers.values() {
                    let mut p = peer.lock();
                    p.tick();
                }
                continue
            }

            for peer in self.peers.values() {
                let mut peer = peer.lock();
                match peer.poll_recv(cx, &mut self.dst_buf) {
                    Poll::Ready(pkt) => {
                        println!("write data to device");
                        match self.device.start_send_unpin(pkt) {
                            Ok(_) => println!("data writen!"),
                            Err(e) => println!("unable to write data: {e}"),
                        }

                        self.device.poll_flush_unpin(cx);
                    },
                    Poll::Pending => println!("data pending from peer"),
                }
            }

            return Poll::Pending
        }
    }
}

impl<D> Unpin for Tunnel<D> {}

impl<D> Future for Tunnel<D> 
where D: AsyncRead + AsyncWrite + Unpin
{
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.poll_next_event(cx)
    }
}

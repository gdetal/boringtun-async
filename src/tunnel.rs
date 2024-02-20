use std::{
    pin::Pin,
    task::{Context, Poll},
};

use boringtun::x25519::StaticSecret;
use futures::{Future, FutureExt, Sink, Stream, StreamExt};
use tokio::task::{JoinError, JoinHandle};
use tokio_util::sync::CancellationToken;

use crate::{api, packet::Packet, peers::Peers};

pub struct Tunnel<D> {
    device: D,
    peers: Peers,
}

impl<D> Tunnel<D>
where
    D: Stream + Sink<Packet>,
{
    pub fn new(private_key: StaticSecret, device: D) -> std::io::Result<Self> {
        let peers = Peers::new(private_key, 0)?;

        Ok(Self { device, peers })
    }
}

impl<D> Tunnel<D>
where
    D: Stream<Item = Result<Packet, std::io::Error>>
        + Sink<Packet, Error = std::io::Error>
        + Unpin
        + Send
        + 'static,
{
    async fn run(self, token: CancellationToken) {
        let (dev_sink, dev_stream) = self.device.split();
        let (peers_sink, peers_stream) = self.peers.split();

        futures::select! {
            _ = token.cancelled().fuse() => {
            },
            r  = dev_stream.forward(peers_sink).fuse() => {
                println!("done dev -> peers: {r:?}");
            },
            r  = peers_stream.forward(dev_sink).fuse() => {
                println!("done peers -> dev: {r:?}");
            }
        }
    }

    pub fn spawn(self) -> TunnelHandle {
        let token: CancellationToken = CancellationToken::new();
        let thread_token = token.child_token();
        let api_channel = self.peers.open_api();

        let handle = tokio::spawn(async move {
            self.run(thread_token).await;
        });

        TunnelHandle {
            token,
            handle,
            api_channel,
        }
    }
}

pub struct TunnelHandle {
    token: CancellationToken,
    handle: JoinHandle<()>,
    api_channel: api::ApiChannel,
}

impl TunnelHandle {
    pub fn api(&self) -> api::ApiChannel {
        self.api_channel.clone()
    }

    pub fn cancel(&self) {
        self.token.cancel()
    }
}

impl Future for TunnelHandle {
    type Output = Result<(), JoinError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.handle.poll_unpin(cx)
    }
}

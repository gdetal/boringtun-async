use std::{
    pin::Pin,
    task::{Context, Poll},
};

use async_compat::Compat;
use futures::{AsyncRead, AsyncWrite, Future, FutureExt, Sink, Stream, StreamExt};
use pin_project::pin_project;
use tokio::task::{JoinError, JoinHandle};
use tokio_util::{codec::Framed, sync::CancellationToken};

use crate::{api, codec::TunPacketCodec, packet::Packet, tunnel::Tunnel};

#[pin_project]
pub struct Device<D> {
    #[pin]
    inner: Framed<Compat<D>, TunPacketCodec>,
}

impl<D> Device<D>
where
    D: AsyncRead + AsyncWrite,
{
    pub fn new(device: D, has_packet_info: bool) -> Self {
        let mut inner = Framed::new(
            Compat::new(device),
            TunPacketCodec::new(has_packet_info, crate::MAX_UDP_SIZE),
        );
        // Make sure to flush as soon as one packet is in the buffer:
        inner.set_backpressure_boundary(0);

        Self { inner }
    }
}

impl<D> Stream for Device<D>
where
    D: AsyncRead,
{
    type Item = Result<Packet, std::io::Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.project().inner.poll_next(cx)
    }
}

impl<D> Sink<Packet> for Device<D>
where
    D: AsyncWrite,
{
    type Error = std::io::Error;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.project().inner.poll_ready(cx)
    }

    fn start_send(self: Pin<&mut Self>, pkt: Packet) -> Result<(), Self::Error> {
        self.project().inner.start_send(pkt)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.project().inner.poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.project().inner.poll_close(cx)
    }
}


pub struct TunnelDevice<D> {
    device: D,
    peers: Tunnel,
}

impl<D> TunnelDevice<D>
where
    D: Stream + Sink<Packet>,
{
    pub fn new(device: D) -> std::io::Result<Self> {
        let peers = Tunnel::new()?;

        Ok(Self { device, peers })
    }
}

impl<D> TunnelDevice<D>
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

    pub fn spawn(self) -> TunnelDeviceHandle {
        let token: CancellationToken = CancellationToken::new();
        let thread_token = token.child_token();
        let api_channel = self.peers.open_api();

        let handle = tokio::spawn(async move {
            self.run(thread_token).await;
        });

        TunnelDeviceHandle {
            token,
            handle,
            api_channel,
        }
    }
}

pub struct TunnelDeviceHandle {
    token: CancellationToken,
    handle: JoinHandle<()>,
    api_channel: api::ApiChannel,
}

impl TunnelDeviceHandle {
    pub fn api(&self) -> api::ApiChannel {
        self.api_channel.clone()
    }

    pub fn cancel(&self) {
        self.token.cancel()
    }
}

impl Future for TunnelDeviceHandle {
    type Output = Result<(), JoinError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.handle.poll_unpin(cx)
    }
}

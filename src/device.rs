use std::{
    pin::Pin,
    task::{Context, Poll},
};

use async_compat::Compat;
use futures::{AsyncRead, AsyncWrite, Sink, Stream};
use pin_project::pin_project;
use tokio_util::codec::Framed;

use crate::{codec::TunPacketCodec, packet::Packet};

#[pin_project]
pub struct Device<D> {
    #[pin]
    inner: Framed<Compat<D>, TunPacketCodec>,
}

impl<D> Device<D>
where
    D: AsyncRead + AsyncWrite,
{
    pub fn new(device: D, has_packet_info: bool, pkt_size: usize) -> Self {
        let mut inner = Framed::new(
            Compat::new(device),
            TunPacketCodec::new(has_packet_info, pkt_size),
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

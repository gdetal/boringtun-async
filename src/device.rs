use std::{
    pin::Pin,
    task::{Context, Poll},
};

use byteorder::{NativeEndian, NetworkEndian, WriteBytesExt};
use futures::{ready, AsyncRead, AsyncWrite, Sink, Stream};
use pin_project::pin_project;
use tokio_util::bytes::{BufMut, BytesMut};

use crate::packet::Packet;

#[pin_project]
pub struct Device<D> {
    #[pin]
    inner: D,

    outstanding: Option<Packet>,
    has_packet_info: bool,
    pkt_size: usize,
}

impl<D> Device<D>
where
    D: AsyncRead + AsyncWrite,
{
    pub fn new(device: D, has_packet_info: bool, pkt_size: usize) -> Self {
        Self {
            inner: device,
            outstanding: None,
            has_packet_info,
            pkt_size,
        }
    }
}
impl<D> Device<D>
where
    D: AsyncWrite,
{
    fn poll_flush_buffer(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let mut this = self.project();

        if let Some(pkt) = this.outstanding {
            // TODO minimize copy if possible:
            let mut bytes = BytesMut::with_capacity(pkt.len() + 4);
            if *this.has_packet_info {
                let mut buf = Vec::<u8>::with_capacity(4);

                // flags is always 0
                buf.write_u16::<NativeEndian>(0)?;
                // write the protocol as network byte order

                #[cfg(target_os = "linux")]
                buf.write_u16::<NetworkEndian>(libc::ETH_P_IP as u16)?;

                #[cfg(target_os = "macos")]
                buf.write_u16::<NetworkEndian>(libc::PF_INET as u16)?;

                #[cfg(not(any(target_os = "macos", target_os = "linux")))]
                unimplemented!();
                bytes.put_slice(&buf);
            }

            bytes.put(pkt.get_bytes());

            ready!(this.inner.as_mut().poll_write(cx, &bytes[..]))?;
        }
        *this.outstanding = None;
        Poll::Ready(Ok(()))
    }
}

impl<D> Stream for Device<D>
where
    D: AsyncRead,
{
    type Item = Result<Packet, std::io::Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.project();

        // Improve:
        let mut buf = BytesMut::zeroed(*this.pkt_size);

        let len = ready!(this.inner.poll_read(cx, &mut buf))?;

        let mut buf = buf.split_to(len);

        // if the packet information is enabled we have to ignore the first 4 bytes
        if *this.has_packet_info {
            let _ = buf.split_to(4);
        }

        Poll::Ready(Packet::parse(buf).map(Ok))
    }
}

impl<D> Sink<Packet> for Device<D>
where
    D: AsyncWrite,
{
    type Error = std::io::Error;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        // Make sure to flush outstanding data before starting to send:
        ready!(self.as_mut().poll_flush_buffer(cx))?;
        Poll::Ready(Ok(()))
    }

    fn start_send(self: Pin<&mut Self>, pkt: Packet) -> Result<(), Self::Error> {
        *self.project().outstanding = Some(pkt);
        Ok(())
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        ready!(self.as_mut().poll_flush_buffer(cx))?;
        ready!(self.project().inner.poll_flush(cx))?;
        Poll::Ready(Ok(()))
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        ready!(self.as_mut().poll_flush_buffer(cx))?;
        ready!(self.project().inner.poll_close(cx))?;
        Poll::Ready(Ok(()))
    }
}

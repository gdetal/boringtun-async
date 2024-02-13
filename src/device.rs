use std::{net::IpAddr, pin::Pin, task::{Context, Poll}};

use byteorder::{NativeEndian, NetworkEndian, WriteBytesExt};
use boringtun::noise::Tunn;
use futures::{Sink, Stream};
use pin_project::pin_project;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::{bytes::{BufMut, Bytes, BytesMut}, codec::{Decoder, Encoder, Framed}};

const PACKET_INFO_SIZE: usize = 4;

#[pin_project]
pub(crate) struct Device<D> {
    #[pin]
    inner: Framed<D, TunPacketCodec>,
}

impl<D> Device<D>
where
    D: AsyncRead + AsyncWrite
{
    pub(crate) fn new(device: D, has_packet_info: bool, pkt_size: usize) -> Self {
        Self {
            inner: Framed::new(device, TunPacketCodec {
                has_packet_info,
                pkt_size
            }),
        }
    }
}

impl<D> Stream for Device<D>
where
    D: AsyncRead
{

    type Item = Result<TunPacket, std::io::Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.project().inner.poll_next(cx)
    }
}


impl<D> Sink<&[u8]> for Device<D>
where
    D: AsyncWrite
{
    type Error = std::io::Error;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.project().inner.poll_ready(cx)
    }

    fn start_send(self: Pin<&mut Self>, pkt: &[u8]) -> Result<(), Self::Error> {
        self.project().inner.start_send(pkt)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.project().inner.poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.project().inner.poll_close(cx)
    }
}

#[derive(Debug)]
pub(crate) struct TunPacket(IpAddr, Bytes);

impl TunPacket {
    pub fn address(&self) -> IpAddr {
        self.0
    }

    pub fn bytes(&self) -> &[u8] {
        self.1.as_ref()
    }
}

struct TunPacketCodec {
    has_packet_info: bool,
    pkt_size: usize,
}

impl Decoder for TunPacketCodec {
    type Item = TunPacket;

    type Error = std::io::Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if buf.is_empty() {
            return Ok(None);
        }

        let mut pkt: BytesMut = buf.split_to(buf.len());

        // reserve enough space for the next packet
        if self.has_packet_info {
            buf.reserve(self.pkt_size + PACKET_INFO_SIZE);
        } else {
            buf.reserve(self.pkt_size);
        }

        // if the packet information is enabled we have to ignore the first 4 bytes
        if self.has_packet_info {
            println!("packet read HDR: {:?}", &pkt[..4]);
            let _ = pkt.split_to(PACKET_INFO_SIZE);
        }

        match Tunn::dst_address(pkt.as_ref()) {
            Some(addr) => Ok(Some(TunPacket(addr, pkt.freeze()))),
            None => return Ok(None),
        }
    }
}

impl Encoder<&[u8]> for TunPacketCodec {

    type Error = std::io::Error;

    fn encode(&mut self, item: &[u8], dst: &mut BytesMut) -> Result<(), Self::Error> {
        // TODO handle PACKET_INFO
        dst.reserve(item.len() + 4);

        let mut buf = Vec::<u8>::with_capacity(4);

        // flags is always 0
        buf.write_u16::<NativeEndian>(0)?;
        // write the protocol as network byte order

        #[cfg(target_os = "linux")]
        buf.write_u16::<NetworkEndian>(libc::ETH_P_IP as u16)?;

        #[cfg(target_os = "macos")]
        buf.write_u16::<NetworkEndian>(libc::PF_INET as u16)?;

        // TODO others ?

        println!("packet write HDR: {:?}", buf);

        dst.put_slice(&buf);
        dst.put(item);
        
        Ok(())
    }
}

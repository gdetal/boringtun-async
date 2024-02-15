use byteorder::{NativeEndian, NetworkEndian, WriteBytesExt};
use tokio_util::{
    bytes::{BufMut, BytesMut},
    codec::{Decoder, Encoder},
};

use crate::packet::Packet;

const PACKET_INFO_SIZE: usize = 4;

pub(crate) struct TunPacketCodec {
    has_packet_info: bool,
    pkt_size: usize,
}

impl TunPacketCodec {
    pub(crate) fn new(has_packet_info: bool, pkt_size: usize) -> Self {
        Self {
            has_packet_info,
            pkt_size,
        }
    }
}

impl Decoder for TunPacketCodec {
    type Item = Packet;

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
            let _ = pkt.split_to(PACKET_INFO_SIZE);
        }

        // println!("decode tun packet -> {:?}", pkt);

        Ok(Packet::parse(pkt))
    }
}

impl Encoder<Packet> for TunPacketCodec {
    type Error = std::io::Error;

    fn encode(&mut self, pkt: Packet, dst: &mut BytesMut) -> Result<(), Self::Error> {
        dst.reserve(pkt.len() + 4);

        if self.has_packet_info {
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

            dst.put_slice(&buf);
        }

        dst.put(pkt.into_bytes());

        Ok(())
    }
}

pub(crate) struct PacketCodec;

impl Decoder for PacketCodec {
    type Item = Packet;

    type Error = std::io::Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if buf.is_empty() {
            return Ok(None);
        }

        Ok(Packet::parse(buf.split_to(buf.len())))
    }
}

impl Encoder<Packet> for PacketCodec {
    type Error = std::io::Error;

    fn encode(&mut self, pkt: Packet, dst: &mut BytesMut) -> Result<(), Self::Error> {
        // println!("peers: packet write {:?}", pkt.get_bytes());

        dst.reserve(pkt.len());
        dst.put(pkt.into_bytes());

        // println!("encode packet -> {:?}", dst);

        Ok(())
    }
}

use byteorder::{NativeEndian, NetworkEndian, WriteBytesExt};
use etherparse::IpHeaders;
use tokio_util::{
    bytes::{BufMut, BytesMut},
    codec::{Decoder, Encoder},
};

use crate::packet::Packet;

/// The size of the packet information.
const PACKET_INFO_SIZE: usize = 4;

/// Represents a codec for encoding and decoding TUN packets.
pub(crate) struct TunPacketCodec {
    has_packet_info: bool,
    buffer_size: usize,
}

impl TunPacketCodec {
    pub(crate) fn new(has_packet_info: bool, buffer_size: usize) -> Self {
        Self {
            has_packet_info,
            buffer_size,
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

        // if the packet information is enabled we have to skip the information
        if self.has_packet_info {
            let _ = buf.split_to(PACKET_INFO_SIZE);
        }

        // This is a bit of a hack, but it's the only way to handle multiple packets in a single buffer.
        let len = match IpHeaders::from_slice_lax(buf) {
            Err(e) => {
                log::debug!("bad packet received: {e}");
                // Don't know the packet size -> flush all buffer:
                buf.len()
            }
            Ok((IpHeaders::Ipv4(h, _), _, _)) => h.total_len as usize,
            Ok((IpHeaders::Ipv6(h, _), _, _)) => h.header_len() + h.payload_length as usize,
        };

        // Retrieve packet from buffer:
        let pkt: BytesMut = buf.split_to(len);

        // reserve enough space for the next packet
        buf.reserve(self.buffer_size);

        Ok(Packet::parse(pkt))
    }
}

impl Encoder<Packet> for TunPacketCodec {
    type Error = std::io::Error;

    fn encode(&mut self, pkt: Packet, dst: &mut BytesMut) -> Result<(), Self::Error> {
        dst.reserve(pkt.len() + 4);

        // if the packet information is enabled we have to write the packet information
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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_tun_packet_codec_decode_empty_buffer() {
        let mut codec = TunPacketCodec::new(false, 1024);
        let mut buf = BytesMut::new();

        let result = codec.decode(&mut buf).unwrap();

        assert!(result.is_none());
    }

    #[test]
    fn test_tun_packet_codec_decode_ipv4() {
        let mut codec = TunPacketCodec {
            has_packet_info: false,
            buffer_size: 1024,
        };

        let mut buf = vec![
            0x45, // Version (4) and Header Length (5)
            0x00, // Type of Service
            0x00, 0x1c, // Total Length (28 bytes)
            0x00, 0x00, // Identification
            0x00, 0x00, // Flags and Fragment Offset
            0x80, // Time to Live (128)
            0x11, // Protocol (UDP)
            0x00, 0x00, // Header Checksum (to be calculated)
            0xc0, 0xa8, 0x00, 0x64, // Source IP Address (192.168.0.100)
            0xc0, 0xa8, 0x00, 0x01, // Destination IP Address (192.168.0.1)
            0x00, 0x50, // Source Port (80)
            0x00, 0x50, // Destination Port (80)
            0x00, 0x08, // Length (8 bytes)
            0x00, 0x00, // Checksum (to be calculated)
            // UDP payload containing "HELLO"
            b'H', b'E', b'L', b'L', b'O',
        ]
        .as_slice()
        .into();

        let result = codec.decode(&mut buf).unwrap();

        assert!(result.is_some());
    }

    #[test]
    fn test_tun_packet_codec_decode_ipv6() {
        let mut codec = TunPacketCodec {
            has_packet_info: false,
            buffer_size: 1024,
        };

        let mut buf = vec![
            0x60, // Version (6) and Traffic Class + Flow Label
            0x00, // Traffic Class + Flow Label
            0x00, 0x00, 0x00, // Flow Label
            0x00, 0x0a, // Payload Length (10 bytes)
            0x11, // Next Header (UDP)
            0x40, // Hop Limit (64)
            0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Source IP Address (fe80::)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // Source IP Address (fe80::1)
            0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Destination IP Address (fe80::)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x02, // Destination IP Address (fe80::2)
            0x24, 0x7e, // Source Port (9294)
            0x24, 0x7e, // Destination Port (9294)
            0x00, 0x0a, // Length (10 bytes)
            0x00, 0x00, // Checksum (to be calculated)
            // UDP payload containing "HELLO"
            b'H', b'E', b'L', b'L', b'O',
        ]
        .as_slice()
        .into();

        let result = codec.decode(&mut buf).unwrap();

        assert!(result.is_some());
    }

    #[test]
    fn test_packet_codec_encode() {
        let mut codec = TunPacketCodec {
            has_packet_info: false,
            buffer_size: 1024,
        };

        let buf: BytesMut = vec![
            0x45, // Version (4) and Header Length (5)
            0x00, // Type of Service
            0x00, 0x1c, // Total Length (28 bytes)
            0x00, 0x00, // Identification
            0x00, 0x00, // Flags and Fragment Offset
            0x80, // Time to Live (128)
            0x11, // Protocol (UDP)
            0x00, 0x00, // Header Checksum (to be calculated)
            0xc0, 0xa8, 0x00, 0x64, // Source IP Address (192.168.0.100)
            0xc0, 0xa8, 0x00, 0x01, // Destination IP Address (192.168.0.1)
            0x00, 0x50, // Source Port (80)
            0x00, 0x50, // Destination Port (80)
            0x00, 0x08, // Length (8 bytes)
            0x00, 0x00, // Checksum (to be calculated)
            // UDP payload containing "HELLO"
            b'H', b'E', b'L', b'L', b'O',
        ]
        .as_slice()
        .into();

        let pkt = Packet::parse(buf.clone()).unwrap();
        let mut dst = BytesMut::new();

        let result = codec.encode(pkt, &mut dst);

        assert!(result.is_ok());
        assert_eq!(dst.len(), buf.len());
        assert_eq!(dst[..], buf[..]);
    }

    #[test]
    fn test_packet_codec_encode_pi() {
        let mut codec = TunPacketCodec {
            has_packet_info: true,
            buffer_size: 1024,
        };

        let buf: BytesMut = vec![
            0x45, // Version (4) and Header Length (5)
            0x00, // Type of Service
            0x00, 0x1c, // Total Length (28 bytes)
            0x00, 0x00, // Identification
            0x00, 0x00, // Flags and Fragment Offset
            0x80, // Time to Live (128)
            0x11, // Protocol (UDP)
            0x00, 0x00, // Header Checksum (to be calculated)
            0xc0, 0xa8, 0x00, 0x64, // Source IP Address (192.168.0.100)
            0xc0, 0xa8, 0x00, 0x01, // Destination IP Address (192.168.0.1)
            0x00, 0x50, // Source Port (80)
            0x00, 0x50, // Destination Port (80)
            0x00, 0x08, // Length (8 bytes)
            0x00, 0x00, // Checksum (to be calculated)
            // UDP payload containing "HELLO"
            b'H', b'E', b'L', b'L', b'O',
        ]
        .as_slice()
        .into();

        let pkt = Packet::parse(buf.clone()).unwrap();
        let mut dst = BytesMut::new();

        let result = codec.encode(pkt, &mut dst);

        assert!(result.is_ok());
        assert_eq!(dst.len(), buf.len() + 4);
        assert_eq!(dst[4..], buf[..]);
    }
}

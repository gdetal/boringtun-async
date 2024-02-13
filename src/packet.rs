use std::net::IpAddr;

use boringtun::noise::Tunn;
use tokio_util::bytes::{Bytes, BytesMut};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketProtocol {
    IPv4,
    IPv6,
}

fn infer_proto(buf: &[u8]) -> Option<PacketProtocol> {
    match buf[0] >> 4 {
        4 => Some(PacketProtocol::IPv4),
        6 => Some(PacketProtocol::IPv6),
        _ => None,
    }
}

/// Represents a network packet from a TUN device.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Packet {
    bytes: Bytes,
    proto: PacketProtocol,
    address: IpAddr,
}

impl Packet {
    pub fn parse(buf: BytesMut) -> Option<Self> {
        let proto = infer_proto(&buf)?;
        let address = Tunn::dst_address(&buf)?;

        Some(Self {
            bytes: buf.into(),
            proto,
            address,
        })
    }

    pub fn get_bytes(&self) -> &[u8] {
        self.bytes.as_ref()
    }

    pub fn get_proto(&self) -> PacketProtocol {
        self.proto
    }

    pub fn get_dst_address(&self) -> IpAddr {
        self.address
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn into_bytes(self) -> Bytes {
        self.bytes
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    #[test]
    fn test_parse_packet_ipv4() {
        let raw = vec![
            0x45, 0x00, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 0x40, 0x11, 0x00, 0x00, 0xc0, 0xa8,
            0x00, 0x01, 0xc0, 0xa8, 0x00, 0x02,
        ];
        let buf = BytesMut::from(raw.as_slice());
        let packet = Packet::parse(buf).unwrap();

        assert_eq!(packet.get_proto(), PacketProtocol::IPv4);
        assert_eq!(
            packet.get_dst_address(),
            IpAddr::V4(Ipv4Addr::new(192, 168, 0, 2))
        );
        assert_eq!(packet.len(), 20);
    }

    #[test]
    fn test_parse_packet_invalid() {
        let raw = vec![
            0x30, 0x00, 0x00, 0x00, 0x00, 0x14, 0x3a, 0xff, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x02, 0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x01,
        ];
        let buf = BytesMut::from(raw.as_slice());
        let packet = Packet::parse(buf);

        assert!(packet.is_none());
    }
}

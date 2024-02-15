use std::net::IpAddr;

use boringtun::noise::Tunn;
use tokio_util::bytes::{Bytes, BytesMut};

#[derive(Debug, Clone, Copy)]
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

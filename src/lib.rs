mod api;
mod codec;
mod device;
mod packet;
mod peer;
mod tunnel;

const MAX_UDP_SIZE: usize = (1 << 16) - 1;

pub use device::*;

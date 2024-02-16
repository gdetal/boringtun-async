mod codec;
mod device;
mod packet;
mod peer;
mod peers;
mod tunnel;

const MAX_UDP_SIZE: usize = (1 << 16) - 1;

pub use device::*;
pub use tunnel::*;

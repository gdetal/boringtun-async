mod api;
mod builder;
mod codec;
mod config;
mod device;
mod packet;
mod peer;
mod tunnel;

const MAX_UDP_SIZE: usize = (1 << 16) - 1;

pub use builder::*;
pub use config::*;
pub use device::*;
pub use tunnel::*;

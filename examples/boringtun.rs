extern crate tun;

use std::net::IpAddr;

use boringtun::{device::{allowed_ips, peer::AllowedIP}, x25519::{PublicKey, StaticSecret}};
use boringtun_async::Tunnel;

struct KeyBytes(pub [u8; 32]);

impl std::str::FromStr for KeyBytes {
    type Err = &'static str;

    /// Can parse a secret key from a hex or base64 encoded string.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut internal = [0u8; 32];

        match s.len() {
            64 => {
                // Try to parse as hex
                for i in 0..32 {
                    internal[i] = u8::from_str_radix(&s[i * 2..=i * 2 + 1], 16)
                        .map_err(|_| "Illegal character in key")?;
                }
            }
            43 | 44 => {
                // Try to parse as base64
                if let Ok(decoded_key) = base64::decode(s) {
                    if decoded_key.len() == internal.len() {
                        internal[..].copy_from_slice(&decoded_key);
                    } else {
                        return Err("Illegal character in key");
                    }
                }
            }
            _ => return Err("Illegal key size"),
        }

        Ok(KeyBytes(internal))
    }
}

#[tokio::main]
async fn main() {
    let mut config = tun::Configuration::default();

    config
        .platform(|config| {
            #[cfg(target_os = "linux")]
            config.packet_information(true);
        })
        .name("utun42")
        .address((10, 2, 0, 2))
        .netmask((255, 255, 255, 255))
        .destination((10, 2, 0, 2))
        .up();


    let dev = tun::create_as_async(&config).unwrap();

    let ifindex = default_net::interface::get_interfaces().iter().find(|e| e.name == "utun42").unwrap().index;

    let handle = net_route::Handle::new().unwrap();
    let route = net_route::Route::new("8.8.8.8".parse().unwrap(), 32)
        .with_ifindex(ifindex);
    handle.add(&route).await.unwrap();

    let private_key = "aCyyrK5JeEPNkCs4fm92YcYnefQSvekUeJUGl1Kh5UE=".parse::<KeyBytes>().unwrap();
    let mut tunnel = Tunnel::new(StaticSecret::from(private_key.0), dev);

    let peer_public_key = "MK3425tJbRhEz+1xQLxlL+l6GNl52zKNwo5V0fHEwj4=".parse::<KeyBytes>().unwrap();
    let peer_endpoint = "195.181.167.193:51820".parse().unwrap();
    let allowed_ips = vec![AllowedIP { addr: "0.0.0.0".parse().unwrap(), cidr: 0 }];

    tunnel.add_peer(PublicKey::from(peer_public_key.0), peer_endpoint, &allowed_ips);

    tokio::select! {
        _ = tokio::signal::ctrl_c() => {},
        _ = tunnel => {},
    };
}
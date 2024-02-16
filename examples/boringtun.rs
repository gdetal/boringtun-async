extern crate tun;

use async_compat::Compat;
use boringtun::x25519::{PublicKey, StaticSecret};
use boringtun_async::{Device, Tunnel};
use ip_network::IpNetwork;

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
        .name("utun42")
        .address((10, 2, 0, 2))
        .netmask((255, 255, 255, 255))
        .mtu(1440)
        .up();

    #[cfg(target_os = "linux")]
    let config = config.platform(|config| {
        config.packet_information(true);
    });

    #[cfg(not(target_os = "windows"))]
    let config = config.destination((10, 2, 0, 2));

    let dev = tun::create_as_async(&config).unwrap();


    #[cfg(not(target_os = "windows"))]
    {
        let handle = net_route::Handle::new().unwrap();
        let route = net_route::Route::new("146.59.195.115".parse().unwrap(), 32)
            .with_gateway("10.2.0.2".parse().unwrap());
        handle.add(&route).await.unwrap();
    }

    #[cfg(target_os = "windows")]
    let has_pi = false;

    #[cfg(not(target_os = "windows"))]
    let has_pi = true;

    let dev = Device::new(Compat::new(dev), has_pi, 1512);

    let private_key = "aCyyrK5JeEPNkCs4fm92YcYnefQSvekUeJUGl1Kh5UE="
        .parse::<KeyBytes>()
        .unwrap();
    let mut tunnel = Tunnel::new(StaticSecret::from(private_key.0), dev).unwrap();

    let peer_public_key = "MK3425tJbRhEz+1xQLxlL+l6GNl52zKNwo5V0fHEwj4="
        .parse::<KeyBytes>()
        .unwrap();
    let peer_endpoint = "195.181.167.193:51820".parse().unwrap();
    let allowed_ips = vec![IpNetwork::from_str_truncate("0.0.0.0/0").unwrap()];

    tunnel.add_peer(
        PublicKey::from(peer_public_key.0),
        peer_endpoint,
        &allowed_ips,
    );

    tokio::select! {
        _ = tokio::signal::ctrl_c() => {},
        res = tunnel.run() => {
            if let Err(e) = res {
                eprintln!("failed with {e}");
            }
        },
    };
}

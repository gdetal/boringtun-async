use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
};

use boringtun::x25519;
use ip_network::IpNetwork;
use serde::Deserialize;

mod subnet_list {
    use ip_network::IpNetwork;
    use serde::{self, Deserialize, Deserializer};

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<IpNetwork>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let list = String::deserialize(deserializer)?;

        let subnets: Result<Vec<IpNetwork>, _> =
            list.split(',').map(|s| s.trim().parse()).collect();

        match subnets {
            Ok(subnets) => Ok(subnets),
            Err(_) => Err(serde::de::Error::custom("Failed to deserialize IpNet")),
        }
    }
}

mod private_key {
    use base64::prelude::*;
    use boringtun::x25519::StaticSecret;
    use serde::{self, Deserialize, Deserializer};

    pub fn deserialize<'de, D>(deserializer: D) -> Result<StaticSecret, D::Error>
    where
        D: Deserializer<'de>,
    {
        let key = String::deserialize(deserializer)?;
        let mut internal = [0u8; 32];

        match key.len() {
            64 => {
                // Try to parse as hex
                for i in 0..32 {
                    internal[i] = u8::from_str_radix(&key[i * 2..=i * 2 + 1], 16)
                        .map_err(|_| serde::de::Error::custom("Illegal character in key"))?;
                }
            }
            43 | 44 => {
                // Try to parse as base64
                if let Ok(decoded_key) = BASE64_STANDARD.decode(key) {
                    if decoded_key.len() == internal.len() {
                        internal[..].copy_from_slice(&decoded_key);
                    } else {
                        return Err(serde::de::Error::custom("Illegal character in key"));
                    }
                }
            }
            _ => return Err(serde::de::Error::custom("Illegal size of key")),
        }

        Ok(StaticSecret::from(internal))
    }
}

mod public_key {
    use base64::prelude::*;
    use boringtun::x25519::PublicKey;
    use serde::{self, Deserialize, Deserializer};

    pub fn deserialize<'de, D>(deserializer: D) -> Result<PublicKey, D::Error>
    where
        D: Deserializer<'de>,
    {
        let key = String::deserialize(deserializer)?;
        let mut internal = [0u8; 32];

        match key.len() {
            64 => {
                // Try to parse as hex
                for i in 0..32 {
                    internal[i] = u8::from_str_radix(&key[i * 2..=i * 2 + 1], 16)
                        .map_err(|_| serde::de::Error::custom("Illegal character in key"))?;
                }
            }
            43 | 44 => {
                // Try to parse as base64
                if let Ok(decoded_key) = BASE64_STANDARD.decode(key) {
                    if decoded_key.len() == internal.len() {
                        internal[..].copy_from_slice(&decoded_key);
                    } else {
                        return Err(serde::de::Error::custom("Illegal character in key"));
                    }
                }
            }
            _ => return Err(serde::de::Error::custom("Illegal size of key")),
        }

        Ok(PublicKey::from(internal))
    }
}

mod option_u16 {
    use serde::{self, Deserialize, Deserializer};

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<u16>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = Option::<String>::deserialize(deserializer)?;

        match value {
            Some(s) => {
                let port: u16 = s.parse().map_err(serde::de::Error::custom)?;
                Ok(Some(port))
            }
            None => Ok(None),
        }
    }
}

/// Represent a wg config
/// see https://man7.org/linux/man-pages/man8/wg.8.html
#[derive(Deserialize, Clone)]
pub struct WgConfig {
    pub interface: WgInterfaceConfig,
    pub peer: WgPeerConfig,
}

#[derive(Deserialize, Clone)]
/// Represents the configuration for a WireGuard interface.
pub struct WgInterfaceConfig {
    /// The private key used for encryption.
    #[serde(with = "private_key")]
    pub privatekey: x25519::StaticSecret,

    /// The port to listen on.
    #[serde(default, with = "option_u16")]
    pub listenport: Option<u16>,

    // wg-quick parts:
    /// The IP network address for the interface.
    pub address: IpNetwork,

    /// The DNS server IP address.
    pub dns: Option<IpAddr>,

    /// The Maximum Transmission Unit (MTU) size.
    #[serde(default, with = "option_u16")]
    pub mtu: Option<u16>,
    // TODO: add more standard config parts
}

#[derive(Deserialize, Clone)]
/// Represents the configuration for a WireGuard peer.
pub struct WgPeerConfig {
    /// The public key of the peer.
    #[serde(with = "public_key")]
    pub publickey: x25519::PublicKey,

    /// The list of allowed IP networks for the peer.
    #[serde(with = "subnet_list")]
    pub allowedips: Vec<IpNetwork>,

    /// The endpoint address and port for the peer.
    pub endpoint: SocketAddr,

    /// The optional persistent keepalive interval for the peer.
    #[serde(default, with = "option_u16")]
    pub persistant_keepalive: Option<u16>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ConfigError {
    #[error("parsing error")]
    ParseError,
    #[error("ip subnet format error")]
    IpNetFormat,
    #[error("socket address format error")]
    SocketAddrFormat,
    #[error("ip address format error")]
    IpAddrFormat,
}

impl WgConfig {
    fn from_map(
        map: HashMap<String, HashMap<String, Option<String>>>,
    ) -> Result<Self, ConfigError> {
        let json = serde_json::to_string(&map).map_err(|_| ConfigError::ParseError)?;

        serde_json::from_str(&json).map_err(|_| ConfigError::ParseError)
    }

    /// A wg config is a special ini format
    /// The parsing is done by transforming the ini into a hashmap then to json to be then deserialized using serde.
    pub fn from_str(raw: &str) -> Result<Self, ConfigError> {
        let mut config = configparser::ini::Ini::new();
        let config = config.read(raw.to_string()).map_err(|e| {
            log::error!("Cannot parse the following config, got {e:?}\n{raw}");
            ConfigError::ParseError
        })?;
        Self::from_map(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_wg_config_from_str() {
        let raw = r#"
            [Interface]
            PrivateKey = iFB/FQqt1Slg78ITyY4BoWXLI+xWaeuEE9q+3T0Gi3A=
            ListenPort = 4242
            Address = 10.0.0.1/32
            Dns = 8.8.8.8

            [Peer]
            PublicKey = jiIKlk1tiyPgxJ4sP/xy4eCuibeeSlOhPmkNxFR/iA8=
            AllowedIPs = 0.0.0.0/0
            Endpoint = 192.168.0.1:51820
        "#;

        let wg_config = WgConfig::from_str(raw).unwrap();

        assert_eq!(
            wg_config.interface.privatekey.to_bytes(),
            [
                136, 80, 127, 21, 10, 173, 213, 41, 96, 239, 194, 19, 201, 142, 1, 161, 101, 203,
                35, 236, 86, 105, 235, 132, 19, 218, 190, 221, 61, 6, 139, 112
            ]
        );
        assert_eq!(wg_config.interface.listenport, Some(4242));
        assert_eq!(
            wg_config.interface.address,
            "10.0.0.1/32".parse::<IpNetwork>().unwrap()
        );
        assert_eq!(wg_config.interface.dns, Some("8.8.8.8".parse().unwrap()));
        assert_eq!(wg_config.interface.mtu, None);

        assert_eq!(
            wg_config.peer.publickey.to_bytes(),
            [
                142, 34, 10, 150, 77, 109, 139, 35, 224, 196, 158, 44, 63, 252, 114, 225, 224, 174,
                137, 183, 158, 74, 83, 161, 62, 105, 13, 196, 84, 127, 136, 15
            ]
        );
        assert_eq!(
            wg_config.peer.allowedips,
            vec!["0.0.0.0/0".parse::<IpNetwork>().unwrap()]
        );
        assert_eq!(
            wg_config.peer.endpoint,
            "192.168.0.1:51820".parse().unwrap()
        );
        assert_eq!(wg_config.peer.persistant_keepalive, None);
    }

    #[test]
    fn test_wg_config_from_str_invalid() {
        let raw = r#"
            [InvalidSection]
            InvalidKey = InvalidValue
        "#;

        let result = WgConfig::from_str(raw);

        assert_eq!(result.err(), Some(ConfigError::ParseError));
    }
}

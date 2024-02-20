use base64::prelude::*;
use boringtun::x25519;

#[derive(Debug, thiserror::Error)]
pub enum KeyParseError {
    #[error("Illegal character in key")]
    IllegalCharacter,
    #[error("Illegal key size")]
    IllegalSize,
}

pub struct PrivateKey(x25519::StaticSecret);

impl TryFrom<&str> for PrivateKey {
    type Error = KeyParseError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let mut internal = [0u8; 32];

        match value.len() {
            64 => {
                // Try to parse as hex
                for i in 0..32 {
                    internal[i] = u8::from_str_radix(&value[i * 2..=i * 2 + 1], 16)
                        .map_err(|_| KeyParseError::IllegalCharacter)?;
                }
            }
            43 | 44 => {
                // Try to parse as base64
                if let Ok(decoded_key) = BASE64_STANDARD.decode(value) {
                    if decoded_key.len() == internal.len() {
                        internal[..].copy_from_slice(&decoded_key);
                    } else {
                        return Err(KeyParseError::IllegalCharacter);
                    }
                }
            }
            _ => return Err(KeyParseError::IllegalSize),
        }

        Ok(PrivateKey(x25519::StaticSecret::from(internal)))
    }
}

impl From<PrivateKey> for x25519::StaticSecret {
    fn from(value: PrivateKey) -> Self {
        value.0
    }
}

pub struct PublicKey(x25519::PublicKey);

impl TryFrom<&str> for PublicKey {
    type Error = KeyParseError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let mut internal = [0u8; 32];

        match value.len() {
            64 => {
                // Try to parse as hex
                for i in 0..32 {
                    internal[i] = u8::from_str_radix(&value[i * 2..=i * 2 + 1], 16)
                        .map_err(|_| KeyParseError::IllegalCharacter)?;
                }
            }
            43 | 44 => {
                // Try to parse as base64
                if let Ok(decoded_key) = BASE64_STANDARD.decode(value) {
                    if decoded_key.len() == internal.len() {
                        internal[..].copy_from_slice(&decoded_key);
                    } else {
                        return Err(KeyParseError::IllegalCharacter);
                    }
                }
            }
            _ => return Err(KeyParseError::IllegalSize),
        }

        Ok(PublicKey(x25519::PublicKey::from(internal)))
    }
}

impl From<PublicKey> for x25519::PublicKey {
    fn from(value: PublicKey) -> Self {
        value.0
    }
}

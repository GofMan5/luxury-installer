use std::{fmt, str::FromStr};

use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};

use crate::SpecError;

const KEY_ID_BYTES: usize = 32;
const PUBLIC_KEY_BYTES: usize = 32;
const ROTATION_PROOF_BYTES: usize = 64;

macro_rules! impl_fixed_hex_traits {
    ($type:ident) => {
        impl fmt::Display for $type {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&hex::encode(self.0))
            }
        }

        impl fmt::Debug for $type {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_tuple(stringify!($type))
                    .field(&self.to_string())
                    .finish()
            }
        }

        impl FromStr for $type {
            type Err = SpecError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::parse(value)
            }
        }

        impl Serialize for $type {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_str(&self.to_string())
            }
        }

        impl<'de> Deserialize<'de> for $type {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                Self::parse(String::deserialize(deserializer)?).map_err(D::Error::custom)
            }
        }
    };
}

/// Stable identifier of a publisher verification key.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PublisherKeyId([u8; KEY_ID_BYTES]);

impl PublisherKeyId {
    pub fn parse(value: impl Into<String>) -> Result<Self, SpecError> {
        parse_fixed_hex(value.into(), SpecError::InvalidPublisherKeyId).map(Self)
    }

    pub const fn from_bytes(bytes: [u8; KEY_ID_BYTES]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; KEY_ID_BYTES] {
        &self.0
    }
}

/// Raw Ed25519 publisher verification key embedded in a rotation manifest.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PublisherPublicKey([u8; PUBLIC_KEY_BYTES]);

impl PublisherPublicKey {
    pub fn parse(value: impl Into<String>) -> Result<Self, SpecError> {
        parse_fixed_hex(value.into(), SpecError::InvalidPublisherPublicKey).map(Self)
    }

    pub const fn from_bytes(bytes: [u8; PUBLIC_KEY_BYTES]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; PUBLIC_KEY_BYTES] {
        &self.0
    }
}

/// Ed25519 proof that the next publisher key is available to sign updates.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct PublisherRotationProof([u8; ROTATION_PROOF_BYTES]);

impl PublisherRotationProof {
    pub fn parse(value: impl Into<String>) -> Result<Self, SpecError> {
        parse_fixed_hex(value.into(), SpecError::InvalidPublisherRotationProof).map(Self)
    }

    pub const fn from_bytes(bytes: [u8; ROTATION_PROOF_BYTES]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; ROTATION_PROOF_BYTES] {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublisherRotation {
    pub next_public_key: PublisherPublicKey,
    pub proof: PublisherRotationProof,
}

impl fmt::Display for PublisherKeyId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&hex::encode(self.0))
    }
}

impl fmt::Debug for PublisherKeyId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("PublisherKeyId")
            .field(&self.to_string())
            .finish()
    }
}

impl_fixed_hex_traits!(PublisherPublicKey);
impl_fixed_hex_traits!(PublisherRotationProof);

impl FromStr for PublisherKeyId {
    type Err = SpecError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

impl Serialize for PublisherKeyId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for PublisherKeyId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::parse(String::deserialize(deserializer)?).map_err(D::Error::custom)
    }
}

fn parse_fixed_hex<const N: usize>(
    value: String,
    invalid: SpecError,
) -> Result<[u8; N], SpecError> {
    if value.len() != N * 2
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(invalid);
    }

    let mut bytes = [0_u8; N];
    hex::decode_to_slice(&value, &mut bytes).map_err(|_| invalid)?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
    struct StoredId {
        id: PublisherKeyId,
    }

    #[test]
    fn round_trips_bytes_text_and_serde() {
        let bytes = [0xab; KEY_ID_BYTES];
        let id = PublisherKeyId::from_bytes(bytes);
        let encoded = "ab".repeat(KEY_ID_BYTES);

        assert_eq!(id.as_bytes(), &bytes);
        assert_eq!(id.to_string(), encoded);
        assert_eq!(PublisherKeyId::parse(&encoded).unwrap(), id);

        let toml = toml::to_string(&StoredId { id }).unwrap();
        assert_eq!(toml, format!("id = \"{encoded}\"\n"));
        assert_eq!(toml::from_str::<StoredId>(&toml).unwrap(), StoredId { id });
    }

    #[test]
    fn rejects_non_canonical_ids() {
        for value in [
            "",
            &"a".repeat(KEY_ID_BYTES * 2 - 1),
            &"a".repeat(KEY_ID_BYTES * 2 + 1),
            &"A".repeat(KEY_ID_BYTES * 2),
            &"g".repeat(KEY_ID_BYTES * 2),
        ] {
            assert!(matches!(
                PublisherKeyId::parse(value),
                Err(SpecError::InvalidPublisherKeyId)
            ));
        }
    }

    #[test]
    fn rotation_values_are_canonical_hex() {
        let rotation = PublisherRotation {
            next_public_key: PublisherPublicKey::from_bytes([0x12; PUBLIC_KEY_BYTES]),
            proof: PublisherRotationProof::from_bytes([0x34; ROTATION_PROOF_BYTES]),
        };
        let encoded = toml::to_string(&rotation).unwrap();
        assert_eq!(
            toml::from_str::<PublisherRotation>(&encoded).unwrap(),
            rotation
        );
        assert_eq!(
            rotation.next_public_key.to_string(),
            "12".repeat(PUBLIC_KEY_BYTES)
        );
        assert_eq!(
            rotation.proof.to_string(),
            "34".repeat(ROTATION_PROOF_BYTES)
        );

        assert!(matches!(
            PublisherPublicKey::parse("A".repeat(PUBLIC_KEY_BYTES * 2)),
            Err(SpecError::InvalidPublisherPublicKey)
        ));
        assert!(matches!(
            PublisherRotationProof::parse("0".repeat(ROTATION_PROOF_BYTES * 2 - 1)),
            Err(SpecError::InvalidPublisherRotationProof)
        ));
    }

    #[test]
    fn rejected_publisher_values_are_absent_from_errors() {
        let secret = concat!("-----BEGIN PRIVATE ", "KEY-----SECRET-MARKER");
        for error in [
            PublisherKeyId::parse(secret).unwrap_err(),
            PublisherPublicKey::parse(secret).unwrap_err(),
            PublisherRotationProof::parse(secret).unwrap_err(),
        ] {
            assert!(!error.to_string().contains(secret));
            assert!(!format!("{error:?}").contains(secret));
            assert!(!error.to_string().contains("PRIVATE KEY"));
        }
    }
}

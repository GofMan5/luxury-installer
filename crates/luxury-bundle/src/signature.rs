use ed25519_dalek::{
    Signature, Signer, SigningKey, VerifyingKey,
    pkcs8::{DecodePrivateKey, DecodePublicKey},
};
use luxury_spec::{
    PackageId, PublisherKeyId, PublisherPublicKey, PublisherRotation, PublisherRotationProof,
};
use semver::Version;
use sha2::{Digest, Sha256};
use thiserror::Error;

const KEY_ID_DOMAIN: &[u8] = b"luxury.luxpkg.publisher-key.ed25519.v1\0";
const SIGNATURE_DOMAIN: &[u8] = b"luxury.luxpkg.publisher-signature.v1\0";
const ROTATION_DOMAIN: &[u8] = b"luxury.luxpkg.publisher-rotation-proof.ed25519.v1\0";
const KEY_ID_LEN: usize = 32;
const SIGNATURE_LEN: usize = 64;
const TRANSCRIPT_LEN: usize = SIGNATURE_DOMAIN.len() + KEY_ID_LEN + 32;

pub(crate) const SIGNATURE_RECORD_LEN: usize = KEY_ID_LEN + SIGNATURE_LEN;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum PublisherKeyError {
    #[error("invalid PKCS#8 PEM signing key")]
    InvalidSigningKeyPem,
    #[error("invalid SPKI PEM public key")]
    InvalidPublicKeyPem,
    #[error("publisher rotation must use a different next key")]
    RotationToSameKey,
    #[error("publisher rotation context is too long")]
    RotationContextTooLong,
}

pub struct PackageSigningKey {
    signing_key: SigningKey,
}

impl PackageSigningKey {
    pub fn from_pkcs8_pem(pem: &str) -> Result<Self, PublisherKeyError> {
        SigningKey::from_pkcs8_pem(pem)
            .map(|signing_key| Self { signing_key })
            .map_err(|_| PublisherKeyError::InvalidSigningKeyPem)
    }

    pub fn key_id(&self) -> PublisherKeyId {
        key_id(&self.signing_key.verifying_key())
    }

    pub fn create_publisher_rotation(
        &self,
        package_id: &PackageId,
        version: &Version,
        current_key_id: PublisherKeyId,
    ) -> Result<PublisherRotation, PublisherKeyError> {
        if self.key_id() == current_key_id {
            return Err(PublisherKeyError::RotationToSameKey);
        }
        let next_public_key =
            PublisherPublicKey::from_bytes(self.signing_key.verifying_key().to_bytes());
        let transcript = rotation_transcript(package_id, version, current_key_id, next_public_key)
            .ok_or(PublisherKeyError::RotationContextTooLong)?;
        let proof = self.signing_key.sign(&transcript);
        Ok(PublisherRotation {
            next_public_key,
            proof: PublisherRotationProof::from_bytes(proof.to_bytes()),
        })
    }
}

#[derive(Clone, Copy)]
pub struct TrustedPublisherKey {
    verifying_key: VerifyingKey,
}

impl TrustedPublisherKey {
    pub fn from_public_key_pem(pem: &str) -> Result<Self, PublisherKeyError> {
        VerifyingKey::from_public_key_pem(pem)
            .map(|verifying_key| Self { verifying_key })
            .map_err(|_| PublisherKeyError::InvalidPublicKeyPem)
    }

    pub fn key_id(&self) -> PublisherKeyId {
        key_id(&self.verifying_key)
    }
}

pub(crate) fn sign_manifest(
    signing_key: &PackageSigningKey,
    exact_manifest_bytes: &[u8],
) -> [u8; SIGNATURE_RECORD_LEN] {
    let key_id = signing_key.key_id();
    let signature: Signature = signing_key
        .signing_key
        .sign(&transcript(key_id, exact_manifest_bytes));
    let mut record = [0_u8; SIGNATURE_RECORD_LEN];
    record[..KEY_ID_LEN].copy_from_slice(key_id.as_bytes());
    record[KEY_ID_LEN..].copy_from_slice(&signature.to_bytes());
    record
}

pub(crate) fn signature_record_key_id(record: &[u8; SIGNATURE_RECORD_LEN]) -> PublisherKeyId {
    let mut bytes = [0_u8; KEY_ID_LEN];
    bytes.copy_from_slice(&record[..KEY_ID_LEN]);
    PublisherKeyId::from_bytes(bytes)
}

pub(crate) fn verify_manifest_signature(
    trusted_key: &TrustedPublisherKey,
    exact_manifest_bytes: &[u8],
    record: &[u8; SIGNATURE_RECORD_LEN],
) -> bool {
    let record_key_id = signature_record_key_id(record);
    if record_key_id != trusted_key.key_id() {
        return false;
    }

    let mut signature_bytes = [0_u8; SIGNATURE_LEN];
    signature_bytes.copy_from_slice(&record[KEY_ID_LEN..]);
    let signature = Signature::from_bytes(&signature_bytes);
    trusted_key
        .verifying_key
        .verify_strict(&transcript(record_key_id, exact_manifest_bytes), &signature)
        .is_ok()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PublisherRotationError {
    InvalidPublicKey,
    SameKey,
    ContextTooLong,
    InvalidProof,
}

pub(crate) fn verify_publisher_rotation(
    package_id: &PackageId,
    version: &Version,
    current_key_id: PublisherKeyId,
    rotation: &PublisherRotation,
) -> Result<PublisherKeyId, PublisherRotationError> {
    let next_key = VerifyingKey::from_bytes(rotation.next_public_key.as_bytes())
        .map_err(|_| PublisherRotationError::InvalidPublicKey)?;
    let next_key_id = key_id(&next_key);
    if next_key_id == current_key_id {
        return Err(PublisherRotationError::SameKey);
    }
    let proof = Signature::from_bytes(rotation.proof.as_bytes());
    let transcript = rotation_transcript(
        package_id,
        version,
        current_key_id,
        rotation.next_public_key,
    )
    .ok_or(PublisherRotationError::ContextTooLong)?;
    next_key
        .verify_strict(&transcript, &proof)
        .map_err(|_| PublisherRotationError::InvalidProof)?;
    Ok(next_key_id)
}

fn key_id(verifying_key: &VerifyingKey) -> PublisherKeyId {
    let mut hasher = Sha256::new();
    hasher.update(KEY_ID_DOMAIN);
    hasher.update(verifying_key.as_bytes());
    PublisherKeyId::from_bytes(hasher.finalize().into())
}

fn rotation_transcript(
    package_id: &PackageId,
    version: &Version,
    current_key_id: PublisherKeyId,
    next_public_key: PublisherPublicKey,
) -> Option<Vec<u8>> {
    let version = version.to_string();
    let package_id = package_id.as_str().as_bytes();
    let package_id_len = u32::try_from(package_id.len()).ok()?;
    let version_len = u32::try_from(version.len()).ok()?;
    let mut transcript = Vec::with_capacity(
        ROTATION_DOMAIN.len() + 4 + package_id.len() + 4 + version.len() + 32 + 32,
    );
    transcript.extend_from_slice(ROTATION_DOMAIN);
    transcript.extend_from_slice(&package_id_len.to_be_bytes());
    transcript.extend_from_slice(package_id);
    transcript.extend_from_slice(&version_len.to_be_bytes());
    transcript.extend_from_slice(version.as_bytes());
    transcript.extend_from_slice(current_key_id.as_bytes());
    transcript.extend_from_slice(next_public_key.as_bytes());
    Some(transcript)
}

fn transcript(key_id: PublisherKeyId, exact_manifest_bytes: &[u8]) -> [u8; TRANSCRIPT_LEN] {
    let manifest_hash = Sha256::digest(exact_manifest_bytes);
    let mut transcript = [0_u8; TRANSCRIPT_LEN];
    let key_id_start = SIGNATURE_DOMAIN.len();
    let manifest_hash_start = key_id_start + KEY_ID_LEN;
    transcript[..key_id_start].copy_from_slice(SIGNATURE_DOMAIN);
    transcript[key_id_start..manifest_hash_start].copy_from_slice(key_id.as_bytes());
    transcript[manifest_hash_start..].copy_from_slice(&manifest_hash);
    transcript
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signing_key(seed: u8) -> PackageSigningKey {
        PackageSigningKey {
            signing_key: SigningKey::from_bytes(&[seed; 32]),
        }
    }

    #[test]
    fn signature_binds_manifest_record_and_trusted_key() {
        let package_key = signing_key(7);
        let trusted_key = TrustedPublisherKey {
            verifying_key: package_key.signing_key.verifying_key(),
        };
        let manifest = b"format = 2\nname = \"example\"\n";
        let record = sign_manifest(&package_key, manifest);

        assert!(verify_manifest_signature(&trusted_key, manifest, &record));
        assert!(!verify_manifest_signature(
            &trusted_key,
            b"format = 2\nname = \"tampered\"\n",
            &record,
        ));
        let other_key = signing_key(8);
        let other_trusted_key = TrustedPublisherKey {
            verifying_key: other_key.signing_key.verifying_key(),
        };
        assert!(!verify_manifest_signature(
            &other_trusted_key,
            manifest,
            &record
        ));

        let mut mismatched_record = record;
        mismatched_record[0] ^= 1;
        assert!(!verify_manifest_signature(
            &trusted_key,
            manifest,
            &mismatched_record,
        ));
        assert_eq!(package_key.key_id().to_string().len(), 64);
    }

    #[test]
    fn rotation_proof_binds_both_keys_package_and_version() {
        let current = signing_key(7);
        let next = signing_key(8);
        let package_id = PackageId::parse("dev.luxury.demo").unwrap();
        let version = Version::new(2, 0, 0);
        let rotation = next
            .create_publisher_rotation(&package_id, &version, current.key_id())
            .unwrap();

        assert_eq!(
            verify_publisher_rotation(&package_id, &version, current.key_id(), &rotation),
            Ok(next.key_id())
        );
        assert_eq!(
            verify_publisher_rotation(
                &PackageId::parse("dev.luxury.other").unwrap(),
                &version,
                current.key_id(),
                &rotation,
            ),
            Err(PublisherRotationError::InvalidProof)
        );
        assert_eq!(
            verify_publisher_rotation(
                &package_id,
                &Version::new(2, 0, 1),
                current.key_id(),
                &rotation,
            ),
            Err(PublisherRotationError::InvalidProof)
        );
        assert_eq!(
            verify_publisher_rotation(&package_id, &version, signing_key(9).key_id(), &rotation),
            Err(PublisherRotationError::InvalidProof)
        );
        assert_eq!(
            current.create_publisher_rotation(&package_id, &version, current.key_id()),
            Err(PublisherKeyError::RotationToSameKey)
        );
    }

    #[test]
    fn rotation_transcript_bytes_are_stable() {
        let package_id = PackageId::parse("dev.luxury.demo").unwrap();
        let version = Version::new(2, 0, 0);
        let current = PublisherKeyId::from_bytes([0x11; 32]);
        let next = PublisherPublicKey::from_bytes([0x22; 32]);
        let mut expected = b"luxury.luxpkg.publisher-rotation-proof.ed25519.v1\0".to_vec();
        expected.extend_from_slice(&15_u32.to_be_bytes());
        expected.extend_from_slice(b"dev.luxury.demo");
        expected.extend_from_slice(&5_u32.to_be_bytes());
        expected.extend_from_slice(b"2.0.0");
        expected.extend_from_slice(&[0x11; 32]);
        expected.extend_from_slice(&[0x22; 32]);

        assert_eq!(
            rotation_transcript(&package_id, &version, current, next).unwrap(),
            expected
        );
    }
}

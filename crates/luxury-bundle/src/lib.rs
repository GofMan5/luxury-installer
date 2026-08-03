//! Deterministic .luxpkg bundle reader/writer.
//!
//! V1 bundles are deliberately unsigned. V2/v3 bundles require an Ed25519
//! signature from an externally trusted publisher key; v3 also verifies the next key's proof.

mod signature;

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{self, BufReader, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
};

use flate2::{Compression, GzBuilder, bufread::GzDecoder};
use luxury_spec::{
    FORMAT_VERSION, Manifest, PUBLISHER_ROTATION_FORMAT_VERSION, PackagePath,
    SIGNED_FORMAT_VERSION, Sha256Digest, SpecError,
};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use thiserror::Error;

pub use luxury_spec::PublisherKeyId;
pub use signature::{PackageSigningKey, PublisherKeyError, TrustedPublisherKey};
use signature::{
    PublisherRotationError, SIGNATURE_RECORD_LEN, sign_manifest, signature_record_key_id,
    verify_manifest_signature, verify_publisher_rotation,
};

pub const MANIFEST_ENTRY: &str = "META/manifest.toml";
pub const SIGNATURE_ENTRY: &str = "META/signature.ed25519";
pub const OBJECT_PREFIX: &str = "objects/sha256/";

const GZIP_OS_UNKNOWN: u8 = 255;
const REGULAR_FILE_MODE: u32 = 0o644;
const IO_CHUNK_BYTES: usize = 64 * 1024;
const MAX_MANIFEST_BYTES: u64 = 64 * 1024 * 1024;
const REVIEW_FINGERPRINT_DOMAIN: &[u8] = b"luxury.luxpkg.review-fingerprint.v1\0";
static NEVER_CANCELLED: AtomicBool = AtomicBool::new(false);

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum PackageTrust {
    Unsigned,
    TrustedPublisher { key_id: PublisherKeyId },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedPublisherRotation {
    pub from_key_id: PublisherKeyId,
    pub to_key_id: PublisherKeyId,
}

impl std::fmt::Debug for PackageTrust {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unsigned => formatter.write_str("Unsigned"),
            Self::TrustedPublisher { key_id } => formatter
                .debug_struct("TrustedPublisher")
                .field("key_id", &key_id.to_string())
                .finish(),
        }
    }
}

#[derive(Debug, Error)]
pub enum BundleError {
    #[error("operation cancelled")]
    Cancelled,
    #[error(transparent)]
    Spec(#[from] SpecError),
    #[error("bundle I/O failed while {action}: {source}")]
    Io {
        action: &'static str,
        #[source]
        source: io::Error,
    },
    #[error("bundle is missing {} as the first entry", MANIFEST_ENTRY)]
    MissingManifest,
    #[error("manifest must be the first archive entry, found {0}")]
    ManifestNotFirst(String),
    #[error("archive path {0} is not allowed in .luxpkg")]
    InvalidArchivePath(String),
    #[error("archive contains duplicate entry {0}")]
    DuplicateEntry(String),
    #[error("archive contains unexpected entry {0}")]
    ExtraEntry(String),
    #[error("bundle writer requires manifest format {expected}, found {found}")]
    WriterFormatMismatch { expected: u32, found: u32 },
    #[error("unsigned format v1 must not contain {}", SIGNATURE_ENTRY)]
    SignatureForbidden,
    #[error("signed format v2/v3 is missing {}", SIGNATURE_ENTRY)]
    MissingSignature,
    #[error("signature must be the second archive entry, found {0}")]
    SignatureNotSecond(String),
    #[error("signature record has {found} bytes; expected {expected}")]
    MalformedSignature { expected: usize, found: u64 },
    #[error("package signature is invalid")]
    InvalidSignature,
    #[error("publisher rotation contains an invalid Ed25519 public key")]
    InvalidPublisherRotationKey,
    #[error("publisher rotation must use a different next key")]
    PublisherRotationToSameKey,
    #[error("publisher rotation proof is invalid")]
    InvalidPublisherRotationProof,
    #[error("publisher key {key_id} is not trusted")]
    UntrustedPublisher { key_id: String },
    #[error("archive entry {path} has forbidden type {entry_type:?}")]
    ForbiddenEntryType {
        path: String,
        entry_type: tar::EntryType,
    },
    #[error("manifest maps digest {digest} to conflicting file sizes")]
    ConflictingDigestSize { digest: String },
    #[error("source root {path} is not a real directory")]
    SourceRootNotDirectory { path: PathBuf },
    #[error("source path {path} contains a symbolic link or reparse point")]
    SourcePathLink { path: PathBuf },
    #[error("source path component {path} is not a directory")]
    SourceParentNotDirectory { path: PathBuf },
    #[error("source path {path} escapes payload root {root}")]
    SourceEscapesRoot { path: PathBuf, root: PathBuf },
    #[error("source file {path} is not a regular file")]
    SourceNotRegular { path: PathBuf },
    #[error("source file {path} has {found} bytes; manifest requires {expected}")]
    SourceSizeMismatch {
        path: PathBuf,
        expected: u64,
        found: u64,
    },
    #[error("source file {path} has SHA-256 {found}; manifest requires {expected}")]
    SourceHashMismatch {
        path: PathBuf,
        expected: String,
        found: String,
    },
    #[error("object {digest} is missing from archive")]
    MissingObject { digest: String },
    #[error("object {digest} has {found} bytes; manifest requires {expected}")]
    ObjectSizeMismatch {
        digest: String,
        expected: u64,
        found: u64,
    },
    #[error("object {digest} hashed as {found}")]
    ObjectHashMismatch { digest: String, found: String },
    #[error("manifest is too large: {found} bytes; limit is {limit}")]
    ManifestTooLarge { found: u64, limit: u64 },
    #[error("manifest entry declared {expected} bytes but contained {found}")]
    ManifestSizeMismatch { expected: u64, found: u64 },
    #[error("tar footer is not the canonical two zero blocks")]
    InvalidTarFooter,
    #[error("bundle contains bytes after the gzip member")]
    TrailingData,
    #[error("payload byte count overflowed u64")]
    PayloadSizeOverflow,
    #[error("payload path {0} is not in the manifest")]
    UnknownPayloadPath(String),
}

pub type Result<T> = std::result::Result<T, BundleError>;

pub struct Bundle {
    manifest: Manifest,
    objects: TempDir,
    trust: PackageTrust,
    publisher_rotation: Option<VerifiedPublisherRotation>,
    review_fingerprint: String,
}

impl Bundle {
    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }

    pub const fn trust(&self) -> PackageTrust {
        self.trust
    }

    pub const fn publisher_rotation(&self) -> Option<VerifiedPublisherRotation> {
        self.publisher_rotation
    }

    pub fn review_fingerprint(&self) -> &str {
        &self.review_fingerprint
    }

    pub fn open_file(&self, path: &PackagePath) -> Result<File> {
        let file = self
            .manifest
            .files
            .iter()
            .find(|file| file.path == *path)
            .ok_or_else(|| BundleError::UnknownPayloadPath(path.to_string()))?;

        File::open(self.object_path(&file.sha256)).map_err(|source| BundleError::Io {
            action: "opening verified bundle object",
            source,
        })
    }

    fn object_path(&self, digest: &Sha256Digest) -> PathBuf {
        self.objects.path().join(digest.as_str())
    }
}

pub fn create_unsigned_bundle<W: Write>(
    writer: W,
    payload_root: impl AsRef<Path>,
    manifest: &Manifest,
) -> Result<()> {
    create_unsigned_bundle_cancellable(writer, payload_root, manifest, &NEVER_CANCELLED)
}

pub fn create_unsigned_bundle_cancellable<W: Write>(
    writer: W,
    payload_root: impl AsRef<Path>,
    manifest: &Manifest,
    cancelled: &AtomicBool,
) -> Result<()> {
    if manifest.format_version != FORMAT_VERSION {
        return Err(BundleError::WriterFormatMismatch {
            expected: FORMAT_VERSION,
            found: manifest.format_version,
        });
    }
    create_bundle(writer, payload_root.as_ref(), manifest, None, cancelled)
}

pub fn create_signed_bundle<W: Write>(
    writer: W,
    payload_root: impl AsRef<Path>,
    manifest: &Manifest,
    signing_key: &PackageSigningKey,
) -> Result<()> {
    if !matches!(
        manifest.format_version,
        SIGNED_FORMAT_VERSION | PUBLISHER_ROTATION_FORMAT_VERSION
    ) {
        return Err(BundleError::WriterFormatMismatch {
            expected: SIGNED_FORMAT_VERSION,
            found: manifest.format_version,
        });
    }
    create_bundle(
        writer,
        payload_root.as_ref(),
        manifest,
        Some(signing_key),
        &NEVER_CANCELLED,
    )
}

fn create_bundle<W: Write>(
    writer: W,
    payload_root: &Path,
    manifest: &Manifest,
    signing_key: Option<&PackageSigningKey>,
    cancelled: &AtomicBool,
) -> Result<()> {
    check_cancelled(cancelled)?;
    let manifest = canonical_manifest(manifest)?;
    if let Some(signing_key) = signing_key {
        verify_manifest_rotation(&manifest, signing_key.key_id())?;
    }
    let manifest_toml = manifest.to_toml()?;
    check_cancelled(cancelled)?;
    if manifest_toml.len() as u64 > MAX_MANIFEST_BYTES {
        return Err(BundleError::ManifestTooLarge {
            found: manifest_toml.len() as u64,
            limit: MAX_MANIFEST_BYTES,
        });
    }
    let mut objects = verify_payload_objects(payload_root, &manifest, cancelled)?;
    let gzip = GzBuilder::new()
        .mtime(0)
        .operating_system(GZIP_OS_UNKNOWN)
        .write(writer, Compression::default());
    let mut archive = tar::Builder::new(gzip);

    append_regular(
        &mut archive,
        MANIFEST_ENTRY,
        manifest_toml.len() as u64,
        manifest_toml.as_bytes(),
        cancelled,
    )?;
    if let Some(signing_key) = signing_key {
        let signature = sign_manifest(signing_key, manifest_toml.as_bytes());
        append_regular(
            &mut archive,
            SIGNATURE_ENTRY,
            signature.len() as u64,
            signature.as_slice(),
            cancelled,
        )?;
    }

    for (digest, object) in &mut objects {
        object
            .file
            .seek(SeekFrom::Start(0))
            .map_err(|source| BundleError::Io {
                action: "rewinding verified source payload",
                source,
            })?;
        append_regular(
            &mut archive,
            &format!("{OBJECT_PREFIX}{digest}"),
            object.size,
            &mut object.file,
            cancelled,
        )?;
    }

    check_cancelled(cancelled)?;
    archive.finish().map_err(|source| BundleError::Io {
        action: "finishing tar archive",
        source,
    })?;
    check_cancelled(cancelled)?;
    archive
        .into_inner()
        .and_then(|gzip| gzip.finish())
        .map_err(|source| BundleError::Io {
            action: "finishing gzip stream",
            source,
        })?;
    check_cancelled(cancelled)?;

    Ok(())
}

pub fn open_bundle<R: Read>(
    reader: R,
    trusted_key: Option<&TrustedPublisherKey>,
) -> Result<Bundle> {
    open_bundle_cancellable(reader, trusted_key, &NEVER_CANCELLED)
}

pub fn open_bundle_cancellable<R: Read>(
    reader: R,
    trusted_key: Option<&TrustedPublisherKey>,
    cancelled: &AtomicBool,
) -> Result<Bundle> {
    check_cancelled(cancelled)?;
    let result = open_bundle_inner(reader, trusted_key, cancelled);
    if cancelled.load(Ordering::Relaxed) {
        Err(BundleError::Cancelled)
    } else {
        result
    }
}

fn open_bundle_inner<R: Read>(
    reader: R,
    trusted_key: Option<&TrustedPublisherKey>,
    cancelled: &AtomicBool,
) -> Result<Bundle> {
    let reader = CancellableReader {
        inner: reader,
        cancelled,
    };
    let gzip = GzDecoder::new(BufReader::new(reader));
    let mut archive = tar::Archive::new(gzip);
    check_cancelled(cancelled)?;
    let mut entries = archive
        .entries()
        .map_err(|source| BundleError::Io {
            action: "reading tar entries",
            source,
        })?
        .raw(true);

    check_cancelled(cancelled)?;
    let mut first = entries
        .next()
        .transpose()
        .map_err(|source| BundleError::Io {
            action: "reading first tar entry",
            source,
        })?
        .ok_or(BundleError::MissingManifest)?;
    check_cancelled(cancelled)?;

    let first_path = entry_path(&first)?;
    if first_path != MANIFEST_ENTRY {
        return Err(BundleError::ManifestNotFirst(first_path));
    }
    require_regular(&first, &first_path)?;

    let (manifest, exact_manifest_bytes) = read_manifest(&mut first, cancelled)?;
    let (trust, publisher_rotation) = match manifest.format_version {
        FORMAT_VERSION => (PackageTrust::Unsigned, None),
        SIGNED_FORMAT_VERSION | PUBLISHER_ROTATION_FORMAT_VERSION => {
            check_cancelled(cancelled)?;
            let mut signature_entry = entries
                .next()
                .transpose()
                .map_err(|source| BundleError::Io {
                    action: "reading signature entry",
                    source,
                })?
                .ok_or(BundleError::MissingSignature)?;
            check_cancelled(cancelled)?;
            let path = entry_path(&signature_entry)?;
            if path != SIGNATURE_ENTRY {
                return Err(BundleError::SignatureNotSecond(path));
            }
            require_regular(&signature_entry, &path)?;
            let signature = read_signature(&mut signature_entry, cancelled)?;
            check_cancelled(cancelled)?;
            let key_id = signature_record_key_id(&signature);
            let Some(trusted_key) = trusted_key else {
                return Err(BundleError::UntrustedPublisher {
                    key_id: key_id.to_string(),
                });
            };
            if key_id != trusted_key.key_id() {
                return Err(BundleError::UntrustedPublisher {
                    key_id: key_id.to_string(),
                });
            }
            check_cancelled(cancelled)?;
            let valid = verify_manifest_signature(trusted_key, &exact_manifest_bytes, &signature);
            check_cancelled(cancelled)?;
            if !valid {
                return Err(BundleError::InvalidSignature);
            }
            let publisher_rotation = verify_manifest_rotation(&manifest, key_id)?;
            (
                PackageTrust::TrustedPublisher { key_id },
                publisher_rotation,
            )
        }
        _ => unreachable!("validated manifest format"),
    };
    check_cancelled(cancelled)?;
    let review_fingerprint = review_fingerprint(&exact_manifest_bytes, trust);
    let expected = expected_objects(&manifest)?;
    check_cancelled(cancelled)?;
    let objects = TempDir::new().map_err(|source| BundleError::Io {
        action: "creating verified object store",
        source,
    })?;
    let mut seen = BTreeSet::new();

    for entry in entries.by_ref() {
        check_cancelled(cancelled)?;
        let mut entry = entry.map_err(|source| BundleError::Io {
            action: "reading tar entry",
            source,
        })?;
        check_cancelled(cancelled)?;
        let path = entry_path(&entry)?;

        if path == MANIFEST_ENTRY {
            return Err(BundleError::DuplicateEntry(path));
        }
        if path == SIGNATURE_ENTRY {
            return if trust == PackageTrust::Unsigned {
                Err(BundleError::SignatureForbidden)
            } else {
                Err(BundleError::DuplicateEntry(path))
            };
        }

        let digest = object_digest_from_entry(&path)?;
        let Some(expected_size) = expected.get(digest.as_str()).copied() else {
            return Err(BundleError::ExtraEntry(path));
        };

        require_regular(&entry, &path)?;
        if !seen.insert(digest.to_string()) {
            return Err(BundleError::DuplicateEntry(path));
        }
        if entry.size() != expected_size {
            return Err(BundleError::ObjectSizeMismatch {
                digest: digest.to_string(),
                expected: expected_size,
                found: entry.size(),
            });
        }

        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(objects.path().join(digest.as_str()))
            .map_err(|source| BundleError::Io {
                action: "creating verified object file",
                source,
            })?;
        check_cancelled(cancelled)?;
        let (found_size, found_hash) = copy_and_hash(&mut entry, Some(&mut output), cancelled)?;
        if found_size != expected_size {
            return Err(BundleError::ObjectSizeMismatch {
                digest: digest.to_string(),
                expected: expected_size,
                found: found_size,
            });
        }
        if found_hash != digest.as_str() {
            return Err(BundleError::ObjectHashMismatch {
                digest: digest.to_string(),
                found: found_hash,
            });
        }
    }

    check_cancelled(cancelled)?;
    for digest in expected.keys() {
        check_cancelled(cancelled)?;
        if !seen.contains(digest) {
            return Err(BundleError::MissingObject {
                digest: digest.clone(),
            });
        }
    }

    validate_archive_end(archive, cancelled)?;
    check_cancelled(cancelled)?;

    Ok(Bundle {
        manifest,
        objects,
        trust,
        publisher_rotation,
        review_fingerprint,
    })
}

fn verify_manifest_rotation(
    manifest: &Manifest,
    current_key_id: PublisherKeyId,
) -> Result<Option<VerifiedPublisherRotation>> {
    let Some(rotation) = manifest.publisher_rotation.as_ref() else {
        return Ok(None);
    };
    let to_key_id = verify_publisher_rotation(
        &manifest.package.id,
        &manifest.package.version,
        current_key_id,
        rotation,
    )
    .map_err(|error| match error {
        PublisherRotationError::InvalidPublicKey => BundleError::InvalidPublisherRotationKey,
        PublisherRotationError::SameKey => BundleError::PublisherRotationToSameKey,
        PublisherRotationError::ContextTooLong => BundleError::InvalidPublisherRotationProof,
        PublisherRotationError::InvalidProof => BundleError::InvalidPublisherRotationProof,
    })?;
    Ok(Some(VerifiedPublisherRotation {
        from_key_id: current_key_id,
        to_key_id,
    }))
}

pub fn open_bundle_file(
    path: impl AsRef<Path>,
    trusted_key: Option<&TrustedPublisherKey>,
) -> Result<Bundle> {
    open_bundle_file_cancellable(path, trusted_key, &NEVER_CANCELLED)
}

pub fn open_bundle_file_cancellable(
    path: impl AsRef<Path>,
    trusted_key: Option<&TrustedPublisherKey>,
    cancelled: &AtomicBool,
) -> Result<Bundle> {
    check_cancelled(cancelled)?;
    let file = File::open(path.as_ref()).map_err(|source| BundleError::Io {
        action: "opening bundle file",
        source,
    })?;
    check_cancelled(cancelled)?;
    open_bundle_cancellable(file, trusted_key, cancelled)
}

fn canonical_manifest(manifest: &Manifest) -> Result<Manifest> {
    manifest.validate()?;
    let mut manifest = manifest.clone();
    manifest
        .files
        .sort_by(|left, right| left.path.as_str().cmp(right.path.as_str()));
    Ok(manifest)
}

fn expected_objects(manifest: &Manifest) -> Result<BTreeMap<String, u64>> {
    let mut expected = BTreeMap::new();
    for file in &manifest.files {
        match expected.insert(file.sha256.to_string(), file.size) {
            Some(size) if size != file.size => {
                return Err(BundleError::ConflictingDigestSize {
                    digest: file.sha256.to_string(),
                });
            }
            _ => {}
        }
    }
    Ok(expected)
}

struct VerifiedObject {
    size: u64,
    file: File,
}

fn verify_payload_objects(
    root: &Path,
    manifest: &Manifest,
    cancelled: &AtomicBool,
) -> Result<BTreeMap<String, VerifiedObject>> {
    check_cancelled(cancelled)?;
    let root = canonical_payload_root(root)?;
    let expected = expected_objects(manifest)?;
    let mut objects = BTreeMap::new();

    for file in &manifest.files {
        check_cancelled(cancelled)?;
        let source_path = verified_source_path(&root, &file.path)?;
        let metadata = fs::symlink_metadata(&source_path).map_err(|source| BundleError::Io {
            action: "reading source payload metadata",
            source,
        })?;
        if !metadata.file_type().is_file() {
            return Err(BundleError::SourceNotRegular { path: source_path });
        }
        if metadata.len() != file.size {
            return Err(BundleError::SourceSizeMismatch {
                path: source_path,
                expected: file.size,
                found: metadata.len(),
            });
        }

        let mut source = File::open(&source_path).map_err(|source| BundleError::Io {
            action: "opening source payload",
            source,
        })?;
        let opened_metadata = source.metadata().map_err(|source| BundleError::Io {
            action: "reading opened source payload metadata",
            source,
        })?;
        if !opened_metadata.is_file() {
            return Err(BundleError::SourceNotRegular { path: source_path });
        }
        if opened_metadata.len() != file.size {
            return Err(BundleError::SourceSizeMismatch {
                path: source_path,
                expected: file.size,
                found: opened_metadata.len(),
            });
        }
        let mut stored = if objects.contains_key(file.sha256.as_str()) {
            None
        } else {
            Some(tempfile::tempfile().map_err(|source| BundleError::Io {
                action: "creating source payload snapshot",
                source,
            })?)
        };
        let (found_size, found_hash) = copy_and_hash(&mut source, stored.as_mut(), cancelled)?;
        if found_size != file.size {
            return Err(BundleError::SourceSizeMismatch {
                path: source_path,
                expected: file.size,
                found: found_size,
            });
        }
        if found_hash != file.sha256.as_str() {
            return Err(BundleError::SourceHashMismatch {
                path: source_path,
                expected: file.sha256.to_string(),
                found: found_hash,
            });
        }
        if let Some(snapshot) = stored {
            objects.insert(
                file.sha256.to_string(),
                VerifiedObject {
                    size: expected[file.sha256.as_str()],
                    file: snapshot,
                },
            );
        }
    }

    Ok(objects)
}

fn append_regular<W: Write, R: Read>(
    archive: &mut tar::Builder<W>,
    path: &str,
    size: u64,
    data: R,
    cancelled: &AtomicBool,
) -> Result<()> {
    check_cancelled(cancelled)?;
    let mut header = tar::Header::new_ustar();
    let name = &mut header.as_old_mut().name;
    if path.len() > name.len() {
        return Err(BundleError::InvalidArchivePath(path.into()));
    }
    name[..path.len()].copy_from_slice(path.as_bytes());
    header.set_entry_type(tar::EntryType::Regular);
    header.set_size(size);
    header.set_mode(REGULAR_FILE_MODE);
    header.set_uid(0);
    header.set_gid(0);
    header.set_mtime(0);
    header.set_cksum();
    let result = archive.append(
        &header,
        CancellableReader {
            inner: data,
            cancelled,
        },
    );
    if result.is_err() && cancelled.load(Ordering::Relaxed) {
        return Err(BundleError::Cancelled);
    }
    result.map_err(|source| BundleError::Io {
        action: "writing tar entry",
        source,
    })?;
    check_cancelled(cancelled)
}

struct CancellableReader<'a, R> {
    inner: R,
    cancelled: &'a AtomicBool,
}

impl<R: Read> Read for CancellableReader<'_, R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if self.cancelled.load(Ordering::Relaxed) {
            return Err(io::Error::other("operation cancelled"));
        }
        let length = buffer.len().min(IO_CHUNK_BYTES);
        let read = self.inner.read(&mut buffer[..length])?;
        if self.cancelled.load(Ordering::Relaxed) {
            return Err(io::Error::other("operation cancelled"));
        }
        Ok(read)
    }
}

fn read_manifest<R: Read>(
    entry: &mut tar::Entry<'_, R>,
    cancelled: &AtomicBool,
) -> Result<(Manifest, Vec<u8>)> {
    check_cancelled(cancelled)?;
    if entry.size() > MAX_MANIFEST_BYTES {
        return Err(BundleError::ManifestTooLarge {
            found: entry.size(),
            limit: MAX_MANIFEST_BYTES,
        });
    }
    let expected = entry.size();
    let mut bytes = Vec::with_capacity(expected as usize);
    CancellableReader {
        inner: entry,
        cancelled,
    }
    .read_to_end(&mut bytes)
    .map_err(|source| BundleError::Io {
        action: "reading manifest entry",
        source,
    })?;
    check_cancelled(cancelled)?;
    if bytes.len() as u64 != expected {
        return Err(BundleError::ManifestSizeMismatch {
            expected,
            found: bytes.len() as u64,
        });
    }
    let source = std::str::from_utf8(&bytes).map_err(|_| {
        BundleError::Spec(SpecError::InvalidToml("manifest is not valid UTF-8".into()))
    })?;
    let manifest = Manifest::from_toml(source).map_err(BundleError::Spec)?;
    check_cancelled(cancelled)?;
    Ok((manifest, bytes))
}

fn read_signature<R: Read>(
    entry: &mut tar::Entry<'_, R>,
    cancelled: &AtomicBool,
) -> Result<[u8; SIGNATURE_RECORD_LEN]> {
    check_cancelled(cancelled)?;
    if entry.size() != SIGNATURE_RECORD_LEN as u64 {
        return Err(BundleError::MalformedSignature {
            expected: SIGNATURE_RECORD_LEN,
            found: entry.size(),
        });
    }
    let mut signature = [0_u8; SIGNATURE_RECORD_LEN];
    CancellableReader {
        inner: entry,
        cancelled,
    }
    .read_exact(&mut signature)
    .map_err(|source| BundleError::Io {
        action: "reading signature record",
        source,
    })?;
    check_cancelled(cancelled)?;
    Ok(signature)
}

fn review_fingerprint(exact_manifest_bytes: &[u8], trust: PackageTrust) -> String {
    let mut hasher = Sha256::new();
    hasher.update(REVIEW_FINGERPRINT_DOMAIN);
    match trust {
        PackageTrust::Unsigned => hasher.update([0]),
        PackageTrust::TrustedPublisher { key_id } => {
            hasher.update([1]);
            hasher.update(key_id.as_bytes());
        }
    }
    hasher.update(exact_manifest_bytes);
    hex::encode(hasher.finalize())
}

fn entry_path<R: Read>(entry: &tar::Entry<'_, R>) -> Result<String> {
    let header = entry.header();
    if header
        .as_ustar()
        .is_some_and(|ustar| ustar.prefix.iter().any(|byte| *byte != 0))
    {
        return Err(BundleError::InvalidArchivePath(
            "<non-canonical ustar prefix>".into(),
        ));
    }

    let name = &header.as_old().name;
    let end = name
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(name.len());
    if name[end..].iter().any(|byte| *byte != 0) {
        return Err(BundleError::InvalidArchivePath(
            "<embedded NUL in tar path>".into(),
        ));
    }
    let path = String::from_utf8(name[..end].to_vec())
        .map_err(|_| BundleError::InvalidArchivePath("<non-utf8>".into()))?;
    validate_archive_path(&path)?;
    Ok(path)
}

fn validate_archive_path(path: &str) -> Result<()> {
    if path.is_empty()
        || path.starts_with('/')
        || path.contains(['\\', ':', '\0'])
        || path
            .split('/')
            .any(|component| component.is_empty() || component == "." || component == "..")
    {
        return Err(BundleError::InvalidArchivePath(path.into()));
    }
    Ok(())
}

fn object_digest_from_entry(path: &str) -> Result<Sha256Digest> {
    let Some(digest) = path.strip_prefix(OBJECT_PREFIX) else {
        return Err(BundleError::ExtraEntry(path.into()));
    };
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(BundleError::InvalidArchivePath(path.into()));
    }
    Sha256Digest::parse(digest).map_err(|_| BundleError::InvalidArchivePath(path.into()))
}

fn require_regular<R: Read>(entry: &tar::Entry<'_, R>, path: &str) -> Result<()> {
    let entry_type = entry.header().entry_type();
    if entry_type.is_file() {
        Ok(())
    } else {
        Err(BundleError::ForbiddenEntryType {
            path: path.into(),
            entry_type,
        })
    }
}

fn copy_and_hash<R: Read>(
    reader: &mut R,
    mut writer: Option<&mut File>,
    cancelled: &AtomicBool,
) -> Result<(u64, String)> {
    let mut hasher = Sha256::new();
    let mut size = 0_u64;
    let mut buffer = [0_u8; IO_CHUNK_BYTES];

    loop {
        check_cancelled(cancelled)?;
        let read = reader.read(&mut buffer).map_err(|source| BundleError::Io {
            action: "reading payload bytes",
            source,
        })?;
        check_cancelled(cancelled)?;
        if read == 0 {
            break;
        }
        size = size
            .checked_add(read as u64)
            .ok_or(BundleError::PayloadSizeOverflow)?;
        hasher.update(&buffer[..read]);
        if let Some(output) = writer.as_mut() {
            output
                .write_all(&buffer[..read])
                .map_err(|source| BundleError::Io {
                    action: "writing verified payload bytes",
                    source,
                })?;
            check_cancelled(cancelled)?;
        }
    }

    Ok((size, hex::encode(hasher.finalize())))
}

fn check_cancelled(cancelled: &AtomicBool) -> Result<()> {
    if cancelled.load(Ordering::Relaxed) {
        Err(BundleError::Cancelled)
    } else {
        Ok(())
    }
}

fn canonical_payload_root(root: &Path) -> Result<PathBuf> {
    let metadata = fs::symlink_metadata(root).map_err(|source| BundleError::Io {
        action: "reading source root metadata",
        source,
    })?;
    if is_link_or_reparse(&metadata) {
        return Err(BundleError::SourcePathLink {
            path: root.to_path_buf(),
        });
    }
    if !metadata.is_dir() {
        return Err(BundleError::SourceRootNotDirectory {
            path: root.to_path_buf(),
        });
    }

    fs::canonicalize(root).map_err(|source| BundleError::Io {
        action: "canonicalizing source root",
        source,
    })
}

fn verified_source_path(root: &Path, package_path: &PackagePath) -> Result<PathBuf> {
    let mut path = root.to_path_buf();
    let mut components = package_path.as_str().split('/').peekable();

    while let Some(component) = components.next() {
        path.push(component);
        let metadata = fs::symlink_metadata(&path).map_err(|source| BundleError::Io {
            action: "reading source path metadata",
            source,
        })?;
        if is_link_or_reparse(&metadata) {
            return Err(BundleError::SourcePathLink { path });
        }
        if components.peek().is_some() && !metadata.is_dir() {
            return Err(BundleError::SourceParentNotDirectory { path });
        }
    }

    let canonical = fs::canonicalize(&path).map_err(|source| BundleError::Io {
        action: "canonicalizing source payload",
        source,
    })?;
    if !canonical.starts_with(root) {
        return Err(BundleError::SourceEscapesRoot {
            path: canonical,
            root: root.to_path_buf(),
        });
    }
    Ok(canonical)
}

fn is_link_or_reparse(metadata: &fs::Metadata) -> bool {
    if metadata.file_type().is_symlink() {
        return true;
    }

    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;

        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    }

    #[cfg(not(windows))]
    {
        false
    }
}

fn validate_archive_end<R: Read>(
    archive: tar::Archive<GzDecoder<BufReader<R>>>,
    cancelled: &AtomicBool,
) -> Result<()> {
    let mut gzip = archive.into_inner();
    let mut footer = [0_u8; 513];
    let mut length = 0;
    while length < footer.len() {
        check_cancelled(cancelled)?;
        let read = gzip
            .read(&mut footer[length..])
            .map_err(|source| BundleError::Io {
                action: "validating gzip and tar footer",
                source,
            })?;
        check_cancelled(cancelled)?;
        if read == 0 {
            break;
        }
        length += read;
    }
    if length != 512 || footer[..length].iter().any(|byte| *byte != 0) {
        return Err(BundleError::InvalidTarFooter);
    }

    let mut compressed = gzip.into_inner();
    let mut trailing = [0_u8; 1];
    check_cancelled(cancelled)?;
    let trailing = compressed
        .read(&mut trailing)
        .map_err(|source| BundleError::Io {
            action: "checking trailing bundle data",
            source,
        })?;
    check_cancelled(cancelled)?;
    if trailing != 0 {
        return Err(BundleError::TrailingData);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct CancelOnRead<'a> {
        cancelled: &'a AtomicBool,
    }

    impl Read for CancelOnRead<'_> {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            assert!(buffer.len() <= IO_CHUNK_BYTES);
            buffer[0] = 1;
            self.cancelled.store(true, Ordering::Relaxed);
            Ok(1)
        }
    }

    #[test]
    fn cancellable_reader_reports_other_after_in_flight_read() {
        let cancelled = AtomicBool::new(false);
        let mut reader = CancellableReader {
            inner: CancelOnRead {
                cancelled: &cancelled,
            },
            cancelled: &cancelled,
        };

        let mut buffer = vec![0; IO_CHUNK_BYTES * 2];
        assert_eq!(
            reader.read(&mut buffer).unwrap_err().kind(),
            io::ErrorKind::Other
        );
    }

    #[test]
    fn open_bundle_reports_in_flight_cancellation() {
        let cancelled = AtomicBool::new(false);

        assert!(matches!(
            open_bundle_cancellable(
                CancelOnRead {
                    cancelled: &cancelled,
                },
                None,
                &cancelled
            ),
            Err(BundleError::Cancelled)
        ));
    }
}

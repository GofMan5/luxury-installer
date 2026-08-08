use std::{
    fs,
    io::{Cursor, Read, Write},
};

use flate2::{Compression, GzBuilder, read::GzDecoder};
use luxury_bundle::{
    BundleError, MANIFEST_ENTRY, OBJECT_PREFIX, PackageSigningKey, PackageTrust, SIGNATURE_ENTRY,
    TrustedPublisherKey, create_signed_bundle, create_unsigned_bundle, open_bundle,
};
use luxury_spec::{
    Architecture, FORMAT_VERSION, FileEntry, InstallDirectory, InstallPolicy, InstallScope,
    Manifest, OperatingSystem, PUBLISHER_ROTATION_FORMAT_VERSION, Package, PackageId, PackagePath,
    PublisherPublicKey, PublisherRotationProof, SIGNED_FORMAT_VERSION, Sha256Digest, SpecError,
    Target,
};
use semver::Version;
use sha2::{Digest, Sha256};
use tempfile::TempDir;

// Public, deterministic test fixtures. Never use these keys for a real package.
const SIGNING_KEY_PEM: &str = concat!(
    "-----BEGIN PRIVATE ",
    "KEY-----\nMC4CAQAwBQYDK2VwBCIEIJ1hsZ3v/VpguoRK9JLsLMREScVpezJpGXA7rAMcrn9g\n-----END PRIVATE ",
    "KEY-----\n"
);
const TRUSTED_KEY_PEM: &str = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=\n-----END PUBLIC KEY-----\n";
const OTHER_SIGNING_KEY_PEM: &str = concat!(
    "-----BEGIN PRIVATE ",
    "KEY-----\nMC4CAQAwBQYDK2VwBCIEIEzNCJso/5banbbDRuwRTg9bijGfNaumJNqM9u1PuKb7\n-----END PRIVATE ",
    "KEY-----\n"
);
const OTHER_TRUSTED_KEY_PEM: &str = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAPUAXw+hDiVqStwqnTRt+vJyYLM8uxJaMwM1V8Sr0Zgw=\n-----END PUBLIC KEY-----\n";
const THIRD_SIGNING_KEY_PEM: &str = concat!(
    "-----BEGIN PRIVATE ",
    "KEY-----\nMC4CAQAwBQYDK2VwBCIEIBW5i/wotXaE45F6eC3yToB1KPxW8yoTfUszpVQF/LTi\n-----END PRIVATE ",
    "KEY-----\n"
);

fn digest(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::parse(hex::encode(Sha256::digest(bytes))).unwrap()
}

fn manifest(files: Vec<(&str, &[u8])>) -> Manifest {
    Manifest {
        format_version: FORMAT_VERSION,
        schema_version: 1,
        package: Package {
            id: PackageId::parse("dev.luxury.demo").unwrap(),
            name: "Luxury Demo".into(),
            version: Version::new(1, 0, 0),
            publisher: "Luxury Software".into(),
            description: None,
            license: None,
        },
        target: Target {
            os: OperatingSystem::Windows,
            arch: Architecture::X86_64,
        },
        install: InstallPolicy {
            scope: InstallScope::User,
            directory: InstallDirectory::parse("Luxury Demo").unwrap(),
            allow_downgrade: false,
            entrypoint: None,
            show_install_log: false,
            finish_links: Vec::new(),
            shortcuts: luxury_spec::ShortcutPolicy::default(),
        },
        publisher_rotation: None,
        files: files
            .into_iter()
            .map(|(path, bytes)| FileEntry {
                path: PackagePath::parse(path).unwrap(),
                size: bytes.len() as u64,
                sha256: digest(bytes),
                executable: false,
            })
            .collect(),
    }
}

fn signed_manifest(files: Vec<(&str, &[u8])>) -> Manifest {
    let mut manifest = manifest(files);
    manifest.format_version = SIGNED_FORMAT_VERSION;
    manifest
}

fn rotation_manifest(
    files: Vec<(&str, &[u8])>,
    current: &PackageSigningKey,
    next: &PackageSigningKey,
) -> Manifest {
    let mut manifest = manifest(files);
    manifest.format_version = PUBLISHER_ROTATION_FORMAT_VERSION;
    manifest.publisher_rotation = Some(
        next.create_publisher_rotation(
            &manifest.package.id,
            &manifest.package.version,
            current.key_id(),
        )
        .unwrap(),
    );
    manifest
}

fn signing_key() -> PackageSigningKey {
    PackageSigningKey::from_pkcs8_pem(SIGNING_KEY_PEM).unwrap()
}

fn trusted_key() -> TrustedPublisherKey {
    TrustedPublisherKey::from_public_key_pem(TRUSTED_KEY_PEM).unwrap()
}

fn other_signing_key() -> PackageSigningKey {
    PackageSigningKey::from_pkcs8_pem(OTHER_SIGNING_KEY_PEM).unwrap()
}

fn third_signing_key() -> PackageSigningKey {
    PackageSigningKey::from_pkcs8_pem(THIRD_SIGNING_KEY_PEM).unwrap()
}

fn other_trusted_key() -> TrustedPublisherKey {
    TrustedPublisherKey::from_public_key_pem(OTHER_TRUSTED_KEY_PEM).unwrap()
}

fn payload_root(files: &[(&str, &[u8])]) -> TempDir {
    let root = TempDir::new().unwrap();
    for (path, bytes) in files {
        let path = root
            .path()
            .join(path.replace('/', std::path::MAIN_SEPARATOR_STR));
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, bytes).unwrap();
    }
    root
}

fn tar_gz(entries: Vec<(&str, tar::EntryType, Vec<u8>)>) -> Vec<u8> {
    let gzip = GzBuilder::new()
        .mtime(0)
        .operating_system(255)
        .write(Vec::new(), Compression::default());
    let mut archive = tar::Builder::new(gzip);
    for (path, entry_type, bytes) in entries {
        let mut header = tar::Header::new_ustar();
        assert!(path.len() <= header.as_old().name.len());
        header.as_old_mut().name[..path.len()].copy_from_slice(path.as_bytes());
        header.set_entry_type(entry_type);
        header.set_size(bytes.len() as u64);
        header.set_mode(0o644);
        header.set_uid(0);
        header.set_gid(0);
        header.set_mtime(0);
        header.set_cksum();
        archive.append(&header, Cursor::new(bytes)).unwrap();
    }
    archive.finish().unwrap();
    archive.into_inner().unwrap().finish().unwrap()
}

fn object_path(bytes: &[u8]) -> String {
    format!("{OBJECT_PREFIX}{}", digest(bytes))
}

fn archive_paths(bytes: &[u8]) -> Vec<String> {
    let mut archive = tar::Archive::new(GzDecoder::new(Cursor::new(bytes)));
    archive
        .entries()
        .unwrap()
        .raw(true)
        .map(|entry| {
            String::from_utf8(
                entry.unwrap().header().as_old().name[..]
                    .iter()
                    .copied()
                    .take_while(|byte| *byte != 0)
                    .collect(),
            )
            .unwrap()
        })
        .collect()
}

fn archive_entries(bytes: &[u8]) -> Vec<(String, tar::EntryType, Vec<u8>)> {
    let mut archive = tar::Archive::new(GzDecoder::new(Cursor::new(bytes)));
    archive
        .entries()
        .unwrap()
        .raw(true)
        .map(|entry| {
            let mut entry = entry.unwrap();
            let path = String::from_utf8(
                entry.header().as_old().name[..]
                    .iter()
                    .copied()
                    .take_while(|byte| *byte != 0)
                    .collect(),
            )
            .unwrap();
            let entry_type = entry.header().entry_type();
            let mut bytes = Vec::new();
            entry.read_to_end(&mut bytes).unwrap();
            (path, entry_type, bytes)
        })
        .collect()
}

fn rebuild(entries: &[(String, tar::EntryType, Vec<u8>)]) -> Vec<u8> {
    tar_gz(
        entries
            .iter()
            .map(|(path, entry_type, bytes)| (path.as_str(), *entry_type, bytes.clone()))
            .collect(),
    )
}

fn signed_package(files: &[(&str, &[u8])], signing_key: &PackageSigningKey) -> Vec<u8> {
    let root = payload_root(files);
    let manifest = signed_manifest(files.to_vec());
    let mut package = Vec::new();
    create_signed_bundle(&mut package, root.path(), &manifest, signing_key).unwrap();
    package
}

#[test]
fn rejects_oversized_tar_footer_without_reading_the_whole_tail() {
    let files = [("bin/app", b"payload".as_slice())];
    let root = payload_root(&files);
    let mut package = Vec::new();
    create_unsigned_bundle(&mut package, root.path(), &manifest(files.to_vec())).unwrap();

    let mut raw = Vec::new();
    GzDecoder::new(Cursor::new(package))
        .read_to_end(&mut raw)
        .unwrap();
    let mut state = 1_u64;
    for _ in 0..1024 * 1024 {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1);
        raw.push((state >> 32) as u8);
    }

    let mut gzip = GzBuilder::new()
        .mtime(0)
        .operating_system(255)
        .write(Vec::new(), Compression::default());
    gzip.write_all(&raw).unwrap();
    let oversized = gzip.finish().unwrap();
    assert!(oversized.len() > 64 * 1024);
    assert!(matches!(
        open_bundle(Cursor::new(oversized).take(64 * 1024), None),
        Err(BundleError::InvalidTarFooter)
    ));
}

#[test]
fn still_rejects_bad_gzip_checksum_and_trailing_data() {
    let files = [("bin/app", b"payload".as_slice())];
    let root = payload_root(&files);
    let mut package = Vec::new();
    create_unsigned_bundle(&mut package, root.path(), &manifest(files.to_vec())).unwrap();

    let mut bad_checksum = package.clone();
    let checksum = bad_checksum.len() - 8;
    bad_checksum[checksum] ^= 1;
    assert!(matches!(
        open_bundle(Cursor::new(bad_checksum), None),
        Err(BundleError::Io {
            action: "validating gzip and tar footer",
            ..
        })
    ));

    package.push(0);
    assert!(matches!(
        open_bundle(Cursor::new(package), None),
        Err(BundleError::TrailingData)
    ));
}

#[test]
fn writes_deterministic_content_addressed_bundle() {
    let files = [
        ("bin/demo.exe", b"same".as_slice()),
        ("share/readme.txt", b"same".as_slice()),
    ];
    let root = payload_root(&files);
    let manifest = manifest(files.to_vec());

    let mut first = Vec::new();
    let mut second = Vec::new();
    create_unsigned_bundle(&mut first, root.path(), &manifest).unwrap();
    create_unsigned_bundle(&mut second, root.path(), &manifest).unwrap();
    assert_eq!(first, second);
    assert_eq!(
        archive_paths(&first),
        vec![MANIFEST_ENTRY.to_owned(), object_path(b"same")]
    );

    let opened = open_bundle(Cursor::new(first), None).unwrap();
    assert_eq!(opened.trust(), PackageTrust::Unsigned);

    let mut file = opened
        .open_file(&PackagePath::parse("share/readme.txt").unwrap())
        .unwrap();
    let mut contents = String::new();
    file.read_to_string(&mut contents).unwrap();
    assert_eq!(contents, "same");
}

#[test]
fn writes_and_opens_deterministic_trusted_bundle() {
    let files = [("bin/demo.exe", b"signed payload".as_slice())];
    let signing_key = signing_key();
    let first = signed_package(&files, &signing_key);
    let second = signed_package(&files, &signing_key);
    assert_eq!(first, second);
    assert_eq!(
        archive_paths(&first),
        vec![
            MANIFEST_ENTRY.to_owned(),
            SIGNATURE_ENTRY.to_owned(),
            object_path(b"signed payload"),
        ]
    );

    let trusted_key = trusted_key();
    let opened = open_bundle(Cursor::new(first), Some(&trusted_key)).unwrap();
    assert_eq!(opened.publisher_rotation(), None);
    assert_eq!(
        opened.trust(),
        PackageTrust::TrustedPublisher {
            key_id: trusted_key.key_id()
        }
    );
    assert_eq!(opened.review_fingerprint().len(), 64);
    assert!(
        opened
            .review_fingerprint()
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    );

    let other_signing_key = other_signing_key();
    let other_package = signed_package(&files, &other_signing_key);
    let other_trusted_key = other_trusted_key();
    let other = open_bundle(Cursor::new(other_package), Some(&other_trusted_key)).unwrap();
    assert_ne!(opened.review_fingerprint(), other.review_fingerprint());
}

#[test]
fn writes_and_opens_deterministic_rotation_bundle() {
    let files = [("bin/demo.exe", b"rotation payload".as_slice())];
    let root = payload_root(&files);
    let current = signing_key();
    let next = other_signing_key();
    let manifest = rotation_manifest(files.to_vec(), &current, &next);
    let mut first = Vec::new();
    let mut second = Vec::new();
    create_signed_bundle(&mut first, root.path(), &manifest, &current).unwrap();
    create_signed_bundle(&mut second, root.path(), &manifest, &current).unwrap();
    assert_eq!(first, second);

    assert!(matches!(
        open_bundle(Cursor::new(&first), None),
        Err(BundleError::UntrustedPublisher { .. })
    ));
    assert!(matches!(
        open_bundle(Cursor::new(&first), Some(&other_trusted_key())),
        Err(BundleError::UntrustedPublisher { .. })
    ));

    let opened = open_bundle(Cursor::new(first), Some(&trusted_key())).unwrap();
    assert_eq!(opened.manifest(), &manifest);
    assert_eq!(
        opened.publisher_rotation().unwrap(),
        luxury_bundle::VerifiedPublisherRotation {
            from_key_id: current.key_id(),
            to_key_id: next.key_id(),
        }
    );
}

#[test]
fn rotation_review_fingerprint_binds_the_next_key() {
    let files = [("bin/demo.exe", b"rotation payload".as_slice())];
    let root = payload_root(&files);
    let current = signing_key();
    let next_b = other_signing_key();
    let next_c = third_signing_key();

    let mut package_b = Vec::new();
    create_signed_bundle(
        &mut package_b,
        root.path(),
        &rotation_manifest(files.to_vec(), &current, &next_b),
        &current,
    )
    .unwrap();
    let mut package_c = Vec::new();
    create_signed_bundle(
        &mut package_c,
        root.path(),
        &rotation_manifest(files.to_vec(), &current, &next_c),
        &current,
    )
    .unwrap();

    let fingerprint_b = open_bundle(Cursor::new(package_b), Some(&trusted_key()))
        .unwrap()
        .review_fingerprint()
        .to_owned();
    let fingerprint_c = open_bundle(Cursor::new(package_c), Some(&trusted_key()))
        .unwrap()
        .review_fingerprint()
        .to_owned();
    assert_ne!(fingerprint_b, fingerprint_c);
}

#[test]
fn rotation_writer_rejects_missing_tampered_and_wrong_context_proofs() {
    let files = [("bin/demo.exe", b"rotation payload".as_slice())];
    let root = payload_root(&files);
    let current = signing_key();
    let next = other_signing_key();

    let valid = rotation_manifest(files.to_vec(), &current, &next);
    assert!(matches!(
        create_signed_bundle(Vec::new(), root.path(), &valid, &third_signing_key()),
        Err(BundleError::InvalidPublisherRotationProof)
    ));

    let mut missing = manifest(files.to_vec());
    missing.format_version = PUBLISHER_ROTATION_FORMAT_VERSION;
    assert!(matches!(
        create_signed_bundle(Vec::new(), root.path(), &missing, &current),
        Err(BundleError::Spec(SpecError::PublisherRotationRequired))
    ));

    let mut tampered = rotation_manifest(files.to_vec(), &current, &next);
    let rotation = tampered.publisher_rotation.as_mut().unwrap();
    let mut proof = *rotation.proof.as_bytes();
    proof[0] ^= 1;
    rotation.proof = PublisherRotationProof::from_bytes(proof);
    assert!(matches!(
        create_signed_bundle(Vec::new(), root.path(), &tampered, &current),
        Err(BundleError::InvalidPublisherRotationProof)
    ));

    let mut wrong_package = manifest(files.to_vec());
    wrong_package.format_version = PUBLISHER_ROTATION_FORMAT_VERSION;
    wrong_package.publisher_rotation = Some(
        next.create_publisher_rotation(
            &PackageId::parse("dev.luxury.other").unwrap(),
            &wrong_package.package.version,
            current.key_id(),
        )
        .unwrap(),
    );
    assert!(matches!(
        create_signed_bundle(Vec::new(), root.path(), &wrong_package, &current),
        Err(BundleError::InvalidPublisherRotationProof)
    ));

    let mut wrong_version = manifest(files.to_vec());
    wrong_version.format_version = PUBLISHER_ROTATION_FORMAT_VERSION;
    wrong_version.publisher_rotation = Some(
        next.create_publisher_rotation(
            &wrong_version.package.id,
            &Version::new(9, 0, 0),
            current.key_id(),
        )
        .unwrap(),
    );
    assert!(matches!(
        create_signed_bundle(Vec::new(), root.path(), &wrong_version, &current),
        Err(BundleError::InvalidPublisherRotationProof)
    ));

    let mut wrong_key = rotation_manifest(files.to_vec(), &current, &next);
    wrong_key
        .publisher_rotation
        .as_mut()
        .unwrap()
        .next_public_key = PublisherPublicKey::from_bytes([0xff; 32]);
    assert!(matches!(
        create_signed_bundle(Vec::new(), root.path(), &wrong_key, &current),
        Err(BundleError::InvalidPublisherRotationKey | BundleError::InvalidPublisherRotationProof)
    ));

    assert!(matches!(
        current.create_publisher_rotation(
            &wrong_key.package.id,
            &wrong_key.package.version,
            current.key_id(),
        ),
        Err(luxury_bundle::PublisherKeyError::RotationToSameKey)
    ));
}

#[test]
fn signed_bundle_requires_the_matching_external_trust_anchor() {
    let signing_key = signing_key();
    let package = signed_package(&[("bin/app", b"payload")], &signing_key);

    assert!(matches!(
        open_bundle(Cursor::new(&package), None),
        Err(BundleError::UntrustedPublisher { .. })
    ));
    assert!(matches!(
        open_bundle(Cursor::new(package), Some(&other_trusted_key())),
        Err(BundleError::UntrustedPublisher { .. })
    ));
}

#[test]
fn signed_bundle_binds_the_exact_manifest_bytes() {
    let signing_key = signing_key();
    let package = signed_package(&[("bin/app", b"payload")], &signing_key);
    let mut entries = archive_entries(&package);
    entries[0].2.push(b'\n');

    assert!(matches!(
        open_bundle(Cursor::new(rebuild(&entries)), Some(&trusted_key())),
        Err(BundleError::InvalidSignature)
    ));
}

#[test]
fn signed_bundle_rejects_missing_misordered_duplicate_and_malformed_signature() {
    let signing_key = signing_key();
    let package = signed_package(&[("bin/app", b"payload")], &signing_key);
    let entries = archive_entries(&package);

    assert!(matches!(
        open_bundle(Cursor::new(rebuild(&entries[..1])), Some(&trusted_key())),
        Err(BundleError::MissingSignature)
    ));

    let mut misordered = entries.clone();
    misordered.swap(1, 2);
    assert!(matches!(
        open_bundle(Cursor::new(rebuild(&misordered)), Some(&trusted_key())),
        Err(BundleError::SignatureNotSecond(_))
    ));

    let mut duplicate = entries.clone();
    duplicate.insert(2, duplicate[1].clone());
    assert!(matches!(
        open_bundle(Cursor::new(rebuild(&duplicate)), Some(&trusted_key())),
        Err(BundleError::DuplicateEntry(path)) if path == SIGNATURE_ENTRY
    ));

    let mut malformed = entries;
    malformed[1].2.pop();
    assert!(matches!(
        open_bundle(Cursor::new(rebuild(&malformed)), Some(&trusted_key())),
        Err(BundleError::MalformedSignature { .. })
    ));
}

#[test]
fn signature_failures_never_fall_back_to_unsigned() {
    let signing_key = signing_key();
    let package = signed_package(&[("bin/app", b"payload")], &signing_key);
    let mut invalid = archive_entries(&package);
    invalid[1].2[95] ^= 1;
    assert!(matches!(
        open_bundle(Cursor::new(rebuild(&invalid)), Some(&trusted_key())),
        Err(BundleError::InvalidSignature)
    ));

    let mut downgraded = archive_entries(&package);
    let manifest = String::from_utf8(downgraded[0].2.clone())
        .unwrap()
        .replace("format_version = 2", "format_version = 1");
    downgraded[0].2 = manifest.into_bytes();
    assert!(matches!(
        open_bundle(Cursor::new(rebuild(&downgraded)), None),
        Err(BundleError::SignatureForbidden)
    ));
}

#[test]
fn writers_enforce_their_manifest_format() {
    let files = [("bin/app", b"payload".as_slice())];
    let root = payload_root(&files);
    let unsigned = manifest(files.to_vec());
    let signed = signed_manifest(files.to_vec());

    assert!(matches!(
        create_unsigned_bundle(Vec::new(), root.path(), &signed),
        Err(BundleError::WriterFormatMismatch { .. })
    ));
    assert!(matches!(
        create_signed_bundle(Vec::new(), root.path(), &unsigned, &signing_key()),
        Err(BundleError::WriterFormatMismatch { .. })
    ));
}

#[test]
fn rejects_object_before_manifest() {
    let bytes = b"payload";
    let path = object_path(bytes);
    let archive = tar_gz(vec![(
        path.as_str(),
        tar::EntryType::Regular,
        bytes.to_vec(),
    )]);
    assert!(matches!(
        open_bundle(Cursor::new(archive), None),
        Err(BundleError::ManifestNotFirst(_))
    ));
}

#[test]
fn rejects_extra_duplicate_missing_and_traversal_entries() {
    let bytes = b"payload";
    let manifest = manifest(vec![("bin/app", bytes)]);
    let manifest_toml = manifest.to_toml().unwrap().into_bytes();
    let object = object_path(bytes);

    let extra = tar_gz(vec![
        (
            MANIFEST_ENTRY,
            tar::EntryType::Regular,
            manifest_toml.clone(),
        ),
        (object.as_str(), tar::EntryType::Regular, bytes.to_vec()),
        (
            "objects/sha256/../escape",
            tar::EntryType::Regular,
            b"x".to_vec(),
        ),
    ]);
    assert!(matches!(
        open_bundle(Cursor::new(extra), None),
        Err(BundleError::InvalidArchivePath(_))
    ));

    let uppercase_digest = format!(
        "{OBJECT_PREFIX}{}",
        digest(bytes).to_string().to_ascii_uppercase()
    );
    let uppercase = tar_gz(vec![
        (
            MANIFEST_ENTRY,
            tar::EntryType::Regular,
            manifest_toml.clone(),
        ),
        (
            uppercase_digest.as_str(),
            tar::EntryType::Regular,
            bytes.to_vec(),
        ),
    ]);
    assert!(matches!(
        open_bundle(Cursor::new(uppercase), None),
        Err(BundleError::InvalidArchivePath(_))
    ));

    let unrelated = tar_gz(vec![
        (
            MANIFEST_ENTRY,
            tar::EntryType::Regular,
            manifest_toml.clone(),
        ),
        (object.as_str(), tar::EntryType::Regular, bytes.to_vec()),
        ("META/extra", tar::EntryType::Regular, Vec::new()),
    ]);
    assert!(matches!(
        open_bundle(Cursor::new(unrelated), None),
        Err(BundleError::ExtraEntry(_))
    ));

    let duplicate = tar_gz(vec![
        (
            MANIFEST_ENTRY,
            tar::EntryType::Regular,
            manifest_toml.clone(),
        ),
        (object.as_str(), tar::EntryType::Regular, bytes.to_vec()),
        (object.as_str(), tar::EntryType::Regular, bytes.to_vec()),
    ]);
    assert!(matches!(
        open_bundle(Cursor::new(duplicate), None),
        Err(BundleError::DuplicateEntry(_))
    ));

    let missing = tar_gz(vec![(
        MANIFEST_ENTRY,
        tar::EntryType::Regular,
        manifest_toml,
    )]);
    assert!(matches!(
        open_bundle(Cursor::new(missing), None),
        Err(BundleError::MissingObject { .. })
    ));
}

#[test]
fn rejects_links_special_entries_size_and_hash_mismatch() {
    let bytes = b"payload";
    let manifest = manifest(vec![("bin/app", bytes)]);
    let manifest_toml = manifest.to_toml().unwrap().into_bytes();
    let object = object_path(bytes);

    for entry_type in [
        tar::EntryType::Symlink,
        tar::EntryType::Link,
        tar::EntryType::Directory,
        tar::EntryType::Fifo,
    ] {
        let archive = tar_gz(vec![
            (
                MANIFEST_ENTRY,
                tar::EntryType::Regular,
                manifest_toml.clone(),
            ),
            (object.as_str(), entry_type, Vec::new()),
        ]);
        assert!(matches!(
            open_bundle(Cursor::new(archive), None),
            Err(BundleError::ForbiddenEntryType { .. })
        ));
    }

    let size_mismatch = tar_gz(vec![
        (
            MANIFEST_ENTRY,
            tar::EntryType::Regular,
            manifest_toml.clone(),
        ),
        (
            object.as_str(),
            tar::EntryType::Regular,
            b"payload!".to_vec(),
        ),
    ]);
    assert!(matches!(
        open_bundle(Cursor::new(size_mismatch), None),
        Err(BundleError::ObjectSizeMismatch { .. })
    ));

    let same_size_wrong_hash = tar_gz(vec![
        (MANIFEST_ENTRY, tar::EntryType::Regular, manifest_toml),
        (
            object.as_str(),
            tar::EntryType::Regular,
            b"payloae".to_vec(),
        ),
    ]);
    assert!(matches!(
        open_bundle(Cursor::new(same_size_wrong_hash), None),
        Err(BundleError::ObjectHashMismatch { .. })
    ));
}

#[test]
fn writer_rejects_source_mismatch() {
    let files = [("bin/app", b"payload".as_slice())];
    let root = payload_root(&files);
    let mut manifest = manifest(files.to_vec());
    manifest.files[0].sha256 = digest(b"otherxx");

    assert!(matches!(
        create_unsigned_bundle(Vec::new(), root.path(), &manifest),
        Err(BundleError::SourceHashMismatch { .. })
    ));

    let fake_root = root.path().join("not-a-directory");
    fs::write(&fake_root, b"x").unwrap();
    assert!(matches!(
        create_unsigned_bundle(Vec::new(), &fake_root, &manifest),
        Err(BundleError::SourceRootNotDirectory { .. })
    ));
}

#[cfg(unix)]
#[test]
fn writer_rejects_symlinked_parent() {
    use std::os::unix::fs::symlink;

    let root = TempDir::new().unwrap();
    let outside = TempDir::new().unwrap();
    fs::write(outside.path().join("app"), b"payload").unwrap();
    symlink(outside.path(), root.path().join("bin")).unwrap();
    let manifest = manifest(vec![("bin/app", b"payload")]);

    assert!(matches!(
        create_unsigned_bundle(Vec::new(), root.path(), &manifest),
        Err(BundleError::SourcePathLink { .. })
    ));
}

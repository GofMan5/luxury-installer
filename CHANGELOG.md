# Changelog

All notable changes to Luxury Installer are documented here. The project follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and intends to use semantic versioning once release artifacts are production-ready.

## [Unreleased]

### Added

- Rust-first `.luxpkg` compiler, verifier, transactional installer, repair, uninstall, rollback/recovery, receipts, and explicit receipt-owned launch.
- Tauri 2 Studio and bound-payload Setup for Windows, Linux, and macOS development workflows.
- Publisher-authenticated v2 packages, v3 key rotation, and schema-v3 plain-text license consent.
- Optional completed-install details and bounded HTTPS finish links controlled by `luxury.toml`.
- Host-native assembly, focused CI gates, and independent Windows/Linux/macOS verification commands.
- Studio form authoring, native no-overwrite file/folder import, and validated payload entrypoint selection.
- Staged whole-payload replacement from a native folder picker, with rollback and stale-entrypoint cleanup for repeat release builds.
- A pathless Studio action that reveals the last verified native build output.
- Authenticated package descriptions now appear in Setup instead of being authorable but invisible.
- Safe per-command CLI help plus strict JSONL v3, a validated public AI skill, and a complete CLI/protocol reference.
- One native project build command that publishes Windows `.exe`, Linux `.deb` + `.rpm`, or macOS `.dmg` while keeping the package handoff internal.
- A bounded recent-project list that revalidates projects before reopening them.
- Strict windowless install/uninstall on the final bound Setup, with explicit consent flags, idempotent removal, and stable exit codes for deployment tools.

### Changed

- Desktop windows choose a DPI-aware fixed size from the monitor work area and no longer expose resize or maximize controls.
- The completion screen separates optional links from the clear `Запустить` and `Готово` actions.
- Downloaded newer packages keep one receipt-bound install/update/repair flow, and Tauri now rejects a terminal action that disagrees with the prepared plan.
- Released Studio bundles carry a payload-free Setup template and Rust packager; Windows uses bundled SHA-256-pinned NSIS, while Linux writes and independently parses `.deb`/RPM in Rust without a source checkout or system packaging CLI.
- Portable package paths now enforce the common 255-byte component ceiling, and Tauri reuses the same Rust validators instead of maintaining looser copies.
- GitHub Actions are pinned to current Node 24 releases so hosted CI no longer depends on forced execution of deprecated Node 20 actions.

### Fixed

- Standalone Rust RPM generation now records and verifies publisher provenance through the serialized `Vendor` field instead of the broken `rpm 0.16` `Packager` setter.
- macOS lifecycle cleanup reaps a confirmed exited process-group leader before retrying Darwin's zombie-only `EPERM`, while timeout and live-descendant containment remain fail-closed.
- Windows uninstall crash QA now triggers directly from the first rollback-backup filesystem transition instead of racing a delayed coalesced progress frame with full live-state hashing.
- Headless Linux native verification disables only the unavailable AT-SPI bridge so strict packaged-runner stderr checks are not tripped by the hosted image's missing accessibility D-Bus service.
- The packaged Linux Studio native-build smoke now supplies Xvfb while keeping Cargo, rustc, and pnpm unavailable to the standalone packager.
- Debian verification accepts both current numeric-root/no-prefix and legacy named-root/`./` `dpkg-deb --contents` output while preserving exact paths with spaces.

### Security

- Strict portable-path, archive, JSONL, Tauri invoke/event, receipt, journal, and privileged-helper boundaries.
- Tauri's independent Linux `.deb`/RPM bundler receives the exact reviewed package fingerprint from `xtask`; its rebuilt Setup launcher must remain byte-identical to the verified bound launcher.
- Read-only destination permission and capacity preflight before installation starts.
- Versioned private user state rejects legacy broad ACL/modes without rewriting or trusting old receipts and journals.
- Core manifest validation bounds optional package descriptions instead of relying on Studio-only checks.

> No production release has been published yet. See the blockers in [README.md](README.md#security-model).

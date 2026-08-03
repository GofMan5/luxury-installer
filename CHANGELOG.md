# Changelog

All notable changes to Luxury Installer are documented here. The project follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and intends to use semantic versioning once release artifacts are production-ready.

## [Unreleased]

### Added

- Rust-first `.luxpkg` compiler, verifier, transactional installer, repair, uninstall, rollback/recovery, receipts, and explicit receipt-owned launch.
- Tauri 2 Studio and bound-payload Setup for Windows, Linux, and macOS development workflows.
- Publisher-authenticated v2 packages, v3 key rotation, and schema-v3 plain-text license consent.
- Optional completed-install details and bounded HTTPS finish links controlled by `luxury.toml`.
- Host-native assembly, focused CI gates, and independent Windows/Linux/macOS verification commands.

### Changed

- Desktop windows choose a DPI-aware fixed size from the monitor work area and no longer expose resize or maximize controls.
- The completion screen separates optional links from the clear `Запустить` and `Готово` actions.

### Security

- Strict portable-path, archive, JSONL, Tauri invoke/event, receipt, journal, and privileged-helper boundaries.
- Read-only destination permission and capacity preflight before installation starts.
- Versioned private user state rejects legacy broad ACL/modes without rewriting or trusting old receipts and journals.

> No production release has been published yet. See the blockers in [README.md](README.md#security-model).

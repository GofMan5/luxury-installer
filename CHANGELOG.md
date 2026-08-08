# Changelog

All notable changes to Luxury Installer are documented here. The project follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and intends to use semantic versioning once release artifacts are production-ready.

## [Unreleased]

### Added

- An evidence-based master roadmap from preview to signed 1.0 production: competitor matrix, best-in-class metrics, product workstreams, version milestones, exact vertical-slice queue, performance budgets, release scorecard, typed shortcuts/associations/components/prerequisites/updater priorities, and deliberate exclusion of arbitrary package scripts.
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
- Read-only `--info-json` on the bound Setup for one-line AI/MDM inventory without a window, install preparation, native paths, or system authorization.
- Pathless **Show in folder** on the completed Setup screen for both user and system installations; system paths come only from shared fixed Rust roots.
- A visible Studio **Cancel** action for native builds; cancellation returns to the validated project after Rust reaps the complete process tree and cleans temporary build files.
- A monotonic elapsed-time clock on the Studio build surface, including hour-long builds, without announcing every second to assistive technology.
- One-click Studio save-and-build: a valid dirty form is saved and revalidated by Rust before the pathless native build starts.
- Human-readable native output suggestions derived from the validated application name, with bounded cross-platform sanitization and package-ID fallback.
- A manual **Native project build** workflow that builds repository-owned Windows x64, Linux x64, and macOS ARM64 projects in parallel and uploads Rust-generated `SHA256SUMS.txt` with each unsigned development artifact.
- Rust-owned Studio host detection that disables impossible local target builds before opening a dialog and points users to the matching runner or Native project build workflow.

### Changed

- Opt-in installation details can be expanded while files are being applied and remain available on the completed step; the panel still exposes only bounded authenticated relative paths and factual counters.
- Desktop windows choose a DPI-aware fixed size from the monitor work area and no longer expose resize or maximize controls.
- The completion screen separates optional links from the clear `Запустить` and `Готово` actions.
- Downloaded newer packages keep one receipt-bound install/update/repair flow, and Tauri now rejects a terminal action that disagrees with the prepared plan.
- Released Studio bundles carry a payload-free Setup template and Rust packager; Windows uses bundled SHA-256-pinned NSIS, while Linux writes and independently parses `.deb`/RPM in Rust without a source checkout or system packaging CLI.
- Portable package paths now enforce the common 255-byte component ceiling, and Tauri reuses the same Rust validators instead of maintaining looser copies.
- GitHub Actions are pinned to current Node 24 releases so hosted CI no longer depends on forced execution of deprecated Node 20 actions.
- Manual lifecycle CI can run one selected Linux, Windows, or macOS native lane; the default all-host mode remains the only one that merges the complete evidence set.

### Fixed

- A failed **Launch** action no longer discards the successful Setup result for a generic rebootstrap. It stays inline and retryable; after a successful launch, a separate close failure hides **Launch** and leaves **Done** available instead of starting a second application instance.
- Setup no longer hides an unconfirmed cancellation request: install and uninstall keep running, show the bounded public error inline, and restore a retryable **Cancel** action instead of pretending cancellation started.
- Unsaved Studio settings now block project switching and reload, can be explicitly undone to the last validated baseline, and require a Rust-owned discard confirmation on close or Alt+F4.
- Studio owns the exact native-build work directory and removes it after descendant reaping, including cancellation, timeout, and failure, instead of leaving a hidden partial assembly tree beside the selected output.
- Studio native-build cancellation, timeout, and primary exit now contain and reap the complete Cargo/NSIS/Tauri descendant tree through a shared Rust Job Object/process-group adapter instead of killing only the packager PID.
- Independent Tauri `.deb`/RPM verification now derives the exact launcher hash after the pinned bundler's single `UNK -> DEB/RPM` bundle-type marker patch instead of incorrectly requiring the unpatched source hash.
- RPM cross-checking accepts the observed `rpm2cpio 4.18` empty-stderr exit `1` only when `cpio` completed successfully; exact paths, modes, ownership, and SHA-256 verification still run afterward.
- Standalone Rust RPM generation now records and verifies publisher provenance through the serialized `Vendor` field instead of the broken `rpm 0.16` `Packager` setter.
- macOS lifecycle cleanup reaps a confirmed exited process-group leader before retrying Darwin's zombie-only `EPERM`, while timeout and live-descendant containment remain fail-closed.
- Windows uninstall crash QA now triggers directly from the first rollback-backup filesystem transition instead of racing a delayed coalesced progress frame with full live-state hashing.
- Headless Linux native verification disables only the unavailable AT-SPI bridge so strict packaged-runner stderr checks are not tripped by the hosted image's missing accessibility D-Bus service.
- The packaged Linux Studio native-build smoke now supplies Xvfb while keeping Cargo, rustc, and pnpm unavailable to the standalone packager.
- Debian verification accepts both current numeric-root/no-prefix and legacy named-root/`./` `dpkg-deb --contents` output while preserving exact paths with spaces.

### Security

- Linux receipt-owned launch now executes the exact descriptor that passed receipt hash/mode/link checks. User and post-credential-drop system launch use its kernel-owned `/proc/self/fd/N` name with no original-path fallback, so replacing the entrypoint name after verification cannot select attacker bytes; macOS launch and remaining parent/mapped-writer races stay documented.
- Strict portable-path, archive, JSONL, Tauri invoke/event, receipt, journal, and privileged-helper boundaries.
- Tauri's independent Linux `.deb`/RPM bundler receives only the isolated verified launcher and no build-binding or signing credentials; Rust accepts only its pinned, single fixed-width bundle-type marker patch and verifies every other launcher byte through the independently derived container hash.
- Read-only destination permission and capacity preflight before installation starts.
- Versioned private user state rejects legacy broad ACL/modes without rewriting or trusting old receipts and journals.
- Core manifest validation bounds optional package descriptions instead of relying on Studio-only checks.
- macOS launch now keeps the verified no-follow install root as cwd through direct user spawn and post-credential-drop `launchctl asuser`; executable pathname replacement remains an explicit ceiling.
- Successful system install/uninstall now returns a fresh privileged `prepare_system_install` state in the same terminal frame and exposes that authoritative review to the renderer, so Setup no longer fabricates post-operation Install/Repair state or triggers a second elevation prompt.

> No production release has been published yet. See the blockers in [README.md](README.md#security-model).

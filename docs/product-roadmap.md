# Product roadmap: from secure core to a complete installer

Luxury Installer already has the hard part that many script-first installers bolt on later: verified packages, transactional mutation, recovery, ownership receipts, strict unattended operation, native artifacts, and one Studio/CLI contract. The next stage is not to clone every Inno Setup or NSIS directive. It is to add the common product capabilities people actually need while keeping each OS mutation typed, reversible, and visible in Studio.

This roadmap compares the current checkout with the documented surfaces of Inno Setup 6, NSIS 3, WiX/Burn, Advanced Installer, and InstallBuilder. It is a planning baseline, not a release claim. Update the matrix when a capability ships or its product decision changes.

Reference surfaces reviewed for the comparison:

- [Inno Setup Help](https://jrsoftware.org/ishelp/) — Icons, Tasks, Components, Registry, Run/UninstallRun and silent command-line contracts;
- [NSIS 3 Scripting Reference](https://nsis.sourceforge.io/Docs/Chapter4.html) — Sections, shortcuts, registry, execution, reboot, compression, language and silent-install primitives;
- [WiX Toolset documentation](https://docs.firegiant.com/wix/) — MSI packages plus Burn bundles, prerequisites, dependency and rollback orchestration;
- [Advanced Installer User Guide](https://www.advancedinstaller.com/user-guide/) — GUI-authored shortcuts, associations, services, prerequisites, updates, environment, localization and enterprise deployment surfaces;
- [InstallBuilder product overview](https://installbuilder.com/) — cross-platform components, downloadable components, desktop integration, text/silent modes and DMG workflows.

Production and distribution references additionally include the [Windows Installer portal](https://learn.microsoft.com/en-us/windows/win32/msi/windows-installer-portal), [MSIX overview](https://learn.microsoft.com/en-us/windows/msix/overview), [Apple notarization guidance](https://developer.apple.com/documentation/security/notarizing-macos-software-before-distribution), [Flatpak documentation](https://docs.flatpak.org/en/latest/), [AppImage documentation](https://docs.appimage.org/), [Reproducible Builds](https://reproducible-builds.org/docs/), and [SLSA 1.1](https://slsa.dev/spec/v1.1/).

## North star: what "better than the top installers" means

The target is not the largest directive count. Luxury Installer wins only when a real application can ship faster and with fewer unsafe escape hatches while retaining the mature capabilities users expect.

| Dimension | Best-in-class outcome | Measurement |
| --- | --- | --- |
| Authoring | A first useful installer is produced from Studio or CLI without learning a scripting language. | Clean-project time-to-first native artifact under 10 minutes, excluding toolchain download. |
| Correctness | Install, update, repair, cancel, crash recovery and uninstall converge on one receipt-owned state. | Native fault-injection matrix has no orphaned claimed files, lost modified files, or false success. |
| Security | Package and native identity, privileges, paths and integrations are fail-closed. | Threat model and attack-path review for every trust-boundary slice; zero accepted high/critical release findings. |
| Portability | One portable intent maps to native Windows, Linux and macOS behavior without pretending the OSes are identical. | Every advertised capability has explicit per-OS adapter/evidence rows. |
| Automation | Humans, CI and coding agents receive the same typed contract. | Live CLI help, JSONL, Studio, docs and AI skill drift tests remain green. |
| Operations | Enterprise deployment is observable and deterministic. | Stable exit codes, JSON inventory/plan/result, redacted logs, idempotent unattended flows and rollback records. |
| Performance | Large packages build and install without whole-payload memory growth or serial mega-gates. | Streaming I/O; bounded RSS; published clean/incremental build and install benchmarks. |
| Supply chain | Every public byte is attributable, signed and re-verifiable after download. | Checksums, SBOM, provenance, native signatures/notarization and downloaded-final-byte gates. |
| Accessibility | Studio and Setup work with keyboard, scaling, reduced motion and assistive technology. | Automated contract tests plus native manual checklist at every release candidate. |
| Maintainability | New capability extends a vertical slice instead of a generic scripting runtime. | No `common` dumping ground, speculative factory, renderer policy copy, or unbounded plug-in surface. |

## Definition of full production

Version 1.0 is allowed only when every mandatory gate below is evidenced on the exact release commit and downloaded release assets.

### Product gates

- Studio can create, reopen, validate and build a real target project on all advertised native hosts.
- Setup supports fresh install, update, exact repair, cancellation, recovery, uninstall, launch and reveal for user and system scope.
- P0 desktop integration, associations, components, prerequisite preflight and secure updater are complete across supported platforms or explicitly absent from that platform's advertised surface.
- Headless inventory/install/uninstall/update flows have stable JSON, exit codes and bounded diagnostics suitable for MDM/CI.
- English and Russian are complete compile-time locales; fallback behavior is deterministic and never fetches UI text.
- All public documentation describes only the live parser and packaged behavior.

### Native release gates

| Platform | Production artifact | Mandatory proof |
| --- | --- | --- |
| Windows 10/11 x64 + ARM64 | Authenticode-signed `Setup.exe`; optional MSI/MSIX only after demand review | Signed inner Tauri/backend, assembled outer NSIS, signed outer container, signer equality, SmartScreen-compatible metadata, user/system lifecycle, shortcuts/associations/services, reboot cases, downloaded-byte re-verification. |
| Linux supported distributions x64 + ARM64 | Signed repository-ready `.deb` and `.rpm`; optional Flatpak/AppImage milestone later | GTK advisory removed, installed root-owned helper/polkit lifecycle, package-manager install/upgrade/remove, desktop/MIME integration, distro metadata/signing, downloaded extraction/hash/mode/owner validation. |
| macOS 13+ Intel + Apple Silicon | Developer ID-signed, notarized, stapled `.dmg` with signed `.app`/LaunchDaemon | Nested designated requirements, Gatekeeper, notarization/staple, install/update/uninstall, LaunchServices associations, helper lifecycle, both architectures, downloaded DMG re-verification. |

### Security and reliability gates

- Repository threat model covers package supply chain, Studio authoring, JSONL, renderer/Tauri, helpers, filesystem transactions, updater, OS integrations and CI/release.
- Two independent source-first reviews plus review-of-review close every release-blocking finding.
- Path/link/alias, archive-bomb, hard-link, rename/ABA, cancellation, crash-window, power-loss approximation and low-disk matrices pass.
- Fuzz targets cover manifest/TOML, package archive, receipt/WAL, JSONL, privileged frames, updater metadata and native-container parsers.
- Dependency audit has no unaccepted vulnerability or unmaintained runtime boundary; Linux GTK blocker is gone rather than ignored.
- Secrets never enter Rust commands, JSONL, logs, fixtures or repository artifacts; external signing owns credentials.

### Supply-chain gates

- Hermetic pinned toolchain inputs and dependency locks for every target.
- Per-artifact SHA-256 manifest, CycloneDX or SPDX SBOM, license inventory and SLSA-aligned provenance.
- Release workflow signs metadata, uploads native assets, downloads every asset again, verifies signatures/hashes/layout and publishes a machine-readable verification report.
- Reproducibility is measured per artifact. Differences that cannot yet be bit-reproducible are explained and final signed bytes remain provenance-bound.

### Performance budgets

Budgets are release criteria after a benchmark baseline is recorded on named hardware; they are not claims about the current preview.

- Studio idle RSS: target under 150 MiB; Setup idle RSS: target under 120 MiB.
- Compiler/packager memory: `O(stream buffer + metadata)`, never `O(total payload)`; default streaming buffer at most 16 MiB per active stream.
- 1 GiB/25k-file package: bounded-memory compile and install with monotonic progress and cancellation latency under 500 ms outside commit.
- Incremental `cargo quick`: target under 60 seconds on reference CI; renderer contract/typecheck target under 30 seconds with dependencies cached.
- Full three-host native matrix stays parallel; no single lane exceeds 30 minutes on hosted release runners without an explicit exception record.
- Installed startup/launch overhead added by the receipt check: target under 150 ms median on SSD reference systems.

### Quality gates

- Unit/property tests for pure policy, contract tests for every wire boundary, native integration tests for each adapter, and final-artifact end-to-end tests.
- Keyboard-only, 100/125/150/200% scaling, screen-reader labels, reduced motion, high contrast and long-localized-text checks.
- Upgrade compatibility fixtures from every previously released schema/receipt/config version supported by policy.
- Backup restore and rollback commands are executed, not merely generated.
- Release notes, changelog, README, guides, CLI skill and `llms.txt` are synchronized on the release commit.

## Product rules

1. **Portable intent, native result.** The project describes a shortcut, file association, service, or prerequisite once; Rust maps it to the host-native implementation.
2. **No arbitrary package scripts.** Inno/NSIS-style unrestricted registry writes, shell commands, plug-ins, and install-time code are deliberately replaced by bounded typed actions with validation, ownership and rollback.
3. **One source of truth.** A capability is complete only when project schema, compiler, engine, platform adapter, CLI/JSONL, Studio, Setup, receipts, docs, tests and native evidence agree.
4. **No fake cross-builds.** Windows, Linux and macOS artifacts continue to build and sign on matching native runners.
5. **Fast normal work.** `cargo quick` and `cargo gui-check` stay separate. Native packaging, install integration and signing gates run only for affected platforms or release candidates.

## Current capability matrix

Legend: **Yes** is implemented in the current product flow; **Partial** has a useful subset but not the complete product contract; **No** is not implemented; **Deliberate no** is intentionally excluded.

| Capability | Luxury Installer today | Established installers | Decision |
| --- | --- | --- | --- |
| Native Windows/Linux/macOS output | **Yes**: `.exe`, `.deb` + `.rpm`, `.dmg` on native hosts | Broadly available, with different platform coverage | Keep and finish production signing evidence. |
| GUI authoring plus automation | **Yes**: Studio, human CLI, typed JSONL v3, AI skill | Advanced Installer/InstallBuilder lead in GUI; Inno/NSIS/WiX lead in text automation | Keep both surfaces synchronized. |
| Install/update/repair/uninstall | **Yes** | Standard in MSI/WiX; script-defined elsewhere | Preserve the single receipt-bound lifecycle. |
| Transaction rollback and crash recovery | **Yes**, with documented durability ceilings | MSI/WiX transactional behavior; script tools vary | Continue hardening final filesystem ceilings. |
| Safe ownership-aware uninstall | **Yes**: unknown and modified files are preserved | Usually script/component ownership rules | Product advantage; never weaken it. |
| User/system scope | **Yes**, with authenticated native helpers | Standard | Finish signed-final native proof. |
| Silent/unattended deployment | **Yes**: bounded bound-launcher commands and stable exits | Standard `/SILENT`, `/S`, MSI quiet modes | Add machine-readable deployment diagnostics before adding more flags. |
| License page, finish links, optional details | **Yes** | Standard | Keep bounded plain-text/HTTPS policy. |
| Publisher package signing and key rotation | **Yes** at package level; native release signing still gated | Native signing common; package-key rotation uncommon | Finish native signing UX and evidence. |
| Start Menu/Desktop/application-menu shortcuts | **No** | Inno `[Icons]`, NSIS `CreateShortCut`, WiX `Shortcut`, commercial GUI editors | **P0.** First missing mainstream feature. |
| File associations and URL protocols | **No** | Common in Inno/NSIS/WiX/commercial tools | **P0.** Typed extension/protocol declarations, never raw registry snippets. |
| Optional components/features | **No** | Inno Components, NSIS Sections, MSI Features, InstallBuilder components | **P0.** Needed for real authoring; must bind selection into plan, receipt, repair and uninstall. |
| Prerequisite detection/bootstrap chain | **No** | WiX Burn and commercial suites are strong here | **P0.** Start with detect-and-block guidance, then signed prerequisite bundles. |
| Built-in update feed/download | **No**; a newer Setup performs transactional update | Commercial suites and updater add-ons provide it | **P0.** Signed metadata, resumable download, staged verification, explicit apply/rollback. |
| Localized installer UI | **No**; current renderer copy is Russian | Inno/NSIS/InstallBuilder have multiple languages | **P1.** Compile-time locale catalogs plus optional OS-default selection; no runtime remote strings. |
| Services/daemons | **No** | Common in WiX/Advanced Installer; scriptable in Inno/NSIS | **P1.** Typed service declaration with bounded account/start/recovery policy and rollback. |
| Environment variables / PATH | **No** | Common | **P1.** Typed append/prepend/value actions with exact previous-state restoration. |
| Install conditions and OS/runtime requirements | **Partial**: exact target/architecture, scope, space and permission checks | Mature tools expose OS versions, RAM, runtime and custom conditions | **P1.** Bounded declarative predicates with actionable preflight output. |
| Existing-install discovery/migration | **Partial**: package ID, receipt, version and publisher migration | Inno registry discovery, MSI upgrade codes, commercial migration tools | **P1.** Import only explicit, verifiable legacy roots/identities. |
| Reboot/restart coordination | **No** | Standard on Windows installers | **P1.** Add only when locked-file replacement is implemented; no unconditional reboot action. |
| Digital-signing orchestration | **Partial**: exact two-phase Windows and macOS verify flows, external credentials | Mature products integrate signing UI/CI | **P1.** Add credential-free signing plans and artifact handoff reports, not secret ingestion. |
| Delta patches | **No** | MSI patches and commercial updaters support them | **P2.** Content-addressed chunking only after the full updater is stable. |
| Downloadable/on-demand components | **No** | InstallBuilder and bootstrapper suites support them | **P2.** Signed component manifests, offline cache and atomic aggregate receipt. |
| Custom themes/pages/dialog scripting | **No** | Inno/NSIS plug-ins and commercial products support extensive customization | **P3.** Permit bounded branding/content slots; keep the verified Setup state machine fixed. |
| Raw registry/INI edits, arbitrary shell commands, DLL plug-ins | **Deliberate no** | Core extension mechanism in Inno/NSIS | Replace only proven use cases with typed adapters. Arbitrary code destroys portable rollback and reviewability. |
| MSI/MSIX/PKG/AppImage output | **No** | Covered by WiX/Advanced Installer/platform tools | Reassess after P0/P1. Do not add container formats without a concrete distribution requirement. |
| Server/IIS/SQL/database configuration | **No** | Advanced Installer enterprise surface | Out of the desktop core. Future separately scoped adapters only when a real product needs them. |

## Ranked delivery plan

### P0 — mainstream product completeness

1. **Desktop integration v1**
   - App shortcut derived from the receipt-owned entrypoint.
   - Optional desktop shortcut and Start Menu/application-menu entry.
   - Native icon/title, user/system placement, collision policy, rollback and uninstall ownership.
   - No arbitrary target, arguments, working directory, shell verb or URL.
2. **File associations and URL protocols**
   - Strict extension/scheme, display name and icon declarations.
   - Open only the receipt-owned entrypoint with one OS-supplied document/URL argument through a separate validated launch path.
   - Restore the exact previous association on rollback/uninstall instead of deleting another application's ownership.
3. **Components/features**
   - Required and optional payload groups with stable IDs and localized labels.
   - Selection is authenticated input to preparation/install, persisted in the receipt, reused for repair/update, and shown in Studio/Setup/unattended inventory.
4. **Prerequisite preflight**
   - First release: typed installed-version/path/capability checks with actionable block messages.
   - Later: signed native prerequisite chain with offline cache, reboot state and independent receipts.
5. **Secure updater**
   - Signed channel metadata, rollout policy, resumable download, exact hash/signature validation and atomic handoff to the existing Setup lifecycle.

### P1 — deployment and enterprise readiness

- Locale catalogs and OS-default language selection.
- Typed services/daemons.
- Typed environment/PATH changes.
- Declarative install conditions and richer preflight JSON.
- Legacy-install discovery/import.
- Locked-file and reboot coordination.
- Credential-free signing plans, SBOM/provenance and final-byte release reports.
- Installed native integration tests for Start Menu/desktop entries, MIME/LaunchServices, services and associations.

### P2 — scale and distribution efficiency

- Streaming RPM writer and removal of the current 256 MiB combined-input ceiling.
- Content-addressed delta updates and offline cache.
- Downloadable components.
- Bandwidth/disk estimates and cache cleanup policy.
- Optional MSI/MSIX/PKG/AppImage only when distribution demand justifies their maintenance and signing matrices.

### P3 — bounded customization

- Product accent/logo/background slots with accessibility validation.
- Optional welcome/readme/privacy content.
- Extension SDK only for typed out-of-process adapters with explicit capabilities, receipts and rollback. No in-process installer plug-ins.

## Workstreams

Each workstream is a durable product responsibility. Milestones below select slices from these streams; they do not become new monolithic crates by default.

### W1 — package model and compiler

- Versioned portable manifest with exported limits and compatibility rules.
- Stable typed declarations for shortcuts, associations, components, prerequisites, services, environment changes, conditions, updater channels and branding.
- Deterministic package compilation, streaming payload/object handling, signing and publisher rotation.
- Compatibility fixtures and migration diagnostics for all supported schemas.

### W2 — transactional engine and receipts

- One plan contains payload files plus native integration intents.
- Receipt versions own installed files, selected components and OS integration objects with their exact previous-state backups.
- Install, update, repair, rollback, recovery and uninstall treat the aggregate plan atomically.
- Typed actions declare prepare/apply/verify/undo behavior; engine never executes package-supplied code.

### W3 — native platform adapters

- Windows: shell links, association registry contract, services, environment, Restart Manager/locked files, Authenticode and system roots.
- Linux: XDG desktop/MIME integration, systemd where supported, environment/profile policy, polkit helper and package-manager lifecycle.
- macOS: app/LaunchServices integration, LaunchAgents/Daemons, environment limits, SMAppService, codesign/notarization and DMG.
- All adapters enforce no-follow/link/owner/mode/path rules and restore overwritten native state precisely.

### W4 — Studio authoring experience

- Guided project creation with application, payload, integration, requirements, update and release sections.
- Searchable validation summary, plain-language errors, target compatibility and native preview.
- Reusable presets/templates without hidden code execution.
- Import/migration assistants for safe subsets of Inno Setup, NSIS and existing app layouts; unsupported directives become explicit review items.
- Build history, exact artifact report and pathless reveal; no secret or generic filesystem authority in React.

### W5 — Setup user experience

- Fixed verified state machine for review, components, license, prerequisites, destination, progress, completion and maintenance.
- Compile-time localization, accessibility, scaling and bounded product branding.
- Clear disk/change summary and factual native integrations before mutation.
- Retry/cancel/recovery that never contradicts Rust state.

### W6 — automation and fleet deployment

- Stable human CLI plus versioned typed JSONL/stdio.
- Bound-launcher `--info-json`, plan/validate modes, unattended actions, response-file support only when secret-free, and deterministic exit taxonomy.
- MDM-friendly inventory, logs and verification receipts.
- First-party AI skill generated/tested against live help and schema examples.

### W7 — secure update and distribution

- Signed channel metadata with staged rollout, minimum versions, revocation and publisher-key continuity.
- Resumable range download into a bounded cache, exact package verification before handoff, offline bundle support and proxy policy.
- Update service remains optional; applying bytes always reuses the normal Setup transaction.
- Delta/chunk transport is an optimization over the same verified full-package identity, never a separate trust model.

### W8 — release engineering and supply chain

- Pinned toolchains and native runner images, external credential handoff, SBOM/provenance/checksums.
- Windows two-phase signing, macOS sign/notary/staple, Linux distro signing.
- Release dry-run, candidate, publish, downloaded verification and rollback workflows.
- Public GitHub Release contains only production-qualified assets; prereleases are clearly labelled.

### W9 — observability, diagnostics and support

- Stable error codes and human remedies; redacted structured logs with operation correlation.
- Exportable support bundle containing versions, public package identity, stages and bounded diagnostics—never payload paths, secrets or raw private state.
- Installer self-diagnostics for OS prerequisites, signature validation and helper health.
- Crash reports are opt-in and separate from the install protocol.

### W10 — performance and maintainability

- Streaming package/container writers and parsers, bounded queues and cancellation.
- Benchmarks for compile, package, install, update, repair, uninstall, launch and memory.
- Hot modules split by real ownership inside current crates; dependency and binary-size budgets tracked.
- Tiered gates remain focused; release matrices run in parallel and reuse only trustworthy caches.

## Milestones and release train

Version numbers are planning targets. A milestone advances only when its exit criteria pass; incomplete capability moves forward rather than being hidden behind a release claim.

| Milestone | Product outcome | Mandatory exit criteria |
| --- | --- | --- |
| **0.2 Desktop essentials** | Receipt-owned application-menu/Start Menu and optional desktop shortcuts | Spec → Studio → engine → three native adapters; install/update/repair/uninstall/rollback; user/system native evidence. |
| **0.3 Open-with integration** | Typed file associations and URL protocols | Previous-owner restoration, one validated OS argument, collision UX, LaunchServices/XDG/Windows tests. |
| **0.4 Components** | Required/optional feature selection | Stable component IDs, authenticated selection, receipt persistence, update/repair semantics, unattended selection contract. |
| **0.5 Requirements** | Actionable prerequisites and conditions | Runtime/OS/disk predicates, preflight JSON, Studio editor, offline-friendly detect-and-block behavior. |
| **0.6 Updater preview** | Signed feed and verified full-package download | Metadata signing/rotation/revocation, resumable cache, staged rollout, handoff to existing Setup, proxy/offline tests. |
| **0.7 Deployment** | Localization and enterprise typed integrations | English/Russian, services/daemons, environment/PATH, richer inventory/logs, system-scope native matrix. |
| **0.8 Release pipeline** | Repeatable signed prereleases | Windows/macOS/Linux signing flows, SBOM/provenance, downloaded-final-byte checks, no Linux advisory blocker. |
| **0.9 Hardening RC** | Feature freeze and migration confidence | Fuzz/fault/performance/accessibility matrices, legacy fixtures, zero open release-blocking findings. |
| **1.0 Production** | Public best-in-class stable release | Every full-production gate above passes on exact tagged assets; install/uninstall and rollback proven from downloaded artifacts. |
| **1.1+ Scale** | Efficient large deployments | Streaming RPM, deltas, downloadable components, cache management and measured bandwidth/RSS improvements. |
| **2.x Ecosystem** | Carefully bounded extensibility and extra formats | Typed out-of-process adapter SDK and only demand-backed MSI/MSIX/PKG/Flatpak/AppImage work. |

## Exact implementation queue

This is the working order for agents. Finish one slice—including review and evidence—before starting the next row.

| # | Vertical slice | Depends on | Smallest routine gate | Native gate |
| ---: | --- | --- | --- | --- |
| 1 | Shortcut intent and schema validation | Existing entrypoint schema | `cargo test -p luxury-spec -p luxury-compiler` | None yet |
| 2 | Shortcut plan/receipt compatibility | 1 | Engine focused tests | None yet |
| 3 | User-scope native shortcuts | 2 | Platform focused tests | Matching Windows/Linux/macOS integration |
| 4 | System-scope shortcut helper flow | 3 | Privileged protocol + Tauri tests | Signed/root-owned native helper lanes |
| 5 | Studio shortcut controls and Setup review | 1–4 | `cargo gui-check` + help/docs test | Full shortcut lifecycle matrix |
| 6 | File association schema and previous-owner receipt | Shortcut receipt pattern | Spec/engine tests | None yet |
| 7 | Native file associations | 6 | Platform + GUI contracts | Three-host open/restore tests |
| 8 | URL protocols | 7 | Argument-bound launch tests | Three-host protocol activation |
| 9 | Component schema/compiler | Stable integration receipt | Spec/compiler tests | None yet |
| 10 | Component selection plan/receipt | 9 | Engine/JSONL contracts | None yet |
| 11 | Setup/Studio component UX | 10 | GUI contracts | Three-host install/update/repair matrix |
| 12 | Prerequisite predicates | Component plan | Spec/engine/CLI tests | Host runtime fixtures |
| 13 | Secure updater metadata | Publisher rotation | Parser/signature/fuzz tests | None yet |
| 14 | Resumable verified downloader | 13 | HTTP/cache integration tests | Proxy/offline host lanes |
| 15 | Update UI/automation handoff | 14 | GUI/JSONL contracts | Downloaded end-to-end update matrix |
| 16 | English/Russian locale catalogs | Stable Setup screens | Renderer contract tests | Native manual accessibility |
| 17 | Services/daemons | Typed integration transaction | Engine/platform tests | Three-host service lifecycle |
| 18 | Environment/PATH | Previous-state restore pattern | Engine/platform tests | Three-host shell/session checks |
| 19 | Locked files/reboot | Windows integration maturity | Windows focused tests | Restart Manager/reboot VM matrix |
| 20 | Signing/provenance release UX | Stable feature set | xtask/release contract tests | Downloaded signed native matrix |

## Dependency graph

```text
entrypoint + receipts
  └─ shortcuts
      └─ native-integration receipt pattern
          ├─ associations ── URL protocols
          ├─ components ── prerequisites
          ├─ services/daemons
          └─ environment/PATH ── reboot handling

publisher signing + rotation
  └─ signed updater metadata
      └─ resumable verified download
          └─ staged rollout ── deltas/downloadable components

stable Setup screens
  └─ localization + accessibility freeze
      └─ 0.9 hardening RC

all P0/P1 + signing + supply-chain + native evidence
  └─ 1.0 production
```

## Production scorecard

Maintain this table in every release-readiness review. Evidence must name an exact commit/run/artifact; `planned` is never green.

| Gate | Current preview | 0.9 requirement | 1.0 requirement |
| --- | --- | --- | --- |
| Core transactional lifecycle | Implemented and source/native-smoke tested | Full fault matrix | Downloaded final-byte matrix |
| Windows signed release | Source flow exists | Signed RC lifecycle | Signed downloaded release verified |
| Linux release | Blocked by GTK advisory | Advisory removed + distro integration | Signed downloaded `.deb`/`.rpm` verified |
| macOS release | Source flow exists | Signed/notarized dual-arch RC | Downloaded stapled DMG verified |
| Shortcuts/associations/components/prerequisites/updater | Planned | Complete and frozen | Compatibility evidence |
| Localization/accessibility | Russian presentation baseline | English/Russian + automated/manual matrix | Release checklist green |
| Fuzz/fault/security reviews | Strong focused tests, incomplete portfolio | Full portfolio, no blockers | Repeat on final diff/bytes |
| Performance budgets | No authoritative baseline | Baseline + budgets met | Regression comparison published |
| SBOM/provenance/reproducibility | Partial checksums/evidence | RC artifacts carry reports | Downloaded public assets reverified |
| Documentation/AI compatibility | Live help drift test exists | All feature docs synchronized | Release docs and skill versioned |

## Release decision rules

- A capability is not shipped because its schema compiles; it needs final native behavior and rollback proof.
- A platform is not supported because another OS passed or a cross-compile succeeded.
- A GitHub Actions artifact is not a release; production requires GitHub Release assets downloaded and reverified.
- Unsigned output is always a development/prerelease artifact.
- A known security advisory in a shipped runtime blocks production rather than receiving a silent ignore.
- A failed neighboring test invalidates reused matrix evidence.
- Performance and accessibility regressions are release defects, not post-release polish.
- Every milestone ends with independent review, review-of-review, concise before/after value, exact gaps and runnable rollback.

## Architecture and build optimization backlog

The architecture direction is correct, but several composition modules are now expensive to review:

| Hotspot | Current size | Planned ownership split |
| --- | ---: | --- |
| `apps/luxury-cli/src/stdio.rs` | ~4.1k lines | project authoring, lifecycle operations, wire types, and server loop modules inside the CLI crate |
| `xtask/src/runner.rs` | ~3.1k lines | assembly, project packager, lifecycle smoke and evidence modules; platform container modules stay separate |
| `crates/luxury-platform/src/local/mod.rs` | ~2.6k lines | install adapter, uninstall adapter, receipt store and shared local policy modules |
| `apps/luxury-installer/src-tauri/src/setup.rs` | ~2.5k lines | bootstrap/review, operation lifecycle, completion actions and contract tests |
| `crates/luxury-platform/src/local/transaction.rs` | ~2.3k lines | journal codec, recovery, durability primitives and lock/rename operations |
| `apps/luxury-installer/src-tauri/src/studio.rs` | ~1.8k lines | recent projects, authoring commands, native build orchestration and validation |

Splits are refactors inside existing crates, not new `common` crates or speculative interfaces. Do them only adjacent to a feature that benefits from the ownership boundary.

Build priorities:

- retain the separate root and Tauri workspaces;
- add affected-slice commands only when they save measured CI time;
- keep full native lanes parallel and manual/release-scoped;
- measure clean/incremental compile time before changing profiles or codegen;
- remove duplicate schema literals by exporting current manifest limits/versions to adapters instead of hand-maintaining `1..=3` checks;
- migrate the buffered RPM writer before raising its memory ceiling;
- avoid adding installer dependencies to the core `cargo quick` graph.

## First implementation slice

Start with **Desktop integration v1**, not a generic actions framework:

```toml
[install.shortcuts]
application_menu = true
desktop = false
```

The target is always the existing receipt-owned entrypoint. Projects without an entrypoint cannot enable shortcuts. The engine plans the exact native artifacts; platform adapters create them transactionally; the receipt owns their identity and prior-state backup; Setup offers only the two author choices already authenticated in the package. This narrow shape covers the common Inno/NSIS use case without introducing arbitrary commands, arguments or paths.

Definition of done:

- schema and compiler validation;
- Studio editing and strict Tauri/JSONL contracts;
- preparation summary and unattended inventory;
- transactional user/system creation on Windows, Linux and macOS;
- rollback, repair, update and uninstall ownership tests;
- exact native package/container integration and native-host evidence;
- synchronized README, AI guide, `llms.txt`, public CLI skill and changelog.

## Explicitly not next

- A Pascal/NSIS-like scripting language.
- A raw registry editor.
- Arbitrary post-install commands.
- A plug-in loader.
- More archive/container formats before common authoring capabilities.
- A universal Windows cross-build that pretends to sign/notarize Linux or macOS outputs.

## Roadmap maintenance contract

- This file is the single public product roadmap. Do not create a competing backlog document.
- When a slice ships, update its capability-matrix state, milestone exit criteria, implementation queue and production scorecard in the same commit.
- Every roadmap claim must be `implemented`, `partial`, `blocked`, `planned`, or `deliberate no`; avoid vague percentages.
- Issues/PRs reference the workstream, milestone and queue row, but source/docs remain authoritative for live behavior.
- Quarterly or before a release candidate, refresh competitor/platform references and reassess whether excluded formats or integrations have real demand.
- New ideas enter after evidence of user value, threat-boundary analysis, rollback ownership and native verification cost—not because another installer exposes a directive.

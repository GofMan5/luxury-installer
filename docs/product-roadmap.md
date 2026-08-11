# Product roadmap: from secure core to a complete installer

Luxury Installer already has the hard part that many script-first installers bolt on later: verified packages, transactional mutation, recovery, ownership receipts, strict unattended operation, native artifacts, and one Studio/CLI contract. The next stage is not to clone every Inno Setup or NSIS directive. It is to add the common product capabilities people actually need while keeping each OS mutation typed, reversible, and visible in Studio.

This roadmap compares the current checkout with Inno Setup 7.0.2, NSIS 3.12, WiX 7/Burn, Advanced Installer 23.9, and InstallBuilder 26.5.1 as reviewed on 2026-08-09. It is a planning baseline, not a release claim. Update the pinned versions and matrix when a capability ships or a competitor/product decision changes.

Reference surfaces reviewed for the comparison:

> Competitor snapshot: 2026-08-09. Recheck official release notes before changing parity claims or entering RC; rolling documentation may have advanced beyond these pinned versions.

- [Inno Setup Help and downloads](https://jrsoftware.org/ishelp/) — Inno Setup 7.0.2 Icons, Tasks, Components, Registry, Run/UninstallRun, x64/ARM64, extended-length paths and silent command-line contracts;
- [NSIS 3.12 Scripting Reference](https://nsis.sourceforge.io/Docs/Chapter4.html) — Sections, shortcuts, registry, execution, reboot, compression, language and silent-install primitives;
- [WiX 7 Toolset documentation](https://docs.firegiant.com/wix/) — MSI packages plus Burn bundles, prerequisites, dependency and rollback orchestration;
- [Advanced Installer 23.9 User Guide](https://www.advancedinstaller.com/user-guide/) — GUI-authored shortcuts, associations, services, prerequisites, updates, environment, localization and enterprise deployment surfaces;
- [InstallBuilder 26.5.1 product overview](https://installbuilder.com/) — cross-platform components, downloadable components, desktop integration, text/silent modes and DMG workflows.

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
| Performance | Large packages build and install without whole-payload memory growth or serial mega-gates. | Streaming I/O, including RPM before 1.0; bounded RSS; published clean/incremental build and install benchmarks. |
| Supply chain | Every public byte is attributable, signed and re-verifiable after download. | Checksums, SBOM, provenance, native signatures/notarization and downloaded-final-byte gates. |
| Accessibility | Studio and Setup work with keyboard, scaling, reduced motion and assistive technology. | Automated contract tests plus native manual checklist at every release candidate. |
| Maintainability | New capability extends a vertical slice instead of a generic scripting runtime. | No `common` dumping ground, speculative factory, renderer policy copy, or unbounded plug-in surface. |

## Definition of full production

Version 1.0 is allowed only when every mandatory gate below is evidenced on the exact release commit and downloaded release assets.

### Product gates

- Studio can create, reopen, validate and build a real target project on all advertised native hosts.
- Setup supports fresh install, update, exact repair, cancellation, recovery, uninstall, launch and reveal for user and system scope.
- Installed applications remain maintainable after the downloaded Setup is deleted: each supported OS gets a native installed-app/uninstall entry and a repair/uninstall launcher bound to the receipt, product identity and current helper policy.
- The exact 1.0 capability set is complete across supported platforms or explicitly excluded from that platform: product identity, desktop integration, associations/protocols, component modify, global conditions, signed prerequisite chaining, secure updater, durable maintenance/fleet inventory, localization, running-app/locked-file and reboot handling, services/daemons, and environment/PATH ownership.
- Headless inventory, plan, install, repair, uninstall and update flows have versioned JSON, stable documented exit codes, bounded diagnostics and non-interactive system-scope semantics suitable for MDM/CI.
- English and Russian are complete compile-time locales; fallback behavior is deterministic and never fetches UI text.
- All public documentation describes only the live parser and packaged behavior.
- The release publishes a precise support policy: OS/distro/libc/CPU minima, support lifetime, schema/receipt/config compatibility windows, and task-based author, end-user, fleet and troubleshooting guides.

### Native release gates

| Platform | Production artifact | Mandatory proof |
| --- | --- | --- |
| Windows 10/11 x64; ARM64 after an explicit architecture-enablement milestone | Authenticode-signed `Setup.exe`; optional MSI/MSIX only after demand review | Signed inner Tauri/backend, assembled outer NSIS, signed outer container and signer equality. Peer proof evaluates the actual process image through a no-write/delete-sharing handle plus `ProcessImageFileMapping`, never path-only WinTrust. Every Windows capability in the exact 1.0 set and downloaded bytes are reverified. |
| Linux supported distributions x64; ARM64 after native runner evidence | Product-identified `.deb` and `.rpm` plus explicitly named signed repository channels; optional Flatpak/AppImage milestone later | GTK advisory removed, installed root-owned helper/polkit lifecycle, product-derived container identity, no double-install/orphan state, package-manager install/upgrade/remove, desktop/MIME integration, repository metadata/signing, downloaded extraction/hash/mode/owner validation. |
| macOS 13+ Apple Silicon; Intel after native runner evidence | Developer ID-signed, notarized, stapled `.dmg` with signed `.app`/LaunchDaemon | Nested designated requirements, Gatekeeper, notarization/staple, every macOS capability included in the exact 1.0 set, helper lifecycle and downloaded Apple-Silicon DMG re-verification. |

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

The benchmark manifest fixes OS image, CPU/RAM/storage, toolchain, warm/cold cache, corpus hashes and at least five repetitions. It records median and p95 time, peak RSS, output bytes/installer overhead, compression ratio, build/install/update/uninstall throughput and cancellation latency for tiny, medium and 1 GiB/25k-file corpora. Release ceilings are explicit numbers plus allowed regression from the previous release; named competitor versions may be measured with equivalent payloads, without turning their marketing claims into our evidence.

### Quality gates

- Unit/property tests for pure policy, contract tests for every wire boundary, native integration tests for each adapter, and final-artifact end-to-end tests.
- WCAG 2.2 AA for the web shell plus Windows UIA with Narrator/NVDA, macOS VoiceOver and Linux AT-SPI/Orca where supported; keyboard/focus/error announcements, reduced motion, high contrast, RTL/long text and 100/125/150/200/300/400% scaling have zero critical findings.
- Upgrade compatibility fixtures from every previously released schema/receipt/config version supported by policy.
- Automatic rollback/recovery fault cases and the release-deployment rollback procedure are executed, not merely described.
- Release notes, changelog, README, guides, CLI skill and `llms.txt` are synchronized on the release commit.
- RC smoke follows real tasks: an author builds in Studio/CLI, an end user installs/repairs/removes in Setup, and a fleet operator inventories/deploys/diagnoses without the original download.

## Product rules

1. **Portable intent, native result.** The project describes a shortcut, file association, service, or prerequisite once; Rust maps it to the host-native implementation.
2. **No arbitrary package scripts.** Inno/NSIS-style unrestricted registry writes, shell commands, plug-ins, and install-time code are deliberately replaced by bounded typed actions with validation, ownership and rollback.
3. **One source of truth.** A capability is complete only when project schema, compiler, engine, platform adapter, CLI/JSONL, Studio, Setup, receipts, docs, tests and native evidence agree.
4. **No fake cross-builds.** Windows, Linux and macOS artifacts continue to build and sign on matching native runners.
5. **Fast normal work.** `cargo quick` and `cargo gui-check` stay separate. Native packaging, install integration and signing gates run only for affected platforms or release candidates.

## Current capability matrix

Status vocabulary: **Implemented** is live in the complete advertised flow with current evidence; **Partial** has a useful subset but not the complete contract; **Blocked** has implementation behind an unresolved release condition; **Planned** has no shipped product behavior; **Deliberate no** is intentionally excluded. Notes may say which subparts exist, but do not change the status.

| Capability | Luxury Installer today | Established installers | Decision |
| --- | --- | --- | --- |
| Native Windows/Linux/macOS output | **Partial**: verified unsigned development `.exe`, `.deb` + `.rpm`, and `.dmg` exist on the current native matrix; Linux production publication is blocked and macOS production still needs signed/notarized product-app evidence | Broadly available, with different platform coverage | Finish product-derived containers, signing and downloaded-final-byte evidence per platform. |
| GUI authoring plus automation | **Implemented**: Studio, human CLI, typed JSONL v4, AI skill | Advanced Installer/InstallBuilder lead in GUI; Inno/NSIS/WiX lead in text automation | Keep both surfaces synchronized; add a shared multi-target workspace only after identity/version drift proves the need. |
| Install/update/repair/uninstall | **Implemented** | Standard in MSI/WiX; script-defined elsewhere | Preserve the single receipt-bound lifecycle. |
| Transaction rollback and crash recovery | **Partial**, with useful recovery and documented durability ceilings | MSI/WiX transactional behavior; script tools vary | Continue hardening final filesystem ceilings. |
| Safe ownership-aware uninstall | **Implemented**: unknown and modified files are preserved | Usually script/component ownership rules | Product advantage; never weaken it. |
| User/system scope | **Partial**, with authenticated native helper source flows but incomplete signed-final evidence | Standard | Finish signed-final native proof. |
| Silent/unattended deployment | **Partial**: bound launcher has bounded info/install/uninstall commands and stable coarse exits; no plan/repair/update JSON result, response file or fleet-grade exit taxonomy yet | Standard `/SILENT`, `/S`, MSI quiet modes; InstallBuilder also has console mode | **P0.** Add versioned plan/result JSON and actionable exit classes before more aliases; add a text UI only if remote operators need interactive selection. |
| Native installed-app/uninstall registration | **Planned**: removal currently requires the original bound Setup or a development CLI with trusted roots | Windows Installed Apps/ARP and platform package managers expose durable uninstall/maintenance entries | **P0.** Install an exact maintenance launcher plus native metadata, keep it outside the removable payload and update/remove it transactionally. |
| License page, finish links, optional details | **Implemented** | Standard | Keep bounded plain-text/HTTPS policy. |
| Publisher package signing and key rotation | **Partial**: implemented at package level; native release signing still gated | Native signing common; package-key rotation uncommon | Finish native signing UX and evidence. |
| Product identity and native metadata | **Partial**: schema 5 authenticates target-native product icon plus homepage/support; receipt v7 persists the exact snapshot, while native containers, shortcuts and OS inventory consume it in later rows | Mature installers populate container metadata, shortcuts, OS inventory and support links from one product identity | Finish consumers in rows 5, 6, 8 and 9; keep privileged Setup/tool identity separate and visual themes P3. |
| Start Menu/Desktop/application-menu shortcuts | **Partial**: schema 4 intent, receipt v7 artifact authority, engine ports, Windows `.lnk` and Linux `.desktop` codecs; WAL v5/publication and macOS product `.app` remain | Inno `[Icons]`, NSIS `CreateShortCut`, WiX `Shortcut`, commercial GUI editors | **P0.** Next: typed external-root WAL, transactional user adapters, macOS app bundle, then system helpers and lifecycle proof. |
| File associations and URL protocols | **Planned** | Common in Inno/NSIS/WiX/commercial tools | **P0.** Typed extension/protocol declarations, never raw registry snippets. |
| Optional components/features | **Planned** | Inno Components, NSIS Sections, MSI Features, InstallBuilder components | **P0.** Needed for real authoring; must bind selection into plan, receipt, repair and uninstall. |
| Prerequisite detection/bootstrap chain | **Planned** | WiX Burn and commercial suites cover detect/plan/apply, related bundles, dependency providers, cache/source repair, reboot resume and offline layouts | **P0.** Start with detect-and-block, then complete a bounded signed chain contract before claiming bootstrapper parity. |
| Built-in update feed/download | **Planned**; a newer Setup performs transactional update | Commercial suites and updater add-ons provide it | **P0.** Signed metadata, resumable download, staged verification, explicit apply/rollback. |
| Localized installer UI | **Planned**; current renderer copy is Russian | Inno/NSIS/InstallBuilder have multiple languages | **P1.** Compile-time locale catalogs plus optional OS-default selection; no runtime remote strings. |
| Services/daemons | **Planned** | Common in WiX/Advanced Installer; scriptable in Inno/NSIS | **P1.** Typed service declaration with bounded account/start/recovery policy and rollback. |
| Environment variables / PATH | **Planned** | Common | **P1.** Typed append/prepend/value actions with exact previous-state restoration. |
| Install conditions and OS/runtime requirements | **Partial**: exact target/architecture, scope, space and permission checks | Mature tools expose OS versions, RAM, runtime and custom conditions | **P1.** Bounded declarative predicates with actionable preflight output. |
| Existing-install discovery/migration | **Partial**: package ID, receipt, version and publisher migration | Inno registry discovery, MSI upgrade codes, commercial migration tools | **P1.** Import only explicit, verifiable legacy roots/identities. |
| Versions, instances, channels and shared dependencies | **Partial**: single package ID supports update/repair and explicit downgrade policy; no side-by-side instance or dependency-provider model | MSI/WiX models upgrades/features/instances; Burn models related bundles and dependency ownership | **P0 policy.** Define major/minor compatibility, channel switching, component-ID evolution and shared dependency refcounts; unsupported side-by-side modes must be explicit. |
| Running-application and locked-file coordination | **Planned** | Inno can close/restart applications; MSI/WiX and commercial tools integrate Restart Manager | **P1.** Detect product-owned running images first; add bounded graceful-close/retry/defer policy before any locked-file replacement. |
| Reboot/restart coordination | **Planned** | Standard on Windows installers | **P1.** Add only after running-application/locked-file handling exists; preserve one authenticated pending transition across reboot and never expose unconditional reboot as package code. |
| Native installed size and OS inventory metadata | **Planned** | Mature Windows/Linux/macOS packages expose publisher, version, icon and estimated size to system inventory | Fold into the P0 maintenance-registration slice and derive every field from authenticated package/receipt data. |
| Digital-signing orchestration | **Partial**: exact two-phase Windows and macOS verify flows, external credentials | Mature products integrate signing UI/CI | **P1.** Add credential-free signing plans and artifact handoff reports, not secret ingestion. |
| Delta patches | **Planned** | MSI patches and commercial updaters support them | **P2.** Content-addressed chunking only after the full updater is stable. |
| Downloadable/on-demand components | **Planned** | InstallBuilder and bootstrapper suites support them | **P2.** Signed component manifests, offline cache and atomic aggregate receipt. |
| Custom themes/pages/dialog scripting | **Planned** | Inno/NSIS plug-ins and commercial products support extensive customization | **P3.** Permit bounded branding/content slots; keep the verified Setup state machine fixed. |
| Fonts and file ACLs | **Deliberate no** for 1.0 | WiX/Advanced Installer cover common native resources | Reassess after 1.0 against real desktop demand; any implementation is typed, narrowly scoped and exactly reversible. |
| Scheduled tasks and firewall rules | **Planned** | WiX/Advanced Installer/InstallBuilder cover managed OS integrations | Post-1.0 unless a supported product needs them; require principal/port/trigger ownership and rollback. |
| Drivers, certificates, COM and ODBC | **Deliberate no** for 1.0 | Enterprise Windows installers expose them | High-risk or platform-specific adapters require a separately approved product and threat model. |
| Raw registry/INI edits, arbitrary shell commands, DLL plug-ins | **Deliberate no** | Core extension mechanism in Inno/NSIS | Replace only proven use cases with typed adapters. Arbitrary code destroys portable rollback and reviewability. |
| MSI/MSIX/PKG/AppImage output | **Planned** | Covered by WiX/Advanced Installer/platform tools | Reassess after P0/P1. Do not add container formats without a concrete distribution requirement. |
| Enterprise export, repackaging and patch formats | **Planned** | Advanced Installer supports MSI/MSIX editing, Intune/MECM and patches; WiX supports MSI/MSP/MSM/Burn | Separate demand-gated workstreams after 1.0; do not hide migration, fleet export and patching inside an “extra formats” checkbox. |
| Installer analytics | **Deliberate no** for 1.0 | Some commercial products offer reporting/analytics | **Deliberate no for 1.0.** Core install and update protocols remain telemetry-free; future opt-in analytics needs a standalone privacy model. |
| Server/IIS/SQL/database configuration | **Deliberate no** for the desktop core | Advanced Installer enterprise surface | Out of the desktop core. Future separately scoped adapters only when a real product needs them. |

## Ranked delivery plan

### P0 — mainstream product completeness

0. **Durable native maintenance and fleet contract**
   - Install a receipt-bound maintenance launcher, a verified repair-source/cache policy and native Installed Apps/package-manager metadata; deleting the downloaded Setup must not remove repair/uninstall authority.
   - Derive display name, version, publisher, icon and installed size from authenticated package/receipt data; update them atomically and remove them only with matching ownership.
   - Add machine-readable installed-state inventory, plan, repair, update, uninstall and result contracts with documented exit classes, log location/redaction/retention policy and non-interactive elevation behavior.
   - Treat `elevation_required` as a stable result in no-prompt mode; an already-authorized deployment context may continue without a second prompt.
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
   - Maintenance can atomically add/remove optional groups; update defines renamed/removed-ID behavior and unattended modify uses the same typed plan.
4. **Prerequisite preflight**
   - First release: typed installed-version/path/capability checks with actionable block messages.
   - Signed native chain: ordered/DAG packages, per-package detect/install/repair/uninstall, vital/non-vital policy, dependency/refcount ownership, cache/source repair, partial-failure boundary, reboot resume and offline layout, each with an independent receipt.
5. **Secure updater**
   - Signed channel metadata, rollout policy, resumable download, exact hash/signature validation and atomic handoff to the existing Setup lifecycle.

### P1 — deployment and enterprise readiness

- Locale catalogs and OS-default language selection.
- Running-application detection, graceful close/restart and locked-file policy before reboot support.
- Typed services/daemons.
- Typed environment/PATH changes.
- Declarative install conditions and richer preflight JSON.
- Credential-free signing plans, SBOM/provenance and final-byte release reports.
- Installed native integration tests for Start Menu/desktop entries, MIME/LaunchServices, services and associations.

English/Russian is the 1.0 locale floor, not full competitor parity. Post-1.0 expansion includes pseudo-locales, RTL/bidi/mirroring, CJK/IME/font fallback, plural rules and locale persistence across maintenance.
Legacy-install import remains post-1.0 unless a supported migration fixture is committed; 1.0 still detects and protects its own package identity, receipts, versions and publisher transitions.

### Pre-1.0 performance closure

- Streaming RPM writer and removal of the current 256 MiB combined-input ceiling.

### P2 — scale and distribution efficiency

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
- One authenticated product identity supplies display name, publisher, version, native icon, homepage and support URL to containers and integrations; target-specific payloads may override binaries without duplicating identity.
- Stable typed declarations for shortcuts, associations, components, prerequisites, services, environment changes, conditions, updater channels and branding.
- Deterministic package compilation, streaming payload/object handling, signing and publisher rotation.
- Compatibility fixtures and migration diagnostics for all supported schemas.

### W2 — transactional engine and receipts

- One plan contains payload files plus native integration intents.
- Receipts own installed files, selected components and the exact identity of published OS integration objects. The WAL owns crash-recoverable staging/restoration; exact previous-owner backups are mandatory only for integrations that deliberately replace another owner, such as associations.
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
- Post-1.0: import/migration assistants for safe subsets of Inno Setup, NSIS and existing app layouts; unsupported directives become explicit review items.
- Build history, exact artifact report and pathless reveal; no secret or generic filesystem authority in React.
- Usability acceptance measures first-build, reopen, version/payload update, failed-build diagnosis and multi-target release tasks; post-1.0 import adds its own task. Record completion time, error recovery and abandonment rather than judging screenshots.

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
- Documentation conformance executes every public CLI/JSONL example against fixed fixtures and validates typed request, result and error schemas—not only command-name substrings.

### W7 — secure update and distribution

- Signed channel metadata with staged rollout, minimum versions, revocation and publisher-key continuity.
- Resumable range download into a bounded cache, exact package verification before handoff, offline bundle support and proxy policy.
- Update service remains optional; applying bytes always reuses the normal Setup transaction.
- Deployment policy can pin/disable a channel; operators can pause or withdraw rollout metadata, and a bad release has a signed forward-fix procedure that does not rely on silently bypassing downgrade policy.
- Delta/chunk transport is an optimization over the same verified full-package identity, never a separate trust model.

### W8 — release engineering and supply chain

- Pinned toolchains and native runner images, external credential handoff, SBOM/provenance/checksums.
- Windows two-phase signing, macOS sign/notary/staple, Linux distro signing.
- Release dry-run, candidate, publish, downloaded verification and rollback workflows.
- Public GitHub Release contains only production-qualified assets; prereleases are clearly labelled.
- Signed Studio distributions and the installers Studio generates are separate artifact families; each has its own update, support, signature and downloaded-final-byte evidence.

### W9 — observability, diagnostics and support

- Stable error codes and human remedies; redacted structured logs with operation correlation.
- Exportable support bundle containing versions, public package identity, stages and bounded diagnostics—never payload paths, secrets or raw private state.
- Installer self-diagnostics for OS prerequisites, signature validation and helper health.
- Crash reports are opt-in and separate from the install protocol.
- Persistent logs have fixed OS-native locations, private permissions, bounded per-file and total quota, rotation/retention, update continuity, uninstall cleanup and a redacted pathless export flow.

### W10 — performance and maintainability

- Streaming package/container writers and parsers, bounded queues and cancellation.
- Benchmarks for compile, package, install, update, repair, uninstall, launch and memory.
- Hot modules split by real ownership inside current crates; dependency and binary-size budgets tracked.
- Tiered gates remain focused; release matrices run in parallel and reuse only trustworthy caches.

## Milestones and release train

Version numbers are planning targets. A milestone advances only when its exit criteria pass; incomplete capability moves forward rather than being hidden behind a release claim.

| Milestone | Product outcome | Mandatory exit criteria |
| --- | --- | --- |
| **0.2 Desktop essentials** | Product identity plus receipt-owned application-menu/Start Menu and optional desktop shortcuts | Rows 1-7: identity, WAL, product `.app`, install/update/repair/uninstall/rollback and user/system native evidence on the current three-host matrix. |
| **0.3 Durable maintenance** | Native installed-app registration plus fleet-grade headless contract | Rows 8-10: product-derived Linux container lifecycle; original Setup may be deleted; verified retained repair source, installed-state inventory, versioned plan/result JSON, exit taxonomy and no-prompt deployment tests pass. |
| **0.4 Open-with integration** | Typed file associations and URL protocols | Rows 11-13: previous-owner restoration, one validated OS argument, collision UX and LaunchServices/XDG/Windows tests. |
| **0.5 Components** | Required/optional feature selection and Modify | Rows 14-16: stable IDs, authenticated selection, atomic add/remove, receipt persistence, update/repair semantics and unattended modify. |
| **0.6 Requirements and chain core** | Conditions plus signed prerequisite orchestration without reboot continuation | Rows 17-20: global/component predicates, version/dependency policy, offline layout, cache/source repair and partial-failure boundaries. |
| **0.7 Updater preview** | Signed feed and verified full-package download | Rows 21-24: trust-policy attacks, metadata signing/rotation/revocation, resumable cache, staged rollout, Setup handoff and proxy/offline tests. |
| **0.8a Deployment UX** | Complete Setup copy plus diagnostics and executable public docs | Rows 25, 30-32: English/Russian catalogs, support bundle/log limits, runnable CLI/JSONL examples and exact support matrix; full native accessibility evidence remains an RC gate. |
| **0.8b Environment integration** | Typed environment/PATH ownership | Row 28: exact prior-state restoration and three-host shell/session evidence. |
| **0.8c Managed processes** | Running-app policy, services/daemons and reboot continuation | Rows 26-29: graceful close/locked-file handling, service lifecycle and authenticated reboot-resume VM evidence. |
| **0.9 Release pipeline** | Repeatable signed prereleases and Linux repository channels | Rows 33-36: Linux runtime blocker removal, pinned runners, credential-free signing handoff, SBOM/license/provenance, process-image-bound Windows trust, separate Studio/generated-installer contracts and updater lifecycle, plus apt/RPM repository signing/install/update/rollback. |
| **0.10 Hardening RC** | Feature freeze and measured migration confidence | Rows 37-40: streaming RPM, named-host benchmarks, repository threat model, fuzz/fault/accessibility evidence, two independent source-first reviews, review-of-review and a signed exact-byte RC with zero release blockers. |
| **1.0 Production** | Public best-in-class stable release | Row 41 and every full-production gate: publish, redownload, reverify and rehearse deployment rollback on exact tagged assets. |
| **1.1 Architecture coverage** | Same verified product on additional CPU architectures | Row 42: Windows ARM64, Linux ARM64 and macOS Intel only after matching native runners, packagers, signing, helper lifecycle and downloaded-final-byte evidence. |
| **1.2+ Scale** | Efficient large deployments | Deltas, downloadable components, cache management and measured bandwidth/RSS improvements. |
| **2.x Ecosystem** | Carefully bounded extensibility and extra formats | Typed out-of-process adapter SDK and only demand-backed MSI/MSIX/PKG/Flatpak/AppImage work. |

## Exact implementation queue

Rows are priority ordered, but independent rows may run in parallel once every named dependency is evidenced. A row reaches `implemented` only after its focused/native gates, independent review, review-of-review, docs and rollback are complete.

| # | Status | Vertical slice | Depends on | Smallest routine gate | Native/exit evidence |
| ---: | --- | --- | --- | --- | --- |
| 1 | implemented | Shortcut intent and schema validation | Existing entrypoint schema | `cargo test -p luxury-spec -p luxury-compiler` | None yet; native mutation is a later row. |
| 2 | implemented | Shortcut plan/receipt/JSONL/GUI contract compatibility | Row 1 | Engine, CLI and GUI focused tests | Typed preflight remains unsupported pending publication. |
| 3 | partial | Receipt v7-carried shortcut artifacts, engine ports plus Windows `.lnk` and Linux `.desktop` codecs | Row 2 | Engine/platform codec tests | Independent findings must close; no publication authority yet. |
| 4 | implemented | Authenticated product identity core: schema 5 target-native icon, homepage/support, JSONL v4 and receipt v7 | Rows 1-3 | Spec/bundle/compiler/engine/authoring/docs tests | Independent review plus review-of-review closed; native consumer evidence belongs to rows 5, 6, 8 and 9 and never rebrands Setup infrastructure. |
| 5 | planned | External-root WAL v5 and transactional shortcut publication | Rows 3-4 | Transaction/recovery tests | Crash/cancel/collision matrix on Windows/Linux. |
| 6 | planned | macOS product `.app`, bundle identity and credential-free signed-candidate handoff | Row 4 | Compiler/packager/layout tests | Externally signed product-app LaunchServices/shortcut candidate on macOS. |
| 7 | planned | Complete user/system shortcut lifecycle and visible Setup review | Rows 3, 5-6 | Privileged protocol, Tauri, GUI and docs tests | Three-host install/update/repair/uninstall/rollback matrix. |
| 8 | planned | Product-derived Linux outer-container lifecycle | Rows 4-5 | Container identity/layout tests | Two products coexist; package-manager install/upgrade/remove leaves no orphan product, receipt or helper. |
| 9 | planned | Maintenance launcher, verified repair source and native inventory metadata | Rows 4-8 | Engine/platform/release-contract tests | Downloaded Setup install -> delete Setup -> repair/uninstall on three hosts. |
| 10 | planned | Fleet installed-state inventory, plan/result JSON and exit taxonomy | Row 9 | CLI/help/docs/JSONL contract tests | Non-interactive user/system deployment including stable `elevation_required`. |
| 11 | planned | File-association schema and previous-owner receipt | Rows 4-5 | Spec/engine tests | None yet. |
| 12 | planned | Native file associations | Rows 6 and 11 | Platform + GUI contracts | Three-host open/restore tests, including LaunchServices. |
| 13 | planned | URL protocols | Row 12 | Argument-bound launch tests | Three-host protocol activation. |
| 14 | planned | Component schema/compiler | Rows 11-13 native-integration receipt baseline | Spec/compiler tests | None yet. |
| 15 | planned | Component selection plan/receipt | Row 14 | Engine/JSONL contracts | Update/repair and removed/renamed-ID fixtures. |
| 16 | planned | Setup/Studio component Modify UX | Row 15 | GUI contracts | Three-host atomic add/remove/update/repair matrix. |
| 17 | planned | Global prerequisite predicates and declarative conditions | Existing manifest/host preparation | Spec/engine/CLI tests | Host runtime fixtures. |
| 18 | planned | Version, instance, channel and shared-dependency policy | Rows 9 and 15 | Engine transition/refcount tests | Major/minor/channel/side-by-side fixtures on three hosts. |
| 19 | planned | Component-scoped prerequisites | Rows 15 and 17-18 | Spec/engine tests | Selected/unselected component fixtures. |
| 20 | planned | Signed prerequisite chain core without reboot continuation | Rows 17-19 | Planner/cache/receipt tests | Ordered/DAG apply, offline layout, source repair and partial failure; reboot resumes in row 29. |
| 21 | planned | Updater trust policy and threat model | Row 18 plus existing publisher rotation | Policy model/attack tests | Freeze, rollback, mix-and-match, expiry, clock and key-compromise fixtures. |
| 22 | planned | Secure updater metadata | Row 21 | Parser/signature/fuzz tests | None yet. |
| 23 | planned | Resumable verified downloader and cache policy | Row 22 | HTTP/cache integration tests | Proxy/offline host lanes. |
| 24 | planned | Update UI/automation handoff | Row 23 | GUI/JSONL contracts | Downloaded end-to-end update matrix. |
| 25 | planned | English/Russian locale catalogs | Rows 16-17 and 24 stable Setup screens | Renderer contract tests | Native long-text/fallback/persistence smoke; full AT matrix in row 39. |
| 26 | planned | Running-application and locked-file coordination | Row 9 maintenance identity | Engine/platform tests | Windows Restart Manager plus Unix/macOS process fixtures. |
| 27 | planned | Services/daemons | Rows 5 and 26 | Engine/platform tests | Three-host service lifecycle. |
| 28 | planned | Environment/PATH | Row 5 previous-state pattern | Engine/platform tests | Three-host shell/session checks. |
| 29 | planned | Authenticated reboot continuation | Rows 20 and 26 | Windows focused tests | Prerequisite/install restart-resume VM matrix. |
| 30 | planned | Diagnostics/support bundle/self-check and bounded log lifecycle | Row 10 exit/error taxonomy | CLI/privacy/ACL/quota/rotation tests | Failed-operation export/retention/uninstall workflow on three hosts. |
| 31 | planned | Executable AI/CLI docs conformance plus roadmap structural lint | Rows 10 and 25 stable public methods/copy | Extracted examples/schemas plus UTF-8 LF, no BOM/replacement/C0-C1, balanced fences, heading order, table widths, contiguous queue IDs/dependencies and exact status-enum tests | Fixed-fixture public commands on three hosts. |
| 32 | planned | Support and compatibility policy | Current native matrix plus rows 8-10 | Policy/schema fixture tests | Published OS/distro/libc/CPU/EOL and upgrade-from matrix. |
| 33 | planned | Linux runtime blocker removal | Current separate Tauri workspace | Final-lock advisory, exact ACL and CSP tests | Remove `glib 0.18.5`/`RUSTSEC-2024-0429`; rerun packaged helper/polkit, no-`unsafe-inline` production CSP and standalone packager lanes. |
| 34 | planned | Pinned release foundation, process-image-bound Windows trust, signing handoffs, SBOM/license/provenance and separate Studio/Setup contracts | Rows 1-33 | xtask/release/trust contract tests | Credential-free dry-run, `ProcessImageFileMapping` proof and externally signed prerelease on current native matrix. |
| 35 | planned | Studio update and support lifecycle | Rows 21-24 and 34 | Studio feed/policy/rollback tests | Independent downloaded Studio update, failure rollback, support window and generated-installer isolation on three hosts. |
| 36 | planned | Debian/RPM repository metadata and signing lifecycle | Rows 8 and 34 | Repository metadata/verifier tests | apt/RPM publish, trust-anchor rotation, install/update/remove/rollback and downloaded verification. |
| 37 | planned | Streaming RPM writer and large-package closure | Rows 8 and 34 | Container/parser/memory tests | 1 GiB/25k-file `.deb` and RPM build/install within budgets. |
| 38 | planned | Benchmark harness and enforced budgets | Rows 34 and 37 | Deterministic benchmark tooling | Pinned named-host median/p95/output/RSS baselines. |
| 39 | planned | Repository threat model, fuzz/fault/compatibility/accessibility hardening | Rows 1-38 | Threat model, corpus/property/contract gates | Three-host fault plus named UIA/VoiceOver/AT-SPI matrices. |
| 40 | planned | Signed exact-byte release candidate, two independent source-first reviews and review-of-review | Rows 34-39 | Final-diff security/release gates | All blockers closed; separate downloaded signed Studio and generated-installer RC matrices. |
| 41 | planned | GitHub Release publication, redownload and rollback rehearsal | Row 40 | Release dry-run tests | Public assets, signatures, hashes, layouts and deployment rollback reverified after download. |
| 42 | planned | Additional architecture enablement | 1.0 x64/Apple-Silicon baseline | Target-specific focused gates | Windows ARM64, Linux ARM64 and macOS Intel native final-byte lanes. |

## Dependency graph

```text
entrypoint + receipts
  └─ authenticated product identity
      └─ shortcuts
          └─ external-artifact WAL + native-integration receipt pattern
          ├─ installed maintenance launcher + OS inventory
          │   └─ fleet plan/result/exit contract
          ├─ associations ── URL protocols
          ├─ components ── prerequisites
          ├─ services/daemons
          └─ environment/PATH

maintenance identity + operation lifecycle
  └─ running-application/locked-file policy
      └─ authenticated reboot continuation

publisher signing + rotation
  └─ updater trust policy + threat model
      └─ signed updater metadata
          └─ resumable verified download
              └─ staged rollout ── deltas/downloadable components

stable Setup screens
  └─ localization + accessibility freeze
      └─ 0.10 hardening RC

stable error/exit taxonomy
  └─ diagnostics/support bundle + benchmark evidence
      └─ 0.10 hardening RC

all explicitly listed 1.0 gates + signing + supply-chain + native evidence
  └─ 1.0 production
```

## Production scorecard

Maintain this table in every release-readiness review. Evidence must name an exact commit/run/artifact; `planned` is never green.

| Gate | Current preview | RC requirement | 1.0 requirement |
| --- | --- | --- | --- |
| Core transactional lifecycle | Implemented and source/native-smoke tested | Full fault matrix | Downloaded final-byte matrix |
| Durable maintenance and fleet automation | Original Setup/CLI needed; coarse headless exits only | Native uninstall/repair entry, plan/result JSON and deployment matrix | Downloaded Setup can be deleted; maintenance and automation remain verified |
| Product identity and desktop integrations | Schema 5/receipt v7 identity core exists; native consumers, shortcut publication, associations and component Modify remain incomplete | Product identity, shortcuts, associations/protocols, components and conditions frozen with three-host rollback evidence | Downloaded assets preserve exact native identities and compatibility fixtures |
| Managed OS integrations | Running-app/reboot, services and environment/PATH are planned | Locked-file/reboot continuation, service/daemon and environment ownership matrices green | Downloaded final-byte lifecycle and rollback evidence |
| Windows signed release | Source flow exists | Signed RC lifecycle | Signed downloaded release verified |
| Linux release | Blocked by GTK advisory; current containers still expose tool-level identity | Advisory removed + product-derived lifecycle + distro integration | Downloaded `.deb`/`.rpm`, signed repository metadata and installed update/remove/rollback reverified |
| macOS release | Source flow exists | Signed/notarized Apple-Silicon RC | Downloaded stapled Apple-Silicon DMG verified; Intel remains post-1.0 until evidenced |
| Shortcuts/associations/components/prerequisite chain/updater | Shortcut schema/receipt/authoring/review partial; remaining capabilities planned | Complete and frozen, including reboot continuation | Compatibility evidence |
| Localization/accessibility | Russian presentation baseline | English/Russian + automated/manual matrix | Release checklist green |
| Fuzz/fault/security reviews | Strong focused tests, incomplete portfolio | Full portfolio, no blockers | Repeat on final diff/bytes |
| Performance budgets | No authoritative baseline | Baseline + budgets met | Regression comparison published |
| SBOM/provenance/reproducibility | Partial checksums/evidence | RC artifacts carry reports | Downloaded public assets reverified |
| Documentation/AI compatibility | Live help drift test exists | All feature docs synchronized | Release docs and skill versioned |
| Supported CPU architectures | Windows/Linux x64 and macOS ARM64 are the current native matrix | Same three architectures on signed RC bytes | Same three architectures; Windows/Linux ARM64 and macOS Intel stay post-1.0 until separately evidenced |
| Studio distribution | Unsigned development assembly exists | Signed platform-native Studio RC, independent updater/support/rollback policy and final-byte report | Downloaded Studio assets independently updated and reverified from generated installers |

## Release decision rules

- A capability is not shipped because its schema compiles; it needs final native behavior and rollback proof.
- A platform is not supported because another OS passed or a cross-compile succeeded.
- A GitHub Actions artifact is not a release; production requires GitHub Release assets downloaded and reverified.
- Unsigned output is always a development/prerelease artifact.
- A known security advisory in a shipped runtime blocks production rather than receiving a silent ignore.
- A failed neighboring test invalidates reused matrix evidence.
- Performance and accessibility regressions are release defects, not post-release polish.
- Every milestone ends with independent review, review-of-review, concise before/after value, exact gaps and runnable rollback.
- A capability-matrix status is one of `implemented`, `partial`, `blocked`, `planned`, or `deliberate no`; evidence and limitations live in separate text rather than inventing a percentage.

## Architecture and build optimization backlog

The architecture direction is correct, but several composition modules are now expensive to review. Sizes are the 2026-08-09 working-tree snapshot and are approximate:

| Hotspot | Current size | Planned ownership split |
| --- | ---: | --- |
| `apps/luxury-cli/src/stdio.rs` | ~4.5k lines | project authoring, lifecycle operations, wire types, and server loop modules inside the CLI crate |
| `xtask/src/runner.rs` | ~3.3k lines | assembly, project packager, lifecycle smoke and evidence modules; platform container modules stay separate |
| `crates/luxury-platform/src/local/mod.rs` | ~2.7k lines | install adapter, uninstall adapter, receipt store and shared local policy modules |
| `apps/luxury-installer/src-tauri/src/setup.rs` | ~2.6k lines | bootstrap/review, operation lifecycle, completion actions and contract tests |
| `crates/luxury-platform/src/local/transaction.rs` | ~2.5k lines | journal codec, recovery, durability primitives and lock/rename operations |
| `apps/luxury-installer/src-tauri/src/studio.rs` | ~1.9k lines | recent projects, authoring commands, native build orchestration and validation |

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

The target is always the existing receipt-owned entrypoint. Projects without an entrypoint cannot enable shortcuts. The engine plans the exact native artifacts; platform adapters create them transactionally; the receipt owns their published identity while WAL v5 owns crash-recoverable external staging/restoration; Setup offers only the two author choices already authenticated in the package. This narrow shape covers the common Inno/NSIS use case without introducing arbitrary commands, arguments or paths.

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
- Queue row 31 adds CI validation for UTF-8/Markdown structure, replacement characters, ambiguous dependency punctuation and unknown capability statuses; until it lands, reviews run the equivalent local check explicitly.
- Issues/PRs reference the workstream, milestone and queue row, but source/docs remain authoritative for live behavior.
- Quarterly or before a release candidate, refresh competitor/platform references and reassess whether excluded formats or integrations have real demand.
- New ideas enter after evidence of user value, threat-boundary analysis, rollback ownership and native verification cost—not because another installer exposes a directive.

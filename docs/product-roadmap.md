# Product roadmap: from secure core to a complete installer

Luxury Installer already has the hard part that many script-first installers bolt on later: verified packages, transactional mutation, recovery, ownership receipts, strict unattended operation, native artifacts, and one Studio/CLI contract. The next stage is not to clone every Inno Setup or NSIS directive. It is to add the common product capabilities people actually need while keeping each OS mutation typed, reversible, and visible in Studio.

This roadmap compares the current checkout with the documented surfaces of Inno Setup 6, NSIS 3, WiX/Burn, Advanced Installer, and InstallBuilder. It is a planning baseline, not a release claim. Update the matrix when a capability ships or its product decision changes.

Reference surfaces reviewed for the comparison:

- [Inno Setup Help](https://jrsoftware.org/ishelp/) — Icons, Tasks, Components, Registry, Run/UninstallRun and silent command-line contracts;
- [NSIS 3 Scripting Reference](https://nsis.sourceforge.io/Docs/Chapter4.html) — Sections, shortcuts, registry, execution, reboot, compression, language and silent-install primitives;
- [WiX Toolset documentation](https://docs.firegiant.com/wix/) — MSI packages plus Burn bundles, prerequisites, dependency and rollback orchestration;
- [Advanced Installer User Guide](https://www.advancedinstaller.com/user-guide/) — GUI-authored shortcuts, associations, services, prerequisites, updates, environment, localization and enterprise deployment surfaces;
- [InstallBuilder product overview](https://installbuilder.com/) — cross-platform components, downloadable components, desktop integration, text/silent modes and DMG workflows.

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

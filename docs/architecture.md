# Architecture

Luxury Installer combines hexagonal Rust boundaries with small vertical slices and a separate Tauri 2 presentation workspace. This is a functional development architecture, not a completed native release architecture.

## System topology

```text
┌────────────────────── Tauri desktop process ──────────────────────┐
│ React renderer                                                    │
│   │ exact invoke/event contracts                                  │
│   ▼                                                               │
│ Rust Tauri shell                                                  │
│   ├─ native dialogs + window lifecycle                            │
│   ├─ bound project/package/path authority                         │
│   ├─ luxury-system-roots ── completed system reveal               │
│   ├─ strict public error mapping                                  │
│   └─ bounded backend client                                       │
└───────────────────────────────┬────────────────────────────────────┘
                                │ JSONL protocol v3
                                │ inherited stdin/stdout
┌───────────────────────────────▼────────────────────────────────────┐
│ luxury stdio / human CLI composition root                         │
│   ├─ luxury-bundle ── luxury-compiler                             │
│   └─ luxury-engine ── ports ── luxury-platform ── system-roots    │
│              └──────────── luxury-spec ───────────────┘            │
└────────────────────────────────────────────────────────────────────┘
```

The React renderer owns presentation and accessibility. The Rust Tauri shell owns native dialogs, renderer capability boundaries, child-process lifecycle, path authority, transport validation, and public error mapping. The `luxury` backend owns package verification and installer policy. No TypeScript path decides whether a transition, rollback, receipt, or platform mutation is valid.

The desktop bootstrap also fails closed before creating a webview when the process token/effective UID is elevated. Windows windowless artifact verification additionally launches the exact packaged backend through the bounded mutual-PID named-pipe probe described in [privileged-helper.md](privileged-helper.md); explicit manual QA can add `runas`, a retained process handle and independent `TokenElevation` checks without creating a webview. Windows system install/uninstall/launch use that authenticated action-separated helper. Launch checks the system receipt/executable there, then creates the application with a duplicated, verified unelevated Tauri token rather than helper elevation. Signed final-byte lifecycle evidence remains open. Running the renderer or generic stdio backend as Administrator/root remains forbidden.

`luxury-windows-trust` is the narrow shared native adapter for embedded WinTrust validation. Path verification keeps a no-reparse single-link executable handle open without write/delete sharing. Running-peer verification additionally passes that handle to `NtQueryInformationProcess(ProcessImageFileMapping)`, so WinTrust evaluates the file object that actually created the process rather than a replacement now occupying its old pathname. Before an authenticated UAC launch, Tauri holds the exact helper path, compares its verified leaf certificate with the running launcher's process-image-bound identity, and retains the guard through `ShellExecuteExW`; the elevated helper repeats running-peer verification after startup. The adapter returns only a SHA-256 identity of the verified leaf-certificate DER; callers compare exact identities instead of trusting publisher display names, caller pins, hashes without a valid chain, or catalog-only signatures. A release Setup shell is also compiled with one exact reviewed package fingerprint supplied by `xtask`, and rejects payload drift before elevation.

Windows system authorization transfers file authority, not a path. The Tauri shell pins a non-reparse single-link package handle; after kernel PID and Authenticode checks the helper duplicates it from the authenticated parent, validates the exact package/action/host/system scope, and derives Known Folder roots itself. The same authenticated channel runs `prepare_system_install` read-only during system bootstrap and retry, so repair/update/uninstall availability comes from the real protected receipt instead of a fabricated fresh-install state. The engine exposes explicit system constructors for the privileged composition root; existing constructors remain user-only, so ordinary CLI/stdio cannot reinterpret system receipts.

Closing Setup is part of the transaction contract. Every Setup action acquires one startup gate and then rechecks close-state, so close cannot pass an operation that has not yet published `active`. Rust waits for `starting -> active`, requests cooperative cancellation for the active user or system install/uninstall, waits for its correlated terminal rollback/cleanup signal, and only then closes the backend and window. Repeated native close requests remain prevented while shutdown is active; a separate `close_ready` gate permits only the final Rust-initiated close after cleanup. One bounded budget starts before the bootstrap-state mutex and also bounds the user-operation cancel request; timeout leaves the window/process alive for a later retry instead of abandoning a mutation.

Interactive Setup cancellation remains a running-state request until Rust emits the correlated terminal event. A Tauri cancel transport failure clears only the pending-cancel UI flag, preserves the active install/uninstall state, renders the bounded public error inline, and permits another request; it never fabricates cancellation or rollback completion.

The completed Setup surface owns one serialized presentation boundary for launch, reveal, finish-link, and close actions. Failures remain inline without replacing the authenticated installation result. Launch success is recorded before the separate close request; if close fails, launch authority is withheld from the renderer for the rest of that completed state and only pathless close/reveal/link actions remain.

## Workspace and dependency rule

The core workspace is rooted at [`Cargo.toml`](../Cargo.toml):

```text
luxury-bundle   ─→ luxury-spec
luxury-engine   ─→ luxury-spec
luxury-compiler ─→ luxury-bundle + luxury-spec
luxury-system-roots ─→ fixed host OS roots only
luxury-platform ─→ luxury-bundle + luxury-engine + luxury-spec + luxury-system-roots
xtask + standalone Tauri shell ─→ luxury-process
standalone Tauri shell ─→ luxury-system-roots
luxury (CLI / stdio) ─→ compiler + bundle + platform + engine + spec
```

- `luxury-spec` knows only platform-neutral types and invariants.
- `luxury-bundle` owns deterministic package layout and the archive trust boundary.
- `luxury-engine` owns commands, events, outcomes, use-case order, and ports.
- `luxury-platform` owns filesystem/OS adapters, transactional state, recovery, and native launch.
- `luxury-system-roots` owns only fixed system install/state roots: Known Folders on Windows and constants on Linux/macOS. It has two real consumers—`luxury-platform` and the standalone Tauri shell—so reveal and privileged mutation cannot drift to different roots.
- `luxury-compiler` owns safe project scanning, validation, and `.luxpkg` assembly; its `authoring` vertical slice owns atomic settings updates, bounded additive import, staged whole-payload replacement with rollback, and payload-path resolution instead of growing the crate root. Bundle output is written and synced through a same-directory `NamedTempFile`, rejects an existing link/reparse/non-file target, and uses the dependency's platform-native atomic replace instead of a check-then-rename backup namespace.
- `luxury-process` owns only bounded descendant-process containment: suspended Windows Job Object attachment and Unix process groups. It contains no package, UI, or build policy and is shared by `xtask` and the standalone Tauri shell.
- `luxury` is the human CLI and machine-facing `luxury stdio` composition root.
- `xtask` owns repository gates, native runner assembly, smoke orchestration, and evidence validation.

[`apps/luxury-installer/src-tauri/Cargo.toml`](../apps/luxury-installer/src-tauri/Cargo.toml) is deliberately excluded from the root workspace. It is a standalone Cargo workspace with its own committed `Cargo.lock`. This keeps Tauri and its platform graph out of `cargo quick` while retaining a reproducible locked desktop build.

Dependencies point toward policy. The shell may expose a Rust outcome; it may not recreate that outcome in UI code.

## Vertical slices

Every product change follows the smallest complete route:

```text
spec → use case → adapter → CLI/GUI
```

Current slices:

1. `bundle`: build, open, and verify deterministic packages.
2. `install`: read-only preparation, authoritative recheck, recovery, capacity preflight, stage, publish, receipt commit, or rollback.
3. `uninstall`: receipt-driven removal with modified/unknown-file preservation and aggregate public results.
4. `launch`: exact receipt-owned entrypoint verification and direct native spawn without shell, arguments, or protocol streams.
5. `Studio`: typed unsigned-v1 settings, Rust-owned create/open/import/replace/entrypoint/save dialogs, active-folder reveal, project reload/validation, and build; renderer never supplies native paths.
6. `Setup`: one bootstrap-bound payload, Rust-owned destination/state/identity, install/update/repair/recovery, cancellation, maintenance uninstall, reveal, and explicit launch.
7. `native runner`: host-only unsigned-v1 assembly, fixed resources, packaged verification, no-clobber publication, smoke lifecycle, and evidence schema v2.

Upgrade and same-version repair reuse the install use case. There is no parallel policy implementation. A slice remains one readable module until size or ownership makes a split useful; empty layering and one-implementation factories are not architecture.

## Tauri desktop boundary

### Modes

- A debug build without `--package` starts **Studio**.
- A debug build with one absolute `--package` starts **Setup**.
- Default release feature `studio` starts payload-free **Studio** with a fixed backend resource.
- Mutually exclusive release feature `setup` starts **Setup** and resolves one fixed backend/payload resource pair.
- `--trusted-publisher-key` and `LUXURY_BACKEND_PATH` are accepted only in debug builds and require absolute paths.
- `--verify-runner` removes configured windows before runtime startup and exits with an exact machine-readable verification result.
- `--verify-studio` does the same for the payload-free Studio artifact.

Studio dialogs run in Rust. The renderer requests pathless create/open/import/replace/entrypoint/reveal/reload/build/cancel-build actions and submits only strictly typed portable settings. One exact `get_studio_host` command returns validated Rust defaults so presentation can disable an impossible local OS/architecture build without browser platform guessing; the Rust `build_project` host comparison remains authoritative. The primary build action applies native form validity and, when settings are dirty, awaits the existing `updateProject` validation before sending the separate pathless `buildProject` intent; a rejected save cannot reach the output dialog or packager. The shell derives a bounded cross-platform output suggestion from the validated product name and falls back to package ID only when the display name has no usable alphanumeric characters; renderer never supplies a filename or path. Native-build cancellation is registered in Rust before the blocking dialog/worker starts and uses one atomic `idle -> active -> cancelled` lifecycle shared with close and process supervision; a successful late publication wins the race, while a confirmed cancellation returns the renderer to its validated project. The visible elapsed clock is presentation-only: a monotonic browser timer starts and stops with the `building` state, formats hours without inventing native stages, and stays outside assistive live announcements. A bounded six-entry recent list is persisted atomically under app config; renderer receives display data and reopens only by index, then Rust repeats `validateProject` before activation. The shell retains the authoritative active project and every native source/output selection; `luxury stdio` routes settings and payload mutations to `luxury-compiler`. Additive imports publish without overwrite and roll back partial publication. Whole-payload replacement copies the selected directory contents into same-project staging, validates and rechecks the complete current/candidate trees, swaps the tree, atomically updates executable/entrypoint config, and restores the prior tree on ordinary failure; a rollback failure keeps the staging backup instead of deleting it. The intended loop is `create/open/recent → edit settings → add or replace payload → select entrypoint → save or save-and-build → native build`. Signed v2/v3 authoring stays in the human CLI because private keys enter only through bounded stdin.

Unsaved Studio settings cannot be replaced by create/open/reload; the explicit undo restores the last Rust-validated baseline. Native close and Alt+F4 remain under the Rust close gate: Rust emits one correlated `luxury://studio-close-query`, accepts only matching `respond_studio_close`, treats a missing or invalid response as dirty, and owns the native discard confirmation without granting renderer dialog authority.

Project summaries return an executable-file count instead of every path, keeping one JSONL frame bounded at the maximum manifest size. When Studio omits `updateProject.executable`, the compiler preserves explicit executable intent, adds a changed Unix entrypoint, and removes the previous marker only if that old file is gone; an AI client may still provide the full array to replace it deliberately.

Setup is not a package browser. The shell binds one package path, fingerprint, package ID, state root, selected install base, latest Rust preparation, and authenticated finish links. Renderer calls for destination, install, uninstall, cancel, reveal, launch, and finish-link opening do not carry package/root/entrypoint/URL authority; a finish link is selected only by bounded index. After a verified terminal install/update/repair, user reveal uses the Rust-retained selected path and system reveal derives the same fixed install root used by the privileged adapter through `luxury-system-roots`; both remain disabled before completion and while another Setup action is active. A chooser or drag-and-drop replacement would violate the product boundary.

The final bound launcher also exposes one windowless deployment surface: read-only `--info-json`, `--unattended-install` with explicit unsigned/license/publisher-migration consents, idempotent `--unattended-uninstall`, and `--help`. Argument parsing and the existing Rust backend/helper composition run before Tauri is constructed, so Linux needs neither `DISPLAY` nor GTK initialization. Info mode calls only bound-package loading: it verifies the compiled fingerprint, backend output, and host target without constructing `SetupContext`, preparing an installation, or requesting system authorization, then emits one bounded JSON line without license text, finish URLs, package paths, or native roots. It may run inside an already elevated MDM context but never requests elevation; mutating unattended commands remain unelevated and use the authenticated helper for system scope. Every mode uses the compiled payload binding and host-native defaults; argv cannot supply paths, keys, downgrade approval, launch intent, environment, or commands. Windows NSIS starts the inner Rust runner directly without a command shell, forwards raw arguments without interpreting authority, preserves inherited stdout/stderr for automation, waits for cleanup, and returns the exact child exit code. Project assembly and final signed-container verification execute `--info-json` through that outer NSIS boundary and reject channel/schema/fingerprint drift.

### Capability and webview policy

[`capabilities/main.json`](../apps/luxury-installer/src-tauri/capabilities/main.json) grants only:

- core event listen/unlisten;
- native window dragging;
- the named application commands generated by the Rust shell.

It grants no generic renderer access to shell execution, filesystem, dialog, opener, or process APIs. Native dialogs and opener operations are invoked inside Rust commands. The production CSP permits local assets and Tauri IPC only; the loopback Vite/WebSocket origins exist only in `devCsp`. Window drag-and-drop is disabled.

Tauri invoke inputs, event payloads, and JSONL values use strict typed contracts. Backend errors may contain local paths or platform detail, so only stable code-to-public-message mappings cross into the renderer.

## JSONL backend protocol

The Rust Tauri shell starts `luxury stdio` with piped stdin/stdout/stderr. Human diagnostics belong on stderr. Stdout is one bounded JSON object per line and nothing else:

```json
{"protocolVersion":3,"id":"request-1","method":"defaults","params":{}}
```

Protocol v3 methods are `defaults`, `initProject`, `validateProject`, `updateProject`, `importPayload`, `resolvePayloadPath`, `buildProject`, `inspect`, `prepareInstall`, `install`, `uninstall`, `launch`, and `cancel`. `importPayload.replace=true` requires one source directory and replaces its contents as the payload root; omitted/false preserves additive no-overwrite import.

Boundary rules:

- request IDs, protocol version, methods, params, tagged results, errors, and events are validated on both sides;
- absolute paths exist only at the Rust shell/backend boundary, never as Setup renderer authority;
- JSONL lines are bounded; the Tauri client also bounds pending requests, gives cancellable ordinary operations five minutes plus a 30-second terminal grace, and keeps launch timeout-free to avoid post-spawn ambiguity;
- stdout reader EOF or invalid output fails pending work and reaps/terminates the child instead of leaving an orphan;
- shutdown closes stdin, drains pending requests with a stable error, waits briefly, then terminates if necessary;
- install/uninstall operation events are correlated to the active operation before being emitted to the renderer;
- `launch` returns successful process creation only and is not cancellable after spawn;
- `prepareInstall` is advisory and read-only; real install reopens, reauthenticates, recovers, reassesses, and rechecks before mutation.

The backend keeps one latest progress frame behind its bounded ticker and flushes it before action/phase/result/error. The Tauri shell validates counters and emits correlated events; renderer state never receives an unbounded per-file queue.

`luxury stdio` accepts at most one external `--trusted-publisher-key <absolute SPKI PEM>` when the child is created. Private signing material and claimed publisher identity never enter JSONL.

## Package and trust model

- `.luxpkg` v1/v2/v3 share a deterministic gzip/tar layout with `META/manifest.toml` and content-addressed objects under `objects/sha256/<digest>`.
- Package `format_version` and manifest `schema_version` evolve independently.
- Schema v2 adds one optional exact-file `install.entrypoint`. Windows requires `.exe`; Linux/macOS require `executable=true`. Arguments, environment, automatic run, and generic actions do not exist.
- Schema v3 adds one optional authenticated `package.license` plain-text agreement. It is bounded to 16,384 Unicode characters / 64 KiB UTF-8 and rejects unsafe controls and bidi overrides. Install requires caller consent before package verification or platform access; CLI, JSONL, Tauri, and renderer validate that contract independently.
- `install.show_install_log` and `install.finish_links` are optional presentation policy with byte-compatible omitted defaults. The same bounded details projection is available during installation as an authenticated plan with factual counters and after completion as the result; it is capped at 128 relative paths plus an omitted count and never contains backend logs. At most four credential-free HTTPS links are accepted; generic commands, schemes, auto-run, arguments, and environment mutation remain forbidden.
- Logical paths are portable forward-slash relative paths, at most 512 UTF-8 bytes overall and 255 bytes per component. Absolute, parent, UNC, device, ADS, empty/dot, backslash, NUL, device-name, and trailing-dot/space forms are rejected.
- The reader rejects missing, extra, duplicate, linked, special, hash-mismatched, size-mismatched, and trailing compressed content.
- V1 hashes provide integrity only and require explicit unsigned consent.
- V2 authenticates the exact manifest through Ed25519 and an external matching SPKI trust anchor.
- V3 adds an authenticated A→B publisher proof. It requires installed trusted A and strictly greater SemVer precedence; fresh, legacy, unsigned, replay, equal, downgrade, and self-rotation paths fail closed.
- Ownership receipt v4 stores payload signer, authorized publisher, and optional entrypoint. Legacy receipts remain readable but cannot invent entrypoint authority.

Package authentication and native artifact signing are separate. A key stored beside a payload in the same unsigned mutable runner is not a trust anchor. Therefore assembled runners accept unsigned v1 only until the native container has a verified external signing boundary.

## Transaction contract

```text
verify → preflight → lock → journal → stage+sync → backup/atomic publish → receipt → commit
                                      └────────── reverse on error/cancel
```

Read-only preparation authenticates the package, detects pending state, reads the receipt, assesses the transition, checks native write access at the nearest existing destination/state ancestors, and measures capacity without creating roots, locks, journals, or cleanup. Install independently repeats authentication and all authoritative checks before mutation.

For a licensed package, `acceptLicense` is explicit caller authority, never package data. The engine fails before the install port when it is false; Tauri also rejects acceptance when no license was offered. The receipt does not persist a fabricated legal claim—each install/update/repair/recovery invocation must carry current-session acceptance again.

Package and destination locks use a fixed order. Platform envelope v2, ownership receipt v4, and journal v4 bind state to package/destination/install-base identity and exact install scope; legacy journal v2/v3 is user-only. Install and state roots may live on different filesystems: payload publication occurs on the install volume and receipt cutover on the state volume.

Private-state policy is explicit adapter authority, never inferred from elevation or path. Windows user state grants only the exact user, SYSTEM, and Administrators; system state requires elevation and grants/owns only SYSTEM or Administrators. Linux/macOS user state is owned by the effective user, while system state requires root ownership; directories/files are `0700`/`0600`.

New bytes are written and verified in private transaction storage before atomic no-clobber publication. Destructive actions are journaled first. A committed ownership receipt lives outside the removable installation tree. Error/cancel paths reverse journaled changes; recovery validates the journal and physical state before its first mutation.

Uninstall removes only owned files whose content and Unix executable mode still match. Unknown or modified data is preserved. Receipt-bound uninstall recovery rejects legacy/unbound authority before changing installed payload or ownership state.

All production no-clobber renames return a must-use durability token:

- Linux/macOS use descriptor-relative no-follow parents, atomic no-replace rename, and destination/source parent sync;
- Windows uses write-through no-clobber rename and handle-bound verification/deletion where implemented;
- unsupported atomic semantics fail closed; there is no check-then-rename fallback.

Capacity preflight uses the nearest existing real ancestor and caller-visible free space, groups requirements by filesystem identity, and adds bounded journal/receipt/metadata/headroom estimates. It is a snapshot, not block reservation, and the mutating path repeats it under locks.

## Native runner and evidence

`cargo studio-assemble` builds a payload-free authoring artifact for the current host together with a Rust packager and payload-free Setup template. Windows also embeds the exact SHA-256-pinned NSIS archive. Linux enables its small `standalone-linux-packager` feature only for that release sidecar: existing `tar`/`flate2` plus narrow `ar`/`rpm`/`cpio` crates create and independently parse the two native containers without Cargo, Node, Tauri CLI, or system package tools at runtime; routine `cargo quick` does not compile them. Studio spawns that packager through `luxury-process`: Windows creates it suspended, attaches a kill-on-close Job Object, then resumes its exact primary thread; Linux/macOS create a dedicated process group. Manual cancel, timeout, spawn/setup failure, and even normal primary exit terminate/reap the complete descendant tree before Studio reports a result. For Studio builds, the Rust shell creates one unpredictable empty work directory directly under the selected output parent, passes only that exact sibling to the hidden packager entrypoint, and removes it after descendant reaping; xtask rejects a linked, non-empty, wrongly named, or out-of-parent directory and never scans user-writable prefixes. `cargo project-installer -- <project> <native-output>` compiles `.luxpkg` only inside a temporary work tree, materializes exactly one fingerprint slot in that template, repeats runner/container verification, and publishes only `.exe`, `.deb` + `.rpm`, or `.dmg`. `cargo assemble -- <package.luxpkg>` remains the low-level bound Setup gate. On Linux/macOS assembly additionally publishes deterministic `.tar.gz`; the Rust adapter rejects links/special entries and opened-file identity/mode drift, preserves only executable intent, normalizes modes/owners/timestamps, syncs the archive, and publishes without overwrite. Linux stages its exact helper/polkit policy; macOS stages its exact helper/LaunchDaemon plist and 13.0 deployment floor. Studio sidecars are exact-layout/hash checked but an unsigned portable Studio does not cryptographically bind them to the launcher. This is transport preservation, not signing or hostile same-user parent-path binding. Setup assembly:

1. validates one explicit unsigned-v1 package and host target;
2. builds the dist `luxury` backend;
3. runs the isolated renderer/Tauri gate;
4. builds the standalone Tauri release shell using `src-tauri/Cargo.lock`;
5. stages fixed backend/payload resources with no trust resource;
6. verifies source/resource hashes and package identity through the packaged backend;
7. runs the windowless packaged `--verify-runner` entrypoint;
8. publishes once under ignored `dist/` without overwrite, including the Unix mode-preserving archive where applicable.

On native Linux, `cargo linux-packages -- <package.luxpkg>` reuses that verified Setup executable and resources, then delegates only container generation to the pinned Tauri CLI. That bundler changes one fixed-width Tauri bundle-type marker from `UNK` to `DEB` or `RPM`; Rust independently derives the two exact launcher hashes, requires exactly one source marker, and rejects every other byte change. The gate extracts both containers, requires an exact link-free file set, root ownership, `0755` executables, `0644` data, fixed helper/policy destinations, exact content hashes, no install scripts, required polkit/WebKit/GTK dependencies, and a pathless desktop entry. Publication is no-clobber and includes path-free provenance. The output is deliberately unsigned and makes no reproducibility or installed-lifecycle claim.

On native macOS, release verification additionally requires exact signed-bundle structure, branded `icon.icns` bound by `Info.plist`, app/helper designated requirements, strict nested codesign, Gatekeeper, stapled notarization, backend package inspection, and the windowless Tauri runner probe. `cargo macos-dmg -- <signed.app>` copies that verified app with native metadata preservation, creates a compressed HFS+ image, mounts it read-only, allows only the app and exact `/Applications` link, and reverifies the app before publishing unsigned development provenance. After external DMG signing/notarization/stapling, `cargo verify-macos-dmg -- <signed.dmg>` repeats image, Gatekeeper, ticket, layout, and app verification. Credentials remain outside the repository and commands.

`cargo runner-smoke` uses disposable host-native packages to gate normal lifecycle, foreign-file preservation, receipt/transaction cleanup, cancellation rollback, receipt-owned launch, and bounded process-crash recovery paths before evidence publication. Cleanup is part of the gate.

Evidence schema v2 contains no timestamp, absolute path, secret, or signature. License-denial/no-roots, recovery, cancellation, and launch gate publication but are not separate claims. The file records:

- exact target triple/OS/architecture;
- shell `{kind: "tauri", version: "2.11.5"}`;
- package identity/fingerprint;
- backend, payload, frontend-tree, and launcher SHA-256;
- normal lifecycle counters;
- explicit backend inspect/install, installed-byte, foreign-preservation, uninstall, receipt/transaction cleanup, Tauri-entrypoint, and temp-cleanup checks.

Recovery, cancellation, and receipt-owned launch gate the producing command but are not separate schema-v2 claims. The JSON is an unsigned verification receipt, not provenance attestation, native signing, or proof of another host.

The exact combined set is currently Linux/Windows x86_64 plus macOS ARM64. `verify-evidence-set` rejects extra/missing files, wrong host labels, malformed fields, and inconsistent package identity. Workflow configuration is not runtime evidence; only successful downloaded artifacts prove a run.

## Build contract

- Rust `1.96.0`, Node.js `22.12.0`, and pnpm `10.26.2` are pinned/documented; frontend Node types use the same minimum runtime version.
- Bootstrap once with `pnpm --dir apps/luxury-installer install --frozen-lockfile`.
- `cargo quick --locked` exercises the root Rust workspace without Tauri.
- `cargo gui-check` runs renderer contracts, strict TypeScript, Vite production build, and locked standalone Tauri check.
- `cargo tauri-test` and `cargo tauri-clippy` are focused standalone-shell gates.
- `cargo ci` combines formatting, one locked quick gate, and the isolated desktop gate.
- `cargo full-test --locked` is the broad root-workspace release-candidate gate, not the default loop.
- `cargo dist` builds the host backend plus checked frontend; it does not produce a signed native installer.
- `cargo linux-packages -- <package.luxpkg>` is a native-Linux-only release-tooling gate for inspected unsigned `.deb`/RPM development containers; it is not part of `cargo quick` or `cargo gui-check`.
- `cargo macos-dmg -- <signed.app>` and `cargo verify-macos-dmg -- <signed.dmg>` are native-macOS-only container gates; they require already signed/notarized input and never own credentials.
- `cargo verify-windows-signers -- <launcher.exe> <helper.exe>` requires two embedded Authenticode chains and one exact leaf certificate; it does not sign either file.
- Windows release order is fixed: externally sign the inner Tauri launcher/backend with one leaf certificate, run `cargo windows-release-setup -- <signed-runner-dir> <nsis.zip>`, externally sign the emitted outer NSIS with that certificate, then run `cargo verify-windows-release -- <signed-setup.exe>`. Rust never receives signing credentials.
- Routine pull-request/main CI runs format, quick, desktop, and focused Windows `luxury-windows-trust + luxury-platform + luxury-system-roots + luxury-process` jobs separately.
- Manual CI runs full root tests, standalone Tauri tests, inspected unsigned Linux `.deb`/RPM generation, and host-native runner smoke on Linux/Windows x86_64 plus macOS ARM64, then verifies the exact schema-v2 set.
- Manual **Native project build** is a distinct user workflow: three checked-in target projects are canonicalized under checkout by a narrow Rust xtask wrapper, built on matching hosts in parallel, and uploaded with no-clobber Rust-generated SHA-256 manifests. It is development delivery, not release evidence.

One gate has one purpose. Do not repeat the same broad check without new code or evidence.

## Explicit ceilings

User and source-level system scope are implemented on all three hosts; renderer/Tauri invoke and generic JSONL never receive system roots, package file authority or entrypoint paths. The Rust shell may consume `luxury-system-roots` only for a pathless completed-install reveal. Windows uses the Authenticode-bound one-shot helper. Linux uses an installed root-owned helper, exact polkit policy, kernel credential-bound Unix datagrams and one passed package FD; receipt-owned launch opens the entrypoint beneath a retained no-follow install-root descriptor, drops credentials, `fchdir`s to that descriptor and executes `/proc/self/fd/N` without pathname fallback. macOS uses an SMAppService LaunchDaemon, audit-token designated requirements, socket-activated seqpacket and a package FD tied to the strictly validated signed app resource. Signed-final Windows proof, installed/distribution-signed Linux proof, and signed/notarized native macOS lifecycle proof remain unverified.

Windows receipt-owned launch rejects intermediate reparse components and retains every real parent directory without delete sharing through direct spawn or `CreateProcessWithTokenW`. Windows parent binding for other pathname mutations and general create/delete directory durability remain incomplete. Linux receipt-owned image and cwd are descriptor-bound, but pre-open real-directory substitution, other Unix source-leaf mutations and macOS launch/cwd remain pathname-bound. Mapped writers and hostile same-user namespace races outside the guarded launch paths remain. Native macOS/APFS power-cut behavior is not proven. Process containment is not a sandbox. Signed native containers, platform signing/notarization, and published native recovery/signature matrices remain release blockers.

No current gate supports a power-loss-safe, hostile-local-user-safe, universal-binary, or production-ready claim. See [SECURITY.md](../SECURITY.md).

# AI build guide

This is the shortest reliable workflow for coding agents and human contributors. It keeps core Rust policy, platform mutation, the standalone Tauri shell, the React renderer, and native release evidence in separate gates.

## Start here

1. Read [`llms.txt`](../llms.txt), this guide, and the applicable architecture/security document. Use the workspace's local working contract when one is supplied.
2. Inspect `git status --short`; preserve unrelated or concurrent work.
3. Trace the existing caller and trust boundary before editing.
4. Select one vertical slice: `spec → use case → adapter → CLI/GUI`.
5. Run the smallest gate that can disprove the change.
6. Report exact commands/results and unverified OS/release coverage.

Do not run the full matrix during the normal edit loop. Do not repeat equivalent check/test/clippy commands without a new reason.

## Toolchains

| Area | Contract |
| --- | --- |
| Core Rust | `rust-toolchain.toml` pins Rust `1.96.0`, edition 2024, resolver 3. |
| Web tooling | `.node-version` pins Node.js `22.12.0`; `package.json` pins pnpm `10.26.2`. |
| Desktop | Tauri `2.11.5`, React `19`, strict TypeScript `5`, Vite `7`, and Zod contracts. |
| Lockfiles | Root `Cargo.lock`, standalone `apps/luxury-installer/src-tauri/Cargo.lock`, and `apps/luxury-installer/pnpm-lock.yaml` are independent and committed. |

Use pnpm and the committed lockfile:

```console
pnpm --dir apps/luxury-installer install --frozen-lockfile
```

`cargo gui-check` never installs packages or performs hidden network bootstrap. It fails with the bootstrap command when `node_modules` is absent.

Linux desktop compilation needs the host packages required by Tauri/Wry. CI installs:

```console
sudo apt-get install --no-install-recommends libwebkit2gtk-4.1-dev libayatana-appindicator3-dev librsvg2-dev libxdo-dev
```

## Pick one gate

| Change | Primary gate |
| --- | --- |
| Pure schema/value rule | `cargo test -p luxury-spec` |
| Package/archive verification | `cargo test -p luxury-bundle` |
| Use case/port | `cargo test -p luxury-engine` |
| Filesystem or OS adapter | focused `cargo test -p luxury-platform <test-name>` on the native host |
| Fixed system roots or system reveal | `cargo test -p luxury-system-roots` plus `cargo tauri-test <reveal-test>` on the native host |
| Descendant process containment | `cargo test -p luxury-process` on the native host |
| Compiler/project scanning | `cargo test -p luxury-compiler` |
| Human CLI or JSONL backend | focused `cargo test -p luxury <test-name>` |
| Cross-crate core behavior | `cargo quick --locked` |
| Renderer contracts, views, styles | `cargo gui-check` |
| Tauri Rust command/transport | `cargo tauri-test`; add `cargo tauri-clippy` before handoff |
| Host runner/assembly | `cargo test --locked -p xtask`, then `cargo runner-smoke` when lifecycle changed |
| Documentation only | scoped diff, local-link check, and stale-term search; no broad build |
| Release candidate | full root tests + standalone Tauri tests + native runner smoke per advertised host |

Common aliases:

```console
cargo quick --locked
cargo core-check
cargo gui-check
cargo tauri-test
cargo tauri-clippy
cargo ci
cargo full-test --locked
cargo dist
cargo studio-assemble
cargo project-installer -- <absolute-project> <absolute-native-output>
cargo runner-smoke
```

What they prove:

- `cargo quick`: focused root-workspace tests; Tauri is excluded.
- `cargo gui-check`: renderer contract tests, both strict TypeScript projects, Vite production output, then locked `src-tauri` check.
- `cargo tauri-test`: standalone shell tests using its own lockfile.
- `cargo ci`: root formatting, one locked quick run, and the isolated desktop gate.
- `cargo full-test`: all root-workspace targets; still excludes the standalone Tauri workspace.
- `cargo dist`: full root tests, host `luxury` backend, and checked desktop frontend; no runner/signing claim.
- `cargo studio-assemble`: no-clobber payload-free Studio artifact for this host, including exact `--verify-studio`; Linux/macOS also get the deterministic mode-preserving `.tar.gz` used by CI.
- `cargo project-installer`: user-facing host-native build. It keeps `.luxpkg` in a temporary work directory and publishes only Windows `.exe`, Linux `.deb` + `.rpm`, or macOS `.dmg` without overwrite. Studio supplies one exact empty sibling work directory and removes it only after the contained descendant tree is reaped; xtask rejects links, prefilled directories, wrong names, and paths outside the selected output parent.
- `cargo verify-windows-signers -- <launcher.exe> <helper.exe>`: fail-closed embedded Authenticode-chain and exact leaf-certificate comparison for already signed Windows files.
- `cargo windows-release-setup -- <signed-runner-dir> <nsis.zip>`: verify the same-signer inner pair and emit an unsigned outer NSIS for external signing.
- `cargo verify-windows-release -- <signed-setup.exe>`: verify the final signed outer parent, authenticated inner runner/helper, UAC transport, and argument rejection.
- `cargo runner-smoke`: host-native packaged recovery/cancellation/launch/lifecycle probes, Tauri entrypoint, cleanup, then evidence schema v2.

For a Tauri Rust edit, format the standalone workspace explicitly:

```console
cargo fmt --manifest-path apps/luxury-installer/src-tauri/Cargo.toml -- --check
```

The root `cargo fmt --all` cannot discover an excluded workspace.

## CLI and AI automation

Start from live help, not remembered syntax:

```console
cargo run -p luxury -- --help
cargo run -p luxury -- build --help
cargo run -p luxury -- help install
```

Every public subcommand supports non-mutating `--help`/`-h`. The complete agent workflow and exact JSONL examples live in [`skills/luxury-installer-cli`](../skills/luxury-installer-cli/SKILL.md); read its [CLI reference](../skills/luxury-installer-cli/references/cli.md) before implementing a client.

For deployment automation, invoke the already-built bound Setup instead of extracting its internal package:

```console
My-App-Setup.exe --info-json
My-App-Setup.exe --unattended-install --allow-unsigned
My-App-Setup.exe --unattended-uninstall
```

Use `--info-json` before deployment when an agent or MDM needs bound-package inventory. It performs the same bound-package/backend/host validation but no install preparation or system authorization, emits exactly one JSON line, and omits license text, finish URLs, package paths, and native roots. The Windows project/release verifier executes this against the outer Setup, not only the extracted runner, and rejects wrong channels or schema drift.

Linux uses the installed bound `luxury-installer` launcher. On macOS invoke `Luxury Installer.app/Contents/MacOS/Luxury Installer` directly so the caller receives the real exit code. The runner accepts no path, key, downgrade, launch, or command authority. Add `--accept-license` only for a package that offers a license and `--allow-publisher-migration` only for an offered migration. Exit codes are `0` successful inspection/operation or already absent, `1` inspection/operation failure, and `64` invalid arguments.

Create, build, and inspect from the human CLI:

```console
cargo run -p luxury -- init <project-dir>
cargo run -p luxury -- build <project-dir> <out-v1.luxpkg>
cargo run -p luxury -- inspect <out-v1.luxpkg>
```

`init` creates only its exact generated `luxury.toml` and starter payload. A repeated init requires byte-identical content and never overwrites user changes. Studio's first successful real import removes that starter only when it remains the exact sole template file. For repeat releases, Studio can replace the complete payload with the contents of one selected directory: Rust copies and validates the new tree before swapping it, restores the old tree on ordinary validation/config failure, retains the staging backup if rollback itself fails, replaces executable intent, and clears an entrypoint that no longer exists with exact case. `luxury.toml` is untrusted and capped at `1 MiB` before parsing; optional `package.description` is bounded plain text in the core spec even for hand-edited projects.

Signed v2:

```console
<private-key-provider> | cargo run -p luxury -- build <project-dir> <out-v2.luxpkg> --signing-key-stdin
cargo run -p luxury -- inspect <out-v2.luxpkg> --trusted-publisher-key <public.pem>
```

V3 publisher rotation:

```console
cargo run -p luxury -- publisher-key-id <current-a-public.pem>
<next-b-key-provider> | cargo run -p luxury -- prepare-rotation <package-id> <version> <current-a-key-id> --next-signing-key-stdin
<current-a-key-provider> | cargo run -p luxury -- build <project-dir> <out-v3.luxpkg> --signing-key-stdin
```

Private signing keys are bounded UTF-8 PKCS#8 PEM supplied through stdin only. Never add a private-key path, CLI value, environment log, JSONL field, fixture, or committed secret.

Install lifecycle:

```console
cargo run -p luxury -- prepare-install <package.luxpkg> <install-base> <state-root>
cargo run -p luxury -- install <package.luxpkg> <install-base> <state-root> --allow-unsigned
cargo run -p luxury -- uninstall <package-id> <install-base> <state-root>
cargo run -p luxury -- launch <package-id> <install-base> <state-root>
```

Use the matching external `--trusted-publisher-key` for v2/v3. Keep state outside the removable install tree.

For schema-v3 projects with `package.license`, inspect the exact bounded text first and add `--accept-license` to the install command. JSONL/Tauri use the equivalent `acceptLicense` boolean; Rust rejects missing consent before platform access.

Reuse the same install/state roots when a newer downloaded package is installed over an existing one. Rust classifies a strictly newer SemVer as update and equal precedence with the exact same file set/entrypoint as repair. Lower versions require both package policy and explicit CLI caller approval; Setup never silently authorizes downgrade. Update/repair preserve unknown data, remove obsolete owned files only when unchanged, publish a new external receipt atomically, and restore the previous bytes/receipt on cancellation or failure.

## Run the desktop locally

Build the core backend and start Studio:

```console
cargo build -p luxury
pnpm --dir apps/luxury-installer run dev:app
```

Debug mode without a package starts Studio. Its validated form edits unsigned format-1 package/target/install/license/link settings. Rust-owned native dialogs create/open projects, add regular files or a directory without overwrite, stage and replace the payload from one directory, select an entrypoint inside the payload, reveal the project or last verified build output, and choose output. The renderer receives portable authoring state but never native source/output paths or generic filesystem authority.

Start bound-payload Setup by passing application arguments after the Tauri CLI separator:

```console
pnpm --dir apps/luxury-installer exec tauri dev -- -- --package="<absolute-package.luxpkg>"
```

Signed development QA may add:

```text
--trusted-publisher-key="<absolute-public.pem>"
```

`LUXURY_BACKEND_PATH` may point to another absolute debug backend. Debug arguments are strictly parsed: duplicates, missing values, and relative paths fail closed. Release builds ignore debug path overrides. Default feature `studio` resolves a fixed backend resource; Setup artifacts are built separately with `--no-default-features --features setup` and resolve a fixed backend/payload pair.

Never add a Setup package picker, file input, drag-and-drop, or renderer-supplied package/root path. A missing payload/backend/trust anchor is a blocking state, not a request for arbitrary replacement input.

## Process and dependency direction

```text
React renderer
    │ exact Tauri invoke/events
    ▼
Rust Tauri shell
    ├─ luxury-system-roots → pathless system reveal
    │ JSONL v3 over child stdin/stdout
    ▼
luxury stdio
    │
    ├─ luxury-engine → ports
    ├─ luxury-platform → real mutation
    ├─ luxury-system-roots → fixed system install/state roots
    ├─ luxury-bundle → archive trust
    ├─ luxury-compiler → project assembly
    ├─ luxury-process → native descendant containment
    └─ luxury-spec → portable invariants
```

Rules:

- Rust owns package policy, transition classification, rollback, receipts, recovery, and OS mutation.
- The Tauri shell owns native dialogs, bound paths/identity, backend process lifecycle, JSONL validation, public errors, and renderer command/event correlation.
- `luxury-system-roots` is the one narrow source for Windows Known Folders and fixed Linux/macOS system roots. `luxury-platform` uses it for privileged mutation; the Tauri shell uses only its install root after a verified completed operation for pathless reveal.
- `luxury-process` is the shared narrow OS adapter for suspended Job Object / process-group containment. The pathless Studio Cancel button, window close, timeout, setup failure, and primary exit share one Rust `idle -> active -> cancelled` lifecycle and must terminate/reap the complete packager descendant tree before returning; renderer cancellation carries no project/output/process identifier.
- React owns presentation state and accessibility only.
- The Studio primary build action runs native HTML validity first; for a dirty draft it awaits the existing typed `updateProject` Rust validation and only then sends the separate pathless `buildProject` intent. Save failure must not open an output dialog or start a packager.
- Native output suggestions are Rust-owned and use the validated product name, a 96-byte alphanumeric/hyphen component, and package ID only when the name has no usable letters or digits. Renderer never submits an output name/path, and packager no-clobber validation remains authoritative.
- Studio's elapsed build clock uses monotonic `performance.now()`, resets outside `building`, clears its interval on every transition/unmount, and is hidden from the polite live region; it must not invent backend phases or progress percentages.
- The exact Tauri ACL grants no generic renderer shell/fs/dialog/opener/process access.
- The standalone `src-tauri` workspace must remain excluded from the root workspace.
- Do not add Tauri/web dependencies to product crates or duplicate Rust rules in TypeScript.

## JSONL and Tauri contract rules

- `luxury stdio` stdout is protocol-only. Human diagnostics use stderr.
- One bounded JSON object occupies one line; validate protocol version, ID, method, params, result/error/event tag, strings, numbers, and cross-field relations.
- The Tauri backend client bounds line size and pending requests, correlates every response/event, gives cancellable ordinary operations five minutes plus 30 seconds to return their terminal cancellation, and leaves launch timeout-free after spawn.
- EOF, malformed output, child exit, or shutdown must fail/drain pending requests and reap the child; never wait on a reader while leaving its pipe open.
- Keep absolute paths at the Rust shell/backend boundary. Setup renderer intents stay pathless.
- Studio renderer never submits project/output/source paths. Its native import, whole-payload replacement, and entrypoint commands are pathless; Rust shell owns dialog results and active project state, while `luxury-compiler` validates/copies/rolls back authoring mutations.
- Setup shell owns package path/fingerprint/ID, state root, install base, latest preparation, and entrypoint authority.
- Completed-install reveal accepts no renderer path. User scope uses the retained validated selection; system scope joins the authenticated one-component install directory to `luxury-system-roots` only after terminal success and while Setup is idle.
- Optional `install.show_install_log` stays default-off and exposes only a bounded display projection of authenticated manifest paths. The collapsed panel is available during installation as a plan with factual counters and after completion as the result; it never displays raw backend output. `install.finish_links` accepts at most four HTTPS URLs; renderer sends only an index to the Rust-owned opener command.
- System-scope initial/retry preparation goes through the authenticated privileged helper and calls Rust `prepare_system_install`; never fabricate a fresh-install state when the protected receipt is unreadable from the desktop process.
- `prepareInstall` remains read-only and advisory, including native destination write-access and capacity checks. Real install independently reopens, authenticates, recovers, reassesses, and rechecks.
- `allowUnsigned` and `acceptLicense` are separate explicit consents. `allowPublisherMigration` authorizes legacy/unsigned adoption only when the current Rust preparation requires it; it never claims identity.
- Uninstall is receipt-driven and returns aggregate counts. Do not serialize preserved paths to JSONL or renderer events.
- Launch accepts a zero-argument intent and returns successful spawn only. Never expose entrypoint path, accept renderer arguments/environment, auto-run, or forward child streams into JSONL.
- Cancellation targets one active cancellable operation ID. Successful launch is not rollbackable and is not cancellable.
- A Setup command acquires the shared startup gate before rechecking close-state. Window close waits for `starting -> active`, requests cooperative cancellation, and waits for the correlated terminal rollback/cleanup signal before closing backend/window. Repeated native close/Alt+F4 stays prevented until Rust sets `close_ready` for the final programmatic close; the cancel request consumes only the remaining shared timeout budget. Timeout leaves the process alive for retry.
- Keep progress bounded and validate counters before emitting renderer events.
- Current JSONL methods are `defaults`, `initProject`, `validateProject`, `updateProject`, `importPayload`, `resolvePayloadPath`, `buildProject`, `inspect`, `prepareInstall`, `install`, `uninstall`, `launch`, and `cancel`. Add/remove/rename one only with synchronized CLI reference, `llms.txt`, skill, Tauri types, and tests.

Renderer commands and events must stay synchronized with Rust command signatures and strict Zod contracts. A compile pass alone is not proof of wire compatibility; update the focused contract test when the shape changes.

## Build the end-user installer

Studio and agents use one command:

```console
cargo project-installer -- <absolute-project-directory> <absolute-native-output>
```

- Windows x86_64 output is a new `.exe` file.
- Linux x86_64/aarch64 output is a new directory containing `.deb`, `.rpm`, and provenance.
- macOS x86_64/aarch64 output is a new `.dmg` file.

The compiler package is an internal verified handoff and is removed with the work directory. Released Studio uses its bundled payload-free Setup template and Rust packager, so a user build does not run Cargo, pnpm, TypeScript, or Tauri compilation. Windows also carries the SHA-256-pinned NSIS archive. Linux creates deterministic-layout Debian `ar`/tar and RPM/CPIO containers with narrow Rust libraries, then independently parses their metadata, ownership, modes, scripts, dependencies, paths, and hashes; `dpkg`, `rpm`, and `cpio` are release cross-checks, not user runtime dependencies. The pinned RPM writer buffers its payload, so packaged Studio rejects combined Linux inputs above 256 MiB before allocation pressure; raise that ceiling only with a streaming RPM writer. Studio contains the packager and every child tool in one bounded native process tree and treats cleanup failure as build failure. Template materialization patches exactly one reviewed 64-byte binding slot, then repeats package, runner, container, argument-rejection, and final-byte checks.

Native multi-build means running this command on matching Windows/Linux/macOS runners. Do not claim Apple signing from Windows or publish the blocked Linux desktop graph. Low-level package and runner commands below remain release/security gates, not the Studio result.

## Assemble a host-native runner

Build and verify the payload-free authoring Studio first when that is the desired deliverable:

```console
cargo studio-assemble
```

It stages launcher + backend only, rejects payload/trust resources, validates host layout and hashes, runs exact windowless `--verify-studio`, and publishes without overwrite.

```console
cargo assemble -- <absolute-package.luxpkg>
```

Assembly accepts one explicit regular unsigned-v1 package matching the current host. It never searches for “latest” input. The flow builds the dist backend, runs the desktop gate, builds the standalone locked Tauri release shell, stages fixed backend/payload resources, rejects a trust resource, compares hashes/identity, runs windowless `--verify-runner`, and no-clobber publishes under ignored `dist/`.

The runner layout is host-native:

- Windows: launcher plus `backend/` and `payload/` resources;
- Linux: `usr/bin/luxury-installer`, resources under `usr/lib/Luxury Installer/`, a byte-identical helper at `usr/libexec/luxury-installer-helper`, and the exact policy under `usr/share/polkit-1/actions/`;
- macOS: exact-bound `Luxury Installer.app/Contents/Info.plist`, `Contents/MacOS`, `Contents/Resources/luxury-installer-helper`, and `Contents/Library/LaunchDaemons/software.luxury.installer.helper.plist`.

The command does not cross-compile, sign, notarize, or prove another host. Signed v2/v3 input stays disabled until the native container supplies an external verifiable trust root.

Native Linux `.deb` and RPM development containers:

```console
sudo apt-get install --no-install-recommends rpm cpio
cargo linux-packages -- <absolute-package.luxpkg>
```

The pinned Tauri bundler creates both containers and changes exactly one fixed-width bundle-type marker in the launcher to `DEB` or `RPM`. Rust independently derives those two exact hashes from the verified source, rejects missing/duplicate markers and every other launcher change, then verifies metadata, dependencies, exact paths and modes, root ownership, absence of scripts/links/special files, and exact bytes for the backend, payload, helper, policy, and icon. The command also constrains the generated desktop entry to `Exec=luxury-installer` without arguments. Output under `target/linux-packages/` is unsigned development evidence only. Do not publish it as a release or treat it as installed-polkit/signature proof.

On Linux/macOS, publish or upload only the Rust-generated `<artifact>.tar.gz`, not the raw directory: generic CI artifact transport does not preserve executable bits. The archive is deterministic, normalized, link-free, synced, and no-clobber; it is still unsigned. Linux system scope activates only when the `usr/` tree is distribution-installed at `/` with root ownership. Running from an extracted writable tree must fail before `pkexec`.

The macOS bundle has a deployment floor of 13.0 for `SMAppService`. Build the app and helper with the same canonical `LUXURY_APPLE_TEAM_ID`, sign the helper with identifier `software.luxury.installer.helper`, sign the outer app as `software.luxury.installer`, notarize and staple it, then run on macOS:

```console
LUXURY_APPLE_TEAM_ID=XXXXXXXXXX cargo verify-macos-release -- <signed-app.bundle>
```

That gate verifies both designated requirements, strict nested resources, Gatekeeper and the stapled ticket. Cross-target checks do not replace it.

The verified `.app` contains the branded `icon.icns` declared by exact `Info.plist`. Wrap it without exposing credentials:

```console
LUXURY_APPLE_TEAM_ID=XXXXXXXXXX cargo macos-dmg -- <signed-stapled.app>
```

The result is an inspected but unsigned development DMG. Sign it with the Developer ID Application identity, submit it with `notarytool`, staple the accepted ticket, then run:

```console
LUXURY_APPLE_TEAM_ID=XXXXXXXXXX cargo verify-macos-dmg -- <signed-notarized.dmg>
```

The verifier mounts read-only and requires only the exact app plus `/Applications`; it then repeats app/helper designated-requirement, codesign, Gatekeeper, stapler, payload identity and Tauri entrypoint checks. Do not publish the intermediate unsigned DMG or treat cross-target Clippy as native proof.

Windows development wrapper:

```console
cargo windows-setup -- <absolute-package.luxpkg> <absolute-pinned-nsis.zip>
```

The archive must match [`packaging/windows/nsis.lock.json`](../packaging/windows/nsis.lock.json). The output is an unsigned user-scope development `Setup.exe`, not release signing evidence.

Windows release signing is an ordered external workflow:

```console
# after cargo assemble, sign both inner files externally with one certificate
cargo verify-windows-signers -- <signed-runner-dir/"Luxury Installer.exe"> <signed-runner-dir/backend/luxury.exe>
cargo windows-release-setup -- <signed-runner-dir> <absolute-pinned-nsis.zip>

# sign the emitted outer Setup externally with the same certificate
cargo verify-windows-release -- <signed-LuxuryInstallerSetup.exe>
```

Do not reverse the order or treat a signed outer container with unsigned/different-signer inner files as a release. Before authenticated `runas`, Tauri pins the exact helper without write/delete sharing, compares its embedded leaf certificate with the process-image-bound running launcher, and keeps that guard through `ShellExecuteExW`; the helper repeats process-image verification after startup. `windows-release-setup` intentionally emits an unsigned outer artifact; `verify-windows-release` is the only final-byte gate. Signing keys, certificates, tokens, and provider arguments remain outside Rust commands, argv, env, config, logs, and the repository.

## Runner smoke and evidence v2

Run `cargo runner-smoke` natively. On headless Linux:

```console
xvfb-run -a cargo runner-smoke
```

The smoke uses fresh ignored staging and fails if cleanup fails. It gates packaged backend inspection, normal install/uninstall, exact installed bytes, foreign-file preservation, receipt/transaction cleanup, cancellation rollback, receipt-owned launch, bounded recovery scenarios, and the Tauri `--verify-runner` entrypoint.

Only after successful cleanup does it atomically write:

```text
target/runner-evidence/<os>-<arch>.json
```

Schema v2 records target, pinned Tauri shell kind/version, package identity/fingerprint, backend/payload/frontend-tree/launcher hashes, lifecycle counts, and explicit normal-lifecycle/cleanup/Tauri checks. It has no timestamp or absolute path.

The file is unsigned and does not separately encode recovery, cancellation, or receipt-owned launch, even though those probes gate its production. Treat it as a deterministic verification receipt, not attestation or native-signature evidence.

Hosted Linux runs Tauri probes under Xvfb with `NO_AT_BRIDGE=1`. This suppresses only GTK's attempt to connect to an accessibility D-Bus service that the headless runner does not provide; packaged stdout/stderr verification remains exact and production accessibility is unchanged.

Verify the downloaded Linux/Windows x86_64 plus macOS ARM64 set:

```console
cargo run --locked -p xtask -- verify-evidence-set <directory>
```

The directory must contain exactly `linux-x86_64.json`, `windows-x86_64.json`, and `macos-aarch64.json` with consistent package identity. Do not claim three-OS coverage from CI configuration or one local file.

## Cross-platform and release contract

The portable unit is `.luxpkg`, not one universal executable. Build and test a separate native shell for every target OS/architecture.

Routine pull-request/main CI:

- root and standalone-Tauri formatting;
- `cargo quick --locked`;
- isolated renderer + Tauri check;
- focused Windows `cargo test --locked -p luxury-windows-trust -p luxury-platform -p luxury-system-roots -p luxury-process` trust/filesystem/root/process-tree boundary check.

Every routine job has an explicit 10-60 minute timeout; the manual native matrix remains capped at 60 minutes per host and its evidence merge at 20 minutes. Do not remove these caps or replace the separated jobs with one serial mega-gate.

Manual `workflow_dispatch`:

- full root-workspace tests;
- standalone Tauri tests;
- payload-free Studio assembly and `--verify-studio` on each native host;
- inspected unsigned `.deb`/RPM development packaging on Linux, plus native runner smoke on Linux/Windows x86_64 and macOS ARM64;
- exact schema-v2 evidence-set verification.

Before a public release, still require native container signing, signer provenance, installer install/uninstall behavior, platform privilege review, recovery/cancellation on final bytes, and downloaded artifact verification. Current configuration is not release readiness.

## Completion checklist

1. Confirm the requested behavior exists end to end, not only in one layer.
2. Confirm core dependency direction and Tauri process boundaries still hold.
3. Confirm package/renderer/backend inputs are validated at their own trust boundaries.
4. Confirm every mutation has rollback/recovery and every removal is receipt-owned.
5. Run one focused gate; add broader gates only when scope justifies them.
6. Check standalone Tauri formatting/lockfile when `src-tauri` changed.
7. Inspect the final diff and search for generated artifacts, secrets, stale runtime terms, and accidental broad dependencies. Tauri `gen/schemas` and `permissions/autogenerated` are build/editor outputs and stay ignored.
8. Synchronize changed commands, JSONL methods, package fields, and authoring behavior across README, the relevant guide, `llms.txt`, and the public CLI skill; update workspace-local memory when the local contract requires it.
9. State unverified OS, signing, privilege, durability, and hostile-filesystem ceilings plainly.

Never commit signing keys, certificates, tokens, built payloads, `target/`, `node_modules/`, frontend `out/`, native runner output, evidence fixtures, or temporary QA files.

<p align="center">
  <img src="docs/assets/luxury-installer-logo.svg" width="920" alt="Luxury Installer">
</p>

<p align="center">
  <strong>Build a polished installer without giving up control.</strong><br>
  A modern Studio, native installers, transactional updates, and one Rust core for Windows, Linux, and macOS.
</p>

<p align="center">
  <code>Rust 1.96</code>&nbsp;&nbsp;·&nbsp;&nbsp;<code>Tauri 2</code>&nbsp;&nbsp;·&nbsp;&nbsp;<code>React 19</code>&nbsp;&nbsp;·&nbsp;&nbsp;<code>Apache-2.0 OR MIT</code>
</p>

<p align="center">
  <a href="#quick-start">Quick start</a> ·
  <a href="#automation">Automation</a> ·
  <a href="#platform-status">Platform status</a> ·
  <a href="docs/architecture.md">Architecture</a> ·
  <a href="SECURITY.md">Security</a> ·
  <a href="CONTRIBUTING.md">Contributing</a>
</p>

> [!IMPORTANT]
> Luxury Installer is a functional development preview, not a production release. The core package and user-scope lifecycle work today. Final signed Windows evidence, installed and distribution-signed Linux helper evidence, signed/notarized macOS evidence, and a downloaded three-host release matrix are still required.

## One tool, two experiences

### Studio for the person building the installer

Open Studio and describe the application instead of hand-writing a setup script:

- edit identity, version, publisher, target, architecture, and install scope;
- reopen up to six validated recent projects without browsing for their folders again;
- add files or a complete folder through native dialogs;
- choose the launch file from the real payload;
- add a license, optional installation details, and up to four HTTPS finish links;
- save, revalidate, and build a real `.exe`, `.deb` + `.rpm`, or `.dmg` for the selected native target.

The internal package container stays between the Rust compiler and packager and is deleted with the build workspace. It is not the file a Studio user ships. Source and output paths stay in the Rust shell; React receives validated portable settings, not generic filesystem access.

### Setup for the person installing the application

Each Setup is bound to one reviewed payload. It shows the application, publisher, version, destination, and exact operation without becoming a package browser.

- a newer downloaded version becomes an update;
- the same version with the exact file set becomes repair;
- downgrade is never silently approved;
- cancellation and failure restore the previous installation;
- unknown files and modified obsolete files are preserved;
- successful progress waits for an explicit **Next** before showing launch, folder, and finish-link actions;
- package authors decide whether the bounded installation-details panel is available.

There is no built-in update-download service yet. Updating means launching a newer Setup for the same package ID and roots; the transactional upgrade itself is implemented.

## Why it is different

| | Luxury Installer |
| --- | --- |
| Output | One-click Windows `Setup.exe`, Linux `.deb` + `.rpm`, or macOS `.dmg`; the deterministic package is internal. |
| Trust | Unsigned development v1, Ed25519-signed v2, authenticated publisher rotation v3. |
| Lifecycle | Read-only preflight, install, update, repair, explicit downgrade policy, rollback/recovery, uninstall, and receipt-owned launch. |
| Ownership | Receipts live outside the removable application tree. Unknown or modified data is not claimed. |
| Desktop | Fixed adaptive Codex-style Tauri window with a small exact ACL and no renderer shell/fs/process permission. |
| Build speed | Core Rust and desktop graphs are separate; routine work uses targeted gates instead of a serial native matrix. |
| Automation | Human CLI plus strict typed JSONL v3 over stdin/stdout for agents and desktop composition. |

## Quick start

You need:

- [Rust via rustup](https://rustup.rs/) — `rust-toolchain.toml` pins Rust `1.96.0`;
- Node.js `22.12+` and pnpm `10.26.2`;
- the [Tauri 2 prerequisites](https://v2.tauri.app/start/prerequisites/) for your host OS.

Install the desktop dependencies once:

```console
pnpm --dir apps/luxury-installer install --frozen-lockfile
```

Start Studio:

```console
cargo build -p luxury -p xtask
pnpm --dir apps/luxury-installer run dev:app
```

Or create a project and build the host-native installer directly:

```console
cargo run -p luxury -- init <project-dir>
cargo project-installer -- <absolute-project-dir> <absolute-native-output>
```

Native output is explicit:

| Host | Output argument |
| --- | --- |
| Windows x64 | A new `Setup.exe` file. |
| Linux x64/arm64 | A new directory containing verified `.deb` and `.rpm` files. |
| macOS x64/arm64 | A new `.dmg` file. |

The normal Studio build needs no Rust, Node, or Tauri rebuild: released Studio bundles carry a verified host template and Rust packager. The Linux packager writes and independently inspects `.deb` and RPM containers in Rust, so users do not need `dpkg`, `rpm`, Cargo, or pnpm. Its current combined input limit is 256 MiB because the pinned RPM writer buffers payloads; the build fails clearly before exhausting memory. Building all platforms still uses native Windows/Linux/macOS runners because Apple signing and native containers cannot be truthfully produced by one Windows process.

The low-level package/lifecycle CLI remains available for signing, CI, and engine testing. Unsigned package installation always needs explicit consent:

```console
cargo run -p luxury -- prepare-install <out.luxpkg> <install-base> <state-root>
cargo run -p luxury -- install <out.luxpkg> <install-base> <state-root> --allow-unsigned
```

Keep `<state-root>` outside the removable install tree. Reuse the same roots for update, repair, launch, and uninstall.

Run Setup locally with one absolute package path after Tauri's separators:

```console
pnpm --dir apps/luxury-installer exec tauri dev -- -- --package="<absolute-package.luxpkg>"
```

Signed development QA may append `--trusted-publisher-key="<absolute-public.pem>"`. Release Setup ignores debug path overrides and uses only its embedded backend and bound payload.

## Signed packages

Private signing keys are bounded PKCS#8 PEM read from stdin only:

```console
<private-key-provider> | cargo run -p luxury -- build <v2-project> <out-v2.luxpkg> --signing-key-stdin
cargo run -p luxury -- inspect <out-v2.luxpkg> --trusted-publisher-key <public.pem>
```

They are never accepted as an argument, JSONL field, environment setting, project value, log, or fixture. Publisher rotation keeps the current and next private keys in separate processes. See the [complete CLI reference](skills/luxury-installer-cli/references/cli.md).

## Automation

Every public command has safe, non-mutating subcommand help:

```console
cargo run -p luxury -- install --help
cargo run -p luxury -- help install
```

For coding agents and CI clients:

- [`llms.txt`](llms.txt) is the compact repository map;
- [`luxury-installer-cli`](skills/luxury-installer-cli/SKILL.md) is the reusable agent skill;
- its [CLI and JSONL v3 reference](skills/luxury-installer-cli/references/cli.md) contains every current command, method, envelope, consent, update rule, and cancellation pattern;
- [`docs/ai-build.md`](docs/ai-build.md) maps changes to the smallest useful verification gate.

The repository test derives the live JSONL method table and fails when the AI guide, `llms.txt`, or skill falls behind.

## Build and release commands

Use the smallest command that proves the work:

| Command | Use it for |
| --- | --- |
| `cargo quick --locked` | Normal core Rust loop. |
| `cargo gui-check` | Renderer contracts, strict TypeScript, Vite, and both Tauri flavors. |
| `cargo studio-assemble` | Payload-free Studio for the current host. |
| `cargo project-installer -- <project> <native-output>` | User-facing native installer; the package is a temporary internal file. |
| `cargo assemble -- <package.luxpkg>` | Low-level package-bound runner gate. |
| `cargo runner-smoke` | Native packaged lifecycle, cancellation, recovery, launch, cleanup, and local evidence. |

Windows, Linux, and macOS have different final container/signing flows. Follow the exact order in the [AI build guide](docs/ai-build.md); Rust release commands do not accept signing credentials.

## Platform status

| Platform | Implemented | Still required before release |
| --- | --- | --- |
| Windows 10/11 | Standalone Studio template-packager emits and runtime-verifies one NSIS `Setup.exe`; authenticated system lifecycle and two-phase signing flow are implemented. | Authenticode-signed final lifecycle and downloaded final-byte verification. |
| Linux desktop | Native project build emits inspected `.deb` + `.rpm`; fixed helper/polkit lifecycle exists. | Remove the GTK3 advisory, prove installed root-owned lifecycle, and add distribution signing. |
| macOS 13+ | Native project build emits an inspected `.dmg`; signed `SMAppService` lifecycle and final DMG verification flows exist. | Developer ID signing, notarization, and downloaded final-byte proof. |

Linux desktop publication remains blocked by `RUSTSEC-2024-0429` in the pinned GTK3/Wry dependency graph. The project does not hide that advisory or call the current Linux desktop artifact release-ready.

## Security model

The short version:

- all manifest, archive, path, receipt, journal, JSONL, and renderer input is untrusted;
- absolute, parent, UNC/device/ADS, alias-colliding, link/reparse, and special payload entries are rejected;
- mutation starts only after verification and read-only preflight, then runs under locks, journal, rollback, and external receipt ownership;
- Setup never receives a user-selected package; one payload is bound at build time;
- system roots and package authority never come from React, argv, JSONL, or environment variables;
- launch is zero-argument and receipt-owned—no shell, forwarded environment, or automatic run.

Read [SECURITY.md](SECURITY.md), the [architecture](docs/architecture.md), and the [privileged-helper contract](docs/privileged-helper.md) before changing a trust boundary. Please report vulnerabilities privately through GitHub Security Advisories.

## Contributing

Start with [CONTRIBUTING.md](CONTRIBUTING.md). Keep changes as small vertical slices, preserve unrelated work, and report the exact gates that passed plus native/release evidence that remains unverified.

Questions belong in [Discussions](https://github.com/GofMan5/luxury-installer/discussions); reproducible defects use the issue forms. See [SUPPORT.md](SUPPORT.md), [CHANGELOG.md](CHANGELOG.md), and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## License

Licensed under either [Apache License 2.0](LICENSE-APACHE) or [MIT](LICENSE-MIT), at your option.

# Luxury Installer CLI and JSONL v3

## Contents

- [Authority and process rules](#authority-and-process-rules)
- [Human CLI](#human-cli)
- [Project authoring](#project-authoring)
- [Bound Setup unattended mode](#bound-setup-unattended-mode)
- [Install, update, repair, and removal](#install-update-repair-and-removal)
- [Signed packages and rotation](#signed-packages-and-rotation)
- [JSONL process contract](#jsonl-process-contract)
- [JSONL methods](#jsonl-methods)
- [Events, cancellation, and errors](#events-cancellation-and-errors)
- [Agent completion checklist](#agent-completion-checklist)

## Authority and process rules

The checked-out binary is authoritative:

```console
luxury --help
luxury install --help
# source checkout
cargo run -p luxury -- install --help
```

`luxury <command> --help`, `luxury <command> -h`, and `luxury help <command>` are non-mutating and exit successfully. Help is diagnostic output on stderr; `luxury stdio` reserves stdout for JSONL only.

Use the same absolute `install-base` and external `state-root` for the full lifecycle. A receipt in `state-root` binds the package ID, scope, install directory, version, publisher identity, payload, and optional entrypoint. Do not discover or edit receipts manually.

## Human CLI

Current public commands:

```text
luxury stdio [--trusted-publisher-key <absolute-public.pem>]
luxury init <project-dir>
luxury build <project-dir> <out.luxpkg> [--signing-key-stdin]
luxury publisher-key-id <public.pem>
luxury prepare-rotation <package-id> <version> <A-key-id> --next-signing-key-stdin
luxury inspect <package.luxpkg> [--trusted-publisher-key <public.pem>]
luxury prepare-install <package.luxpkg> <install-base> <state-root> [--trusted-publisher-key <public.pem>]
luxury install <package.luxpkg> <install-base> <state-root> [--trusted-publisher-key <public.pem>] [--allow-unsigned] [--accept-license] [--allow-downgrade] [--allow-publisher-migration]
luxury uninstall <package-id> <install-base> <state-root>
luxury launch <package-id> <install-base> <state-root>
luxury help [command]
```

Use `build ... --signing-key-stdin` for signed format 2 or 3.

## Project authoring

Create a project, replace the starter payload through Studio or ordinary filesystem tools, and build the native installer:

```console
luxury init C:\work\my-app-installer
cargo project-installer -- C:\work\my-app-installer C:\work\My-App-Setup.exe
```

On Linux, the output argument is a new directory containing `.deb` and `.rpm`; on macOS it is a new `.dmg`. The packager creates and removes the internal `.luxpkg` itself. Studio supervises the complete native packager descendant tree through `luxury-process`, so cancel, timeout, and primary exit terminate/reap child tools before returning. Use low-level `luxury build` only for signed-package, protocol, or lifecycle automation that explicitly needs that trust boundary.

The project contains `luxury.toml` and its configured payload directory. `init` never overwrites different existing files. Studio can reopen a bounded Rust-owned recent-project entry by index, edit unsigned format-1 settings, import regular files or one directory without overwrite, replace the complete payload through same-project staging with one directory's contents, select an entrypoint through a native dialog, build the native output, and reveal that retained output through a pathless Rust action. Imported links, reparse points, special entries, path aliases, empty imports, and payload/project overlap fail closed. Ordinary partial publication or replacement failures roll back; a rollback failure reports `rollback_failed` and keeps the staging backup. Replacement also refreshes executable intent and clears an entrypoint missing from the new tree with exact-case comparison.

Minimal configuration shape:

```toml
format_version = 1

[package]
id = "com.example.my-app"
name = "My App"
version = "1.0.0"
publisher = "Example"

[target]
os = "windows"
arch = "x86_64"

[install]
scope = "user"
directory = "My App"

[payload]
directory = "payload"
executable = []
```

Optional authoring fields include a 1-1024-character plain-text `package.description`, `package.license`, `install.allow_downgrade`, `install.entrypoint`, `install.show_install_log`, and up to four `[[install.finish_links]]` HTTPS links. Windows entrypoints must end in `.exe`; Linux/macOS entrypoints must also appear in `payload.executable`. When enabled, Setup keeps the collapsed bounded manifest projection available during installation as a plan with factual counters and after completion as the result; it never exposes raw backend logs.

## Bound Setup unattended mode

Automate the final user-facing artifact without exposing its internal `.luxpkg`:

```console
My-App-Setup.exe --info-json
My-App-Setup.exe --unattended-install --allow-unsigned
My-App-Setup.exe --unattended-uninstall
```

On Linux invoke the installed bound `luxury-installer` binary. On macOS invoke `Luxury Installer.app/Contents/MacOS/Luxury Installer` directly; `open` does not preserve the operation's exit code. The accepted surface is exact:

```text
--info-json
--unattended-install [--allow-unsigned] [--accept-license] [--allow-publisher-migration]
--unattended-uninstall
--help | -h
```

`--info-json` validates the compiled payload binding, backend response, and host target without install preparation or system authorization. Success is exactly one JSON line with schema version, bounded package/trust metadata, target, portable install policy, and payload counts. It omits license text, finish URLs, internal package paths, and native roots:

```json
{"schemaVersion":1,"package":{"id":"com.example.app","fingerprint":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","name":"Example App","publisher":"Example","version":"1.0.0","description":null,"trust":{"kind":"unsigned"},"requiresLicense":false,"publisherRotation":false},"target":{"os":"windows","arch":"x86_64"},"install":{"scope":"user","directory":"Example App","hasEntrypoint":true,"showInstallLog":false,"finishLinks":0},"payload":{"files":1,"bytes":42}}
```

Query the final shipped Setup path. Windows packaging verifies this contract through the outer `.exe`; probing an extracted inner runner is not equivalent release evidence.

No package path, install root, state root, key, downgrade approval, launch, environment, or arbitrary command is accepted. The runner uses its compiled payload binding and host-native default roots, waits for terminal rollback/cleanup for mutations, and returns `0` on successful inspection/operation, `1` on an inspection/operation failure, or `64` on invalid arguments. Unattended uninstall is idempotent; system scope can still require the OS-native UAC/polkit authorization prompt. Supply each consent only when the caller explicitly authorized the currently authenticated request.

## Install, update, repair, and removal

Inspect and preflight before mutation:

```console
luxury inspect app.luxpkg
luxury prepare-install app.luxpkg C:\Apps C:\State\Luxury --trusted-publisher-key publisher.pem
luxury install app.luxpkg C:\Apps C:\State\Luxury --trusted-publisher-key publisher.pem
```

For unsigned format 1, add `--allow-unsigned` only after explicit caller consent. Add `--accept-license` only after the caller accepted the package's current authenticated license.

The receipt and SemVer precedence select the action:

- no receipt: install;
- strictly newer precedence: update;
- equal precedence with the exact same file set and entrypoint: repair;
- lower precedence: reject unless both `install.allow_downgrade = true` and explicit `--allow-downgrade` are present;
- equal precedence with different files or entrypoint: reject as `reinstall_mismatch`.

Update and repair are transactional. Unknown files are not adopted, modified obsolete files are preserved, removed owned files are deleted only when unchanged, and cancellation/failure restores the previous receipt and bytes. After success, use the same roots:

```console
luxury launch com.example.my-app C:\Apps C:\State\Luxury
luxury uninstall com.example.my-app C:\Apps C:\State\Luxury
```

`launch` accepts no arguments and starts only the receipt-owned verified entrypoint. `uninstall` preserves unknown and modified files.

## Signed packages and rotation

Set `format_version = 2`, then pipe one bounded PKCS#8 private key:

```console
key-provider | luxury build project app-v2.luxpkg --signing-key-stdin
luxury inspect app-v2.luxpkg --trusted-publisher-key publisher-public.pem
```

Never pass the private key path or PEM as a CLI argument. The public SPKI key is the external trust anchor for inspect/install and can be supplied to `luxury stdio` only at process startup.

For authenticated A-to-B rotation, set format 3 and create the public proof with B while keeping A and B private keys in separate processes:

```console
luxury publisher-key-id A-public.pem
B-key-provider | luxury prepare-rotation com.example.my-app 2.0.0 <A-key-id> --next-signing-key-stdin
A-key-provider | luxury build project app-v3.luxpkg --signing-key-stdin
```

Fresh install, equal/lower version, replay, unsigned/legacy state, self-rotation, or the wrong installed signer rejects rotation.

## JSONL process contract

Start one long-lived process:

```console
luxury stdio
luxury stdio --trusted-publisher-key C:\keys\publisher-public.pem
```

Write one UTF-8 JSON object per line to stdin:

```json
{"protocolVersion":3,"id":"inspect-1","method":"inspect","params":{"packagePath":"C:\\work\\app.luxpkg"}}
```

IDs are 1-128 ASCII letters, digits, `.`, `_`, `:`, or `-`. Params and results are strict: unknown fields, wrong casing, relative paths, unsafe values, oversized lines, and inconsistent cross-fields fail.

Result, error, and event envelopes:

```json
{"protocolVersion":3,"type":"result","id":"inspect-1","result":{}}
{"protocolVersion":3,"type":"error","id":"inspect-1","error":{"code":"inspect_failed","message":"..."}}
{"protocolVersion":3,"type":"event","id":"install-1","event":"progress","data":{"completedFiles":1,"totalFiles":2,"completedBytes":10,"totalBytes":20}}
```

Keep stdin open, read stdout continuously, drain stderr separately, and correlate by exact ID. Only one mutation or ordinary operation runs at a time; concurrent work returns `busy`. Closing stdin requests shutdown/cancellation and the server drains terminal cleanup before exit.

## JSONL methods

### Read and author projects

```json
{"protocolVersion":3,"id":"defaults-1","method":"defaults","params":{}}
{"protocolVersion":3,"id":"init-1","method":"initProject","params":{"projectPath":"C:\\work\\project"}}
{"protocolVersion":3,"id":"validate-1","method":"validateProject","params":{"projectPath":"C:\\work\\project"}}
{"protocolVersion":3,"id":"build-1","method":"buildProject","params":{"projectPath":"C:\\work\\project","outputPath":"C:\\work\\app.luxpkg"}}
```

`defaults` returns Rust-owned user roots, host target, and backend version. `initProject`, `validateProject`, `updateProject`, `importPayload`, and low-level `buildProject` return the current project summary. `authoring.executableFiles` is a bounded count, never an unbounded path list. `buildProject` creates the internal unsigned format-1 handoff; Studio then uses the native packager. Signed builds remain the human stdin-key command.

Update unsigned format-1 settings atomically:

```json
{"protocolVersion":3,"id":"update-project-1","method":"updateProject","params":{"projectPath":"C:\\work\\project","package":{"id":"com.example.my-app","name":"My App","version":"1.1.0","publisher":"Example","description":"Desktop app","license":null},"target":{"os":"windows","arch":"x86_64"},"install":{"scope":"user","directory":"My App","allowDowngrade":false,"entrypoint":"bin/app.exe","showInstallLog":true,"finishLinks":[{"label":"Support","url":"https://example.com/support"}]}}}
```

Omit `executable` to preserve the current list while the compiler adds a new Unix entrypoint and drops the previous entrypoint marker only when that old file is gone. Supply an explicit `executable` array only when the caller intends to replace the full list; manifest validation still requires a Linux/macOS entrypoint to be executable.

Import selected absolute paths without exposing them in the result:

```json
{"protocolVersion":3,"id":"import-1","method":"importPayload","params":{"projectPath":"C:\\work\\project","sourcePaths":["C:\\build\\app.exe","C:\\build\\assets"]}}
```

Replace the complete payload with the contents of exactly one directory:

```json
{"protocolVersion":3,"id":"replace-1","method":"importPayload","params":{"projectPath":"C:\\work\\project","sourcePaths":["C:\\build\\release"],"replace":true}}
```

Omitted or false `replace` keeps additive create-new behavior. Replacement rejects files, multiple sources, empty trees, links, special entries, project/payload overlap, and invalid portable paths before commit.

Resolve a native selection to a validated portable payload path:

```json
{"protocolVersion":3,"id":"entrypoint-1","method":"resolvePayloadPath","params":{"projectPath":"C:\\work\\project","selectedPath":"C:\\work\\project\\payload\\app.exe"}}
```

The result is `{"path":"app.exe"}`. The selected file must be a regular non-link inside the configured payload.

### Inspect and mutate installations

Inspect first and retain its exact lower-hex `packageFingerprint`:

```json
{"protocolVersion":3,"id":"inspect-2","method":"inspect","params":{"packagePath":"C:\\work\\app.luxpkg"}}
{"protocolVersion":3,"id":"prepare-1","method":"prepareInstall","params":{"packagePath":"C:\\work\\app.luxpkg","installBase":"C:\\Apps","stateRoot":"C:\\State\\Luxury","expectedFingerprint":"<64-lower-hex>"}}
```

`prepareInstall` returns `ready`, `insufficientSpace`, or `recoveryRequired`; ready/space results include `action`, `installedVersion`, and `publisherMigrationRequired`. It never grants mutation authority.

Install with explicit booleans:

```json
{"protocolVersion":3,"id":"install-1","method":"install","params":{"packagePath":"C:\\work\\app.luxpkg","installBase":"C:\\Apps","stateRoot":"C:\\State\\Luxury","allowUnsigned":false,"acceptLicense":false,"allowDowngrade":false,"allowPublisherMigration":false,"expectedFingerprint":"<64-lower-hex>"}}
```

Uninstall or launch through the receipt:

```json
{"protocolVersion":3,"id":"uninstall-1","method":"uninstall","params":{"packageId":"com.example.my-app","installBase":"C:\\Apps","stateRoot":"C:\\State\\Luxury"}}
{"protocolVersion":3,"id":"launch-1","method":"launch","params":{"packageId":"com.example.my-app","installBase":"C:\\Apps","stateRoot":"C:\\State\\Luxury"}}
```

`inspect`, `prepareInstall`, and `install` independently reopen and verify the package. Never reuse a fingerprint from another file or bypass a changed-file failure.

## Events, cancellation, and errors

Install events use `action`, `phase`, and `progress`. Actions are `install`, `update`, `repair`, or CLI-only approved `downgrade`. Install phases are `validating`, `recovering`, `verifying`, `planning`, `applying`, `committing`, `rollingBack`, `completed`, `cancelled`, and `failed`.

Uninstall uses `phase` and `progress`; byte counters are zero. Per-file preserved paths are intentionally not exposed by JSONL.

Cancel an active request with a new request ID:

```json
{"protocolVersion":3,"id":"cancel-1","method":"cancel","params":{"requestId":"install-1"}}
```

The result contains `accepted`. Cancellation is cooperative; wait for the original request's terminal result/error and rollback completion. Launch is no longer cancellable after successful spawn.

Handle stable error codes by cause. Examples include `invalid_request`, `invalid_params`, `busy`, `cancelled`, `permission_denied`, `insufficient_space`, `collision`, `state_conflict`, `recovery_required`, `downgrade_denied`, `reinstall_mismatch`, `publisher_mismatch`, `publisher_migration_required`, `publisher_rotation_denied`, `license_not_accepted`, `unsigned_not_allowed`, and integrity/signature failures. Do not parse human messages for control flow.

## Agent completion checklist

1. Re-run `luxury <changed-command> --help`.
2. Use absolute paths and an external state root.
3. Verify package trust and fingerprint before mutation.
4. Confirm every consent came from the caller.
5. Wait for terminal mutation/rollback output.
6. Run one focused gate, then the required repository gate.
7. Update `README.md`, the applicable guide, `llms.txt`, this skill, and local memory when their contract changed.
8. Report native OS/signing/release evidence that remains unverified.

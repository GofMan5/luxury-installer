# Privileged helper contract

System-scope installation is a separate security boundary, not a boolean variation of the user-scope adapter. The Tauri renderer and webview process must remain at the interactive user's normal integrity level.

## Required flow

```text
React renderer
  -> exact pathless Tauri intent
  -> unelevated Rust Tauri shell
  -> platform-native elevation broker
  -> authenticated one-shot Rust helper
  -> luxury-engine + system-scope platform adapter
```

The helper is not a generic root service. One process handles one reviewed package transition, emits bounded progress, commits or rolls back, closes its transport, and exits.

## Authority and validation

The helper must independently:

1. authenticate the requesting peer through OS identity and the exact launched helper process, not a claimed token;
2. verify its own installed/signed executable identity before accepting authority;
3. reopen the package and match its exact reviewed fingerprint, package ID, host target and system scope;
4. verify the package against a native-container-bound or root-owned publisher trust anchor—never a public key supplied by the renderer or unprivileged request;
5. derive fixed host system roots itself and reject caller-selected install/state roots;
6. execute the existing Rust engine so scope policy, journal, rollback, recovery and receipt rules remain single-source;
7. keep state private to SYSTEM/Administrators or root and keep installed application bytes readable/executable according to native system policy;
8. return only bounded typed progress and aggregate outcomes; paths, keys, receipt bodies and raw platform errors remain privileged.

Every request is versioned and one-shot. It binds an unpredictable operation ID, exact package fingerprint and intended action. Replay, a second request, peer exit, malformed frames, unknown fields, timeout or identity drift fails closed. Cancellation is cooperative before commit and cannot convert a committed mutation into a reported rollback.

## Platform transports

| Platform | Required transport and peer proof | Current status |
| --- | --- | --- |
| Windows | Unelevated shell creates a one-shot named pipe, pins the exact single-link non-reparse helper without write/delete sharing, and, for authenticated actions, compares its embedded signer with the process-image-bound signer of the running Tauri launcher before `ShellExecuteExW(..., "runas")`. The guard remains live through process creation. The shell retains the returned process handle and accepts only a pipe client whose kernel-reported PID equals that launched process and whose token is elevated. Each running peer is then independently bound with `ProcessImageFileMapping` before WinTrust. Native container/helper Authenticode identity supplies package trust. The pipe name is routing data, not a secret. | Read-only system preparation, install, uninstall, and receipt-owned launch are source-complete: pre-UAC helper pin/signer equality, random first-instance/local-only pipe, `runas`, retained process handle, mutual kernel PID/token/running-image WinTrust checks, action-bound duplicated package handle, fixed roots, strict private state, bounded mutation progress/cancel, path-suppressed terminal output, and clean helper exit. Launch duplicates the authenticated unelevated parent token and uses `CreateProcessWithTokenW`; elevated parent/primary tokens fail. Final signed artifact runtime gates remain. |
| Linux | A root-owned installed helper is invoked through a reviewed polkit action. The helper verifies effective UID 0, caller identity/action authorization and root-owned executable/config identity. Portable `pkexec <writable sidecar>` and `sudo sh -c` are forbidden. | Source-complete for install, uninstall and receipt-owned non-root launch. Tauri and helper use a private Unix datagram stdio pair with `SO_PASSCRED` on every JSONL frame and exactly one `SCM_RIGHTS` package FD; fixed helper/policy/launcher identity and ownership are rechecked. The deterministic Linux tree stages helper and policy, but installed root-owned polkit lifecycle and distribution-signature evidence remain. |
| macOS | A signed, notarized helper is registered through the supported launchd/SMAppService flow and validates the caller's designated code requirement. Tauri remains unelevated. Deprecated shell elevation and writable portable helpers are forbidden. | Source-complete for install, uninstall and receipt-owned non-root launch: exact bundled LaunchDaemon plist, socket-activated seqpacket, `LOCAL_PEERTOKEN`, strict app/helper designated requirements, one signed-resource package FD, bounded action frames and kqueue exit observation. Native signed/notarized lifecycle evidence remains. |

## Explicitly forbidden shortcuts

- launching Tauri, WebView2, WebKitGTK or WKWebView as Administrator/root;
- trusting renderer consent, package paths, roots, public keys or claimed helper identity without Rust revalidation;
- putting JSON requests, secrets, license text, keys or package authority in command-line arguments, environment variables or predictable temporary files;
- a long-lived generic privileged command API, arbitrary filesystem operations, shell commands or post-install scripts;
- accepting an unsigned mutable helper/container as the trust root for signed system packages;
- falling back from failed peer/signature/root validation to user-scope or unsigned behavior.

## Completion evidence

System scope is not complete until each supported OS has native tests proving: normal UI is unelevated; elevation cancellation is clean; wrong PID/token/signer/root/fingerprint/replay are rejected without state; helper death rolls back or leaves recoverable state; install/update/repair/uninstall pass through the helper; receipts survive restart; and final signed artifacts pass native runtime gates. Cross-compilation and unit tests alone are insufficient.

Current Windows `--verify-studio`/`--verify-runner` launches the exact packaged Rust backend in non-elevated probe mode. The server creates a CSPRNG-named first-instance pipe with remote clients rejected, validates `GetNamedPipeClientProcessId == Child::id`, and sends a random operation challenge. The backend validates `GetNamedPipeServerProcessId`, pipe-name/operation binding and strict frames before returning its PID; both peers use 15-second bounded polling and the parent requires clean child exit.

For native manual QA, append `--verify-elevated-transport` to exactly one packaged verifier. Windows then launches the same backend through `ShellExecuteExW` with `runas`, keeps the returned process handle, checks that handle's PID and `TokenElevation`, and requires the helper to independently reject a non-elevated token before connecting. Success prints only `{"elevatedTransportVerified":true}`. This proves the UAC/token-bound transport primitive, not Authenticode, package authority or system mutation.

Append `--verify-authenticated-transport` instead to require embedded Authenticode on both running binaries and the exact same SHA-256 DER leaf certificate. The helper obtains the server PID from the pipe, opens the reported image without write/delete sharing, and requires `ProcessImageFileMapping` to bind that exact file object to the process before WinTrust; renaming the running executable and replacing its old pathname therefore fails closed. Current unsigned development artifacts must fail with exit 1. `cargo verify-windows-signers -- <launcher.exe> <helper.exe>` exposes the same certificate gate without UAC; catalog-only Windows files intentionally fail because a portable helper requires its own embedded signature.

All system actions, including read-only preparation, are bound without a package path. The parent opens one exact regular single-link non-reparse package handle with write/delete sharing denied and sends only operation/action/package identity, the inherited handle value, and install-only UI consents after authentication. The helper retains one `PROCESS_QUERY_INFORMATION | PROCESS_DUP_HANDLE` handle for the authenticated parent, duplicates the package handle into itself, requires unsigned-v1 native-container binding, exact identity/fingerprint, host target and `scope=system`, and derives fixed Known Folder roots. Authorization returns the strict `prepare_system_install` outcome used for initial and retry maintenance review; no root or receipt path crosses into Tauri or the renderer. Install invokes `InstallCommand::for_system` plus `LocalInstallAdapter::for_system`; uninstall invokes the pathless `UninstallCommand::for_system` plus `LocalUninstallAdapter::for_system`, so only receipt-owned unchanged files can be removed. Launch invokes `LaunchCommand::for_system` through the same receipt/hash/lock validation, rejects an elevated parent token, duplicates it as a primary token, creates the user's environment, opens and retains every real parent directory without delete sharing, and calls `CreateProcessWithTokenW` for the exact entrypoint without arguments while those parent and final-file guards remain live. Completed-install reveal is not a new privileged action: after the helper's strict terminal result, the unelevated Rust shell derives the same install base from `luxury-system-roots`, joins only the authenticated one-component install directory, and calls the native opener with no renderer path. Unknown fields—including caller roots/paths, entrypoints or file lists—are rejected, and frames cannot cross-complete actions. Progress is coalesced to a bounded number of aggregate frames; modified-file paths stay inside Rust; cancellation is sampled at engine safe checkpoints and cannot rewrite a committed result. `--verify-system-authorization` remains a non-mutating signed-artifact gate.

Linux uses the same action/result vocabulary over newline-terminated JSON datagrams capped at 4 KiB. The Tauri process creates the socket pair before `pkexec`; `SO_PEERCRED` binds the original unprivileged creator and `SO_PASSCRED` binds every challenge, request, cancellation and response to its actual sender. The reviewed package crosses only once as `SCM_RIGHTS`; the helper requires one root-owned, single-link, non-writable regular FD and independently reopens the bundle. The polkit action is bound only to `/usr/libexec/luxury-installer-helper`; that installed executable rejects every ordinary CLI/stdio command before dispatch. Launch reuses system receipt/hash/lock validation, opens the install root and receipt entrypoint through one no-follow descriptor-relative chain, clears inherited environment, copies only a bounded desktop allowlist, drops supplementary groups/GID/UID, `fchdir`s to the retained root and executes the verified `/proc/self/fd/N` entrypoint. Neither old pathname is reopened and the cwd FD remains CLOEXEC. The portable tar is never an authority source.

macOS 13+ registers `Contents/Library/LaunchDaemons/software.luxury.installer.helper.plist` with `SMAppService`. launchd owns a fixed `seqpacket` socket and activates the bundled helper for one connection; the helper accepts exactly one action and exits. Both peers read `LOCAL_PEERTOKEN` and Security.framework validates strict app/helper designated requirements using the embedded 10-character `LUXURY_APPLE_TEAM_ID`. The helper revalidates the caller after receiving one `SCM_RIGHTS` FD, requires that descriptor to be the exact `Contents/Resources/payload/package.luxpkg` inode inside the validated signed app, and only then opens the bundle and fixed system roots. Launch resolves the authenticated account/groups, opens the receipt entrypoint beneath one no-follow install-root FD, drops groups/GID/UID, `fchdir`s to that retained root and invokes fixed `/bin/launchctl asuser` so the application enters the user's bootstrap namespace without application arguments. launchctl still resolves the executable pathname. `cargo verify-macos-release` separately requires strict nested codesign, Gatekeeper acceptance and a stapled notarization ticket.

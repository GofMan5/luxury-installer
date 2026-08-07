---
name: luxury-installer-cli
description: Build native Luxury Installer outputs, inspect and sign internal packages, automate install/update/repair/uninstall/launch, and use the strict JSONL v3 protocol. Use for Luxury Installer repository work, AI-driven authoring, CI, Studio backend operations, or any request involving the luxury command or native packager.
---

# Luxury Installer CLI

Use the repository's current binary as authority. Never guess a command or retain a removed flag.

## Start

1. Locate the repository root and inspect `git status --short`.
2. Read the applicable local working contract when the workspace supplies one.
3. Run `luxury --help` and `luxury <command> --help`; in a source checkout use `cargo run -p luxury -- <command> --help`.
4. Read [references/cli.md](references/cli.md) before authoring a package, mutating an installation, or implementing JSONL.
5. Preserve unrelated work and use absolute paths for every JSONL filesystem field.

## Choose the interface

- Use the human CLI for one-shot local or CI commands.
- Use `luxury stdio` for a long-lived typed v3 subprocess, Tauri integration, or an AI tool that needs structured results, progress, cancellation, and stable errors.
- Use Studio for interactive unsigned-v1 authoring. Save or explicitly undo a dirty draft before new/open/reload; Rust owns close confirmation and treats a missing correlated renderer reply as dirty. Add files without overwrite or replace the complete payload from one native-selected directory; keep every native selection in the Rust shell and never give the renderer generic filesystem or dialog authority.
- Use `cargo project-installer -- <absolute-project> <absolute-native-output>` for the file a user ships: Windows `.exe`, Linux `.deb` + `.rpm`, or macOS `.dmg`. Treat `.luxpkg` as the low-level signing/lifecycle boundary, not the Studio result.
- Use the final bound launcher's read-only `--info-json` for inventory and `--unattended-install` / `--unattended-uninstall` for deployment. Never extract its internal package or invent path flags; pass consent flags only with explicit caller authority.

## Execute safely

- Run `prepare-install` or JSONL `prepareInstall` before an install/update/repair when presenting a plan. Treat it as advisory and read-only; the mutation repeats every authoritative check.
- Keep `state-root` outside the removable install tree and reuse the same roots for update, repair, uninstall, and launch.
- Pass a private signing key only through the documented stdin flag. Never put it in argv, JSONL, environment variables, project files, logs, fixtures, or chat output.
- Supply consent flags only when the caller explicitly authorized them. Never infer unsigned, license, downgrade, or publisher-migration consent.
- Treat `install.show_install_log` as presentation policy only: Setup shows the bounded authenticated manifest projection during and after installation, never raw backend output or privileged paths.
- Treat stdout from `luxury stdio` as protocol-only. Drain stdout and stderr independently and keep request IDs unique while active.
- Treat a cancel transport error as an active operation, not a cancelled result. Keep reading the original request, show the bounded error, and retry only the pathless cancel intent; terminal cancellation requires the original correlated result/error after rollback.
- On the completed Setup surface, keep launch/reveal/link/close failures inline. Record a successful launch before requesting window close and never repeat launch to recover from a close error.
- Do not retry collisions, state conflicts, publisher failures, downgrade denial, or reinstall mismatch without changing the proven cause.
- Native multi-build requires matching Windows/Linux/macOS runners. Never claim that Windows produced a notarized macOS artifact or publish the blocked Linux desktop graph.
- Studio/native packager supervision must use `luxury-process`; cancellation and timeout are incomplete until the complete descendant tree is terminated and reaped.
- For an OS-specific repository change, dispatch `.github/workflows/ci.yml` with `native_scope=linux-x64`, `windows-x64`, or `macos-arm64`. Use the default `all` only for the complete three-host lifecycle gate; only `all` merges the evidence set, and no mode proves production signing.

## Verify

Run the smallest relevant gate:

- CLI or compiler behavior: `cargo test -p luxury --locked` or a focused test filter.
- Core cross-crate behavior: `cargo quick --locked`.
- Renderer/Tauri contract: `cargo gui-check` after the frozen pnpm install.
- Release work: use the host-native command and signing order documented in the repository; never infer release readiness from a cross-check or one scoped native lane.
- Windows Setup inventory evidence must come from the final outer `.exe`; project/release verification rejects `--info-json` schema or stdout/stderr transport drift.

Before finishing, compare every changed command, JSONL method, package field, and example across `README.md`, `docs/`, `llms.txt`, this skill, and local project memory when its contract changed. Remove stale syntax instead of preserving compatibility prose.

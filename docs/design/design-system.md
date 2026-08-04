# Codex-style desktop UI

This document describes the Tauri 2 + React renderer in `apps/luxury-installer`. It is a presentation contract; installer policy and desktop authority remain in Rust.

## Direction

The interface follows the flat dark language of Codex and ChatGPT:

- charcoal canvas and darker navigation rail;
- square geometry with `0 px` radii;
- neutral borders and surfaces instead of floating cards;
- ChatGPT green only for verification, progress, and focus;
- no blue glow, ambient gradient, decorative ring, pill, or glass effect;
- no status badges, oversized icon containers, dashboard tiles, or nested cards; status is plain icon + text and content is arranged as open rows;
- no internal package/runtime terminology in Setup end-user copy; Studio uses only terms needed for authoring.

Setup makes four facts obvious: which application is being installed, where it will be installed, whether its publisher is trusted, and what the installation is doing. Studio keeps project actions in the rail and one flat form for validated identity, target, install policy, license, finish links, payload import, and build. Its empty surface may show up to six recent projects as a flat two-column list with name, publisher/version, target, and a truncated display-only path; opening one sends only its bounded index.

## Implementation stack

- Tauri webview window with a Rust-owned native lifecycle and custom drag region.
- React + TypeScript renderer.
- Typed Tauri invoke/events with an exact capability allowlist.
- Native HTML controls and DOM/ARIA semantics.
- CSS custom properties, grid/flex layout, and media queries.
- Supported named Lucide exports from the already-pinned package; no second icon library.
- Renderer receives no generic shell, filesystem, dialog, opener, or process capability; business logic is not copied from Rust.

## Tokens

| Token | Value | Use |
| --- | --- | --- |
| `canvas` | `#212121` | main window background |
| `rail` | `#171717` | product and step rail |
| `surface` | `#282828` | primary flat surface |
| `surface-hover` | `#2F2F2F` | hover surface |
| `surface-strong` | `#242424` | secondary surface |
| `border` | `#343434` | separators |
| `border-strong` | `#4A4A4A` | interactive borders |
| `text` | `#F2F2F2` | primary text |
| `muted` | `#B4B4B4` | supporting copy |
| `faint` | `#8D8D8D` | inactive metadata |
| `accent` | `#10A37F` | progress and focus |
| `accent-strong` | `#19C59A` | active icon or label |
| `warning` | `#E7B84B` | unsigned publisher consent |
| `danger` | `#FF6B6B` | blocking failure |

All component radii are zero. Focus remains a visible two-pixel green ring and never relies on color alone.

## Layout

- Configured desktop window: `1080 × 720`; minimum: `900 × 600`.
- Native overlay/titlebar region: `42 px`.
- Setup and Studio rail: `236 px`; `216 px` below `980 px`; Setup rail is hidden below `760 px` and Studio actions become a compact top row.
- Studio project workspace: `min(920 px, 100%)`.
- Setup main screen: `min(780 px, 100%)`.
- Spacing follows `4, 8, 12, 16, 24, 32, 48` with small optical adjustments.
- A height breakpoint compacts the layout below `660 px` without hiding the primary action.
- No horizontal or nested vertical scrolling at the configured minimum window size.

## Typography

- UI stack: platform UI sans-serif, `Segoe UI Variable`, `Segoe UI`, then `sans-serif`.
- Paths and counters: `Cascadia Code`, `SFMono-Regular`, `Consolas`, then `monospace`.
- Display title: responsive `28–34 px`, semibold, tight line height and tracking.
- Body: `14 px / 1.6`.
- Controls: `12–13 px`, semibold.
- Labels: `9–11 px`; required instructions never use faint contrast.

No font download is required at runtime.

## Screen states

### Studio

- Empty: offer only `Новый проект` and `Открыть проект`; no HTML file input or drag-and-drop.
- Loading: disable project actions while the Rust-owned native dialog and validation complete.
- Ready: show the current project, manifest facts, payload counts/size, target, one primary build action, and secondary native-folder/reload actions in the rail.
- Refreshing: preserve the last validated summary, disable project actions, and show one bounded validation status until Rust returns the replacement summary.
- Building/built: show bounded Rust progress copy, then the selected output path from the validated result.
- Error: preserve the active project when possible and keep one dismiss action.
- V2/v3 projects remain openable and validated, but GUI build is disabled with a CLI/stdin signing note; v3 explains that PoP is verified during CLI build with the current key.

### Setup booting

- Show `Подготовка установки` while the bound payload is inspected and Rust performs read-only transition preparation.
- There is no package picker, drag-and-drop, file input, or replacement action in Setup mode.
- A missing or corrupt bound payload is a blocking error.

### Setup review

- Show application name, publisher, version, byte size, Rust-owned install base, final directory, and Rust-classified install/update/repair/recovery intent.
- Never expose package path, package ID, backend version, target triple, or archive vocabulary.
- `Файлы проверены` communicates integrity without leaking hash implementation detail.
- Unsigned installation requires explicit consent with plain-language publisher guidance.
- Update copy names both installed and requested versions; repair/recovery copy does not promise mutation before the user starts it.
- When Rust preparation proves an installed version, show `Удалить` as a secondary maintenance action. First activation expands one inline confirmation; focus defaults to `Отмена`, and copy states that modified files are preserved.

### Setup license

- A package with schema-v3 `package.license` changes the review primary action to `Далее` and opens a separate agreement screen; packages without a license keep the direct install action.
- Render authenticated text only as escaped plain text in one bounded, keyboard-scrollable square document surface. Do not interpret HTML, Markdown, links, ANSI, or bidi controls.
- `Принять и продолжить` remains disabled until the native checkbox is checked. Back navigation keeps the reviewed package/destination; Rust independently requires `acceptLicense=true` before mutation.

### Setup progress and cancellation

- Show percentage, file/byte counters, and four user-facing stages.
- Do not expose `manifest`, `objects`, `recovery`, `receipt`, `commit`, or `rollback` in visible copy.
- Disable cancellation after cancellation begins or while the terminal state is being saved.
- Uninstall progress shows file counters only; do not invent byte progress. Its rail/heading say `Удаление`, not installation.
- Successful install/update/repair stays on the completed progress surface and enables one primary `Далее`; it does not jump directly to the finish screen.
- When the authenticated package opts into `show_install_log`, use one native square `<details>` disclosure for destination, factual counts, up to 128 relative manifest paths, and the omitted count. Keep it collapsed by default and never render raw backend/stderr text.

### Setup complete and error

- Complete state follows the explicit `Далее`, uses the factual post-recovery install/update/repair result, and offers `Показать в папке` and `Готово`. Setup never authorizes downgrade; `downgrade_denied` is an error, not a renderable action. When Rust inspection exposes only `hasEntrypoint=true`, add one primary `Запустить` action between them; when finish links exist, render their authenticated labels as secondary actions. Renderer sends only the selected link index, never a URL. While an action is pending, disable all result actions and show inline progress text. Launch success closes Setup; link/reveal failures stay inline. Never show the entrypoint path or auto-run.
- A rejected destination chooser keeps the previous valid review and renders one inline actionable error below the destination row. Do not replace the whole Setup flow with the generic terminal error screen.
- Uninstall complete has no reveal action and summarizes removed, already-missing and preserved-modified counts; all-zero is presented as already removed.
- Error state gives one bounded actionable message and offers retry only when safe.
- Never expose raw stack traces, host paths, control characters, or backend text; main maps stable error codes to bounded public copy.

## Navigation and accessibility

- Setup rail middle step follows the prepared action (`Установка`, `Обновление`, or `Восстановление`); the current step uses `aria-current="step"`.
- Studio rail exposes `Новый проект`, `Открыть проект`, and—only with an active project—`Папка проекта` and `Перепроверить`, plus the current validated project identity. Payload actions stay beside the payload summary; entrypoint selection stays beside its field. Native-dialog actions disable while settings are unsaved so a returned summary cannot discard the draft.
- Tab order follows visual order; native buttons and checkbox keep keyboard behavior.
- Every screen has a labelled heading; errors use `role="alert"`; progress exposes numeric ARIA values.
- Icons that repeat visible text are hidden from assistive technology.
- `:focus-visible` stays visible and `prefers-reduced-motion` collapses animation durations.

## Boundary rule

Renderer state may format already-validated data. Studio create/open/import/entrypoint/reveal/reload/build actions carry no filesystem paths: the Rust Tauri shell owns native dialog results and the authoritative active project. The renderer may submit only strict portable settings and receive display-only project/output paths or a validated relative entrypoint. System Setup review keeps `destination=null`, renders a fixed-system-location row, and never exposes a chooser or an invented system path. System install/uninstall use the same pathless buttons and aggregate progress. System completion exposes launch only when the Rust review reports a receipt-owned entrypoint; Windows uses the authenticated unelevated token, Linux drops the authenticated groups/GID/UID, and macOS drops credentials before fixed `launchctl asuser`. System reveal stays hidden because it is not implemented. Inspection, path policy, trust, transaction state, rollback, ownership receipt, and terminal results come from Rust through typed Tauri commands/events backed by `luxury stdio` or the one-shot privileged Rust helper. Presentation must not become a second policy implementation.

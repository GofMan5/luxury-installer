# Native build matrix example

This example keeps one small installer project per native target:

```text
windows/  -> Windows x64 Setup.exe
linux/    -> Linux x64 .deb + .rpm
macos/    -> macOS ARM64 .dmg
```

The projects intentionally share package identity but keep target, architecture, payload, executable markers, and entrypoint target-specific. Replace each `payload/` with the matching application build; payload links are rejected, so do not join target trees with symlinks.

Run **Actions → Native project build** with the default inputs to build this example. The three downloadable artifacts are unsigned development outputs and each includes `SHA256SUMS.txt`.

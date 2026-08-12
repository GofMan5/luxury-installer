# Native build matrix example

This example keeps one small installer project per native target:

```text
windows/  -> Windows x64 Setup.exe
linux/    -> Linux x64 .deb + .rpm
macos/    -> macOS ARM64 .dmg
```

The projects intentionally share package identity but keep target, architecture, payload, executable markers, and entrypoint target-specific. Replace each `payload/` with the matching application build; payload links are rejected, so do not join target trees with symlinks.

These three directories are the workflow defaults, so **Actions → Native project build** builds this example with no inputs at all. The three downloadable artifacts are unsigned development outputs, each includes `SHA256SUMS.txt`, and they are retained for 14 days.

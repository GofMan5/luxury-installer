## What changed

<!-- Describe one complete vertical slice and its user/developer impact. -->

## Boundary

<!-- Which layer owns the behavior: spec, engine, platform, CLI/stdio, Tauri, renderer, tooling? -->

## Verification

<!-- List exact commands and results. Do not claim another OS from one host run. -->

## Checklist

- [ ] The diff is focused and contains no generated artifacts, payloads, keys, tokens, or unrelated changes.
- [ ] Package-controlled values are validated at every changed trust boundary.
- [ ] Mutations preserve rollback, ownership receipts, cancellation, and recovery semantics.
- [ ] Renderer commands remain pathless/typed and the Tauri ACL stays exact.
- [ ] Documentation and `MEMORY.md` are updated when the architecture, package, protocol, or build contract changed.
- [ ] Remaining native/release gaps are stated without a production-ready claim.

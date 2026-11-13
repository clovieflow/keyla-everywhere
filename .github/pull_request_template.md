## What

<!-- One or two sentences: what changes and why. -->

## Verification

<!-- Paste or check what you ran. Do not claim a command passed unless it was executed. -->

### Rust backend (required for any `crates/` or `migrations/` change)

- [ ] `cargo fmt --all --check`
- [ ] `cargo clippy --workspace --all-targets -- -D warnings`
- [ ] `cargo test --workspace`

### Dashboard (required for `dashboard/` changes)

- [ ] `bun run dashboard:typecheck`

## Docs

<!-- Required when the change adds a route group, provider capability, env var,
     or DB table. -->

- [ ] No doc update needed (why: <!-- ... -->)
- [ ] Updated: <!-- e.g. README.md, .env.example -->
- [ ] No `file:line` refs added to any committed doc (anchor citations to symbols and paths — line numbers drift)

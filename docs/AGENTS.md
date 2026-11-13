# Keyla Everywhere Agent Guide

Keyla Everywhere is a Rust gateway (Axum + SQLx) with a Vite/React dashboard.
The gateway, provider adapters, console API, CLI, migrations, and packaging are
Rust; the dashboard is the only TypeScript source and talks to the gateway over
HTTP only.

## Core rule

Every reported issue must be reproduced or explicitly flagged as unverified.
Fix the owning layer and migrate every caller; do not ship a workaround disguised
as a fix. Keep the smallest complete change that proves its acceptance criteria.

## Layout

- `crates/keyla-gateway` — HTTP server, `/v1` surfaces, dispatch loop.
- `crates/keyla-providers` — provider metadata, OpenAI-compatible and bespoke
  adapters (`qoder`, `kiro`, `buddy`, `antigravity`, `devin`, `mimostudio`,
  `mimodesktop`, `gemini`, `adapter`).
- `crates/keyla-console` — `/console/api`, OAuth, quota, CLI injectors.
- `crates/keyla-db` — schema stores, embedded migrations/models.
- `crates/keyla-protocol` / `keyla-core` — canonical wire types.
- `crates/keyla-routing` — route planning, eligibility, simulation.
- `crates/keyla-security` — credentials, admission, auth, CSRF.
- `crates/keyla-cli` — `keyla` binary and lifecycle commands.
- `dashboard/` — browser console; it must not import deleted backend sources.
- `migrations/` — SQL, embedded into the binary at build time.

## Working agreement

- Keep code, docs, and tests together as one coherent change.
- Run the narrowest gate that proves the change, then the workspace gates:
  `cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D warnings`,
  `cargo test --workspace`, and for dashboard edits
  `bun run dashboard:typecheck && bun run dashboard:test && bun run dashboard:build`.
- Never claim upstream provider behavior was verified without a live credential;
  say exactly what remains unverified.
- Do not commit, push, deploy, or touch production data unless explicitly asked.
- Never expose credentials or provider payloads in output.

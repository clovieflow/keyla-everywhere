# Keyla Everywhere

Keyla Everywhere is a self-hosted AI gateway: one OpenAI/Anthropic-compatible
endpoint in front of many upstream providers, with routing, quotas,
observability, and an operator console.

The rebrand uses Keyla Everywhere naming throughout: `keyla` binary, `KEYLA_*`
environment variables, `keyla-*` crates, `keyla:*` storage keys, `Keyla` data
directory, and `keyla_schema_migrations`. It is a clean break; deployments
with the old identifiers must export/import their data into a fresh install.

The backend is Rust. `src/` no longer exists; the dashboard is the only
TypeScript source and is a pure HTTP client of the gateway.

## Repository layout

| Path | Purpose |
|---|---|
| `crates/` | 11 Rust crates: gateway, providers, console, DB, protocol, routing, security, observability, config, core, CLI |
| `dashboard/` | React/Vite landing, console, and public share UI |
| `migrations/` | SQL schema and forward migrations, embedded into the binary |
| `deploy/` | Dockerfile and Compose deployment |
| `docs/` | Agent guide, changelog, and notices |

## Build

```bash
bun install                 # dashboard dependencies
bun run dashboard:build     # emits dist/dashboard (embedded by cargo)
cargo build --release -p keyla-cli --bin keyla
```

The release binary embeds the dashboard and migrations. Run it with:

```bash
DATABASE_URL=postgresql://user:pass@127.0.0.1:5432/keyla \
KEYLA_ENCRYPTION_KEY='<base64 32-byte key>' \
./target/release/keyla up
```

`keyla setup` writes a `.env` with a generated encryption key; `start`,
`down`, `restart`, `logs`, `status`, and `doctor` manage a detached instance.
Without `DATABASE_URL` the gateway boots an embedded PostgreSQL under
`KEYLA_DATA_DIR`.

Docker deployment lives in `deploy/`:

```bash
docker compose -f deploy/docker-compose.yml up --build
```

## Development

```bash
cargo run -p keyla-gateway     # port 12800
bun run dashboard:dev             # Vite dashboard against it
```

Gates: `cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D warnings`,
`cargo test --workspace`, `bun run dashboard:typecheck`, `bun run dashboard:test`,
`bun run dashboard:build`.

## Providers

OpenAI-compatible providers use the shared chat adapter. Bespoke adapters live
in `crates/keyla-providers`: Qoder (COSY), Kiro (AWS EventStream), Buddy
(CodeBuddy/WorkBuddy), Antigravity (Cloud Code), Devin (Connect+protobuf), and
Xiaomi MiMo Studio/Desktop. Provider-specific upstream behavior that has not
been exercised against a live account is explicitly documented as unverified.

Antigravity browser OAuth requires operator-supplied Google OAuth credentials:
`KEYLA_ANTIGRAVITY_CLIENT_ID` and `KEYLA_ANTIGRAVITY_CLIENT_SECRET`. They are not
bundled with the source.

## License

GPL-3.0-only. See `LICENSE` and [`docs/NOTICE.md`](docs/NOTICE.md).

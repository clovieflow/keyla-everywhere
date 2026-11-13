# Keyla Everywhere

Keyla Everywhere is a self-hosted AI gateway and operator console. It exposes one
OpenAI/Anthropic-compatible endpoint in front of many providers, with routing,
failover, API keys, quotas, usage accounting, logs, and a browser console.

The gateway, provider adapters, console API, CLI, migrations, and packaging are
Rust. The dashboard is a React/Vite browser client; it is served as static assets
by the Rust binary and talks to the gateway over HTTP only.

## What it does

- One base URL for OpenAI Chat, OpenAI Responses, Anthropic Messages, legacy
  completions, and native search.
- 45 built-in provider definitions and 466 seeded model rows, plus compatible
  custom endpoints.
- Ordered routing: aliases, combos, fallback, weights, health, cooldown, quota,
  concurrency, and per-key model access.
- Provider credentials, scoped API keys, tenant isolation, CSRF, rate limits,
  and SSRF-safe outbound requests.
- Usage, latency, token, cost, quota, audit, and live log views.
- A route simulator that uses the gateway's own eligibility owner.
- Bansos: publish a subsidized key and a public access page.
- One Rust binary; PostgreSQL is the only required service. Redis is optional.

## Repository layout

| Path | Purpose |
|---|---|
| `crates/keyla-gateway` | HTTP server, `/v1` surfaces, dispatch loop |
| `crates/keyla-providers` | Provider registry and adapters |
| `crates/keyla-console` | `/console/api`, auth, OAuth, quota, logs, share, bansos |
| `crates/keyla-db` | PostgreSQL pool, embedded migrations, catalog seed |
| `crates/keyla-protocol` / `keyla-core` | Canonical wire types and codecs |
| `crates/keyla-routing` | Eligibility, ordering, fallback, simulation |
| `crates/keyla-security` | Keys, scopes, CSRF, crypto, admission, model abuse |
| `crates/keyla-observability` | Metrics and runtime counters |
| `crates/keyla-config` | Environment contract and path resolution |
| `crates/keyla-cli` | `keyla` binary and lifecycle commands |
| `dashboard/` | Landing, operator console, and public share UI |
| `migrations/` | SQL migrations embedded into the release binary |
| `deploy/` | Dockerfile and Compose deployment |
| `docs/` | Agent guide, changelog, and notices |

## Requirements

- Rust **1.87+** with Cargo.
- Bun **1.4.x** for building the dashboard.
- PostgreSQL reachable by `DATABASE_URL` (or libpq variables).
- Redis optional. Without it, admission limits use in-process state.
- macOS or Linux for the source-first CLI. Docker is the simplest path on
  other hosts.

The current release does **not** boot an embedded PostgreSQL database. If no
database is configured, the process serves the shell but `/v1` and console data
routes remain unavailable. This is intentional and visible in `keyla doctor`
and the startup warning.

## Quick start from source

```bash
git clone https://github.com/clovieflow/keyla-everywhere.git
cd keyla-everywhere

bun install
cargo build --release -p keyla-cli --bin keyla
./target/release/keyla setup
```

`keyla setup` writes `.env` beside the current working directory and generates
`KEYLA_ENCRYPTION_KEY` if it is absent. It does not invent a database. Edit
`.env` and set at least:

```dotenv
DATABASE_URL=postgres://keyla:secret@127.0.0.1:5432/keyla
KEYLA_PUBLIC_ORIGIN=http://127.0.0.1:12800
```

Then either run in the foreground:

```bash
./target/release/keyla up
```

or run detached:

```bash
./target/release/keyla start
./target/release/keyla status
./target/release/keyla logs --lines 100
```

Open `http://127.0.0.1:12800/console`. The first visit creates the operator
account; later visits use the operator password. Put `target/release` on
`PATH`, or symlink `keyla` into a directory already on `PATH`, so the commands
below can be run as `keyla …`.

### Useful first checks

```bash
keyla doctor
keyla status
curl -fsS http://127.0.0.1:12800/health
curl -fsS http://127.0.0.1:12800/health/ready
```

`doctor` checks the encryption key, database reachability, migration ledger,
and seeded provider/model counts. It never prints credentials.

## One-command update

In a clean source checkout, with Bun and Cargo installed:

```bash
keyla update
```

That command performs the whole release update:

1. Refuses to run with a dirty working tree.
2. Runs `git pull --ff-only`.
3. Runs `bun install` and `bun run dashboard:build` when `dashboard/` exists.
4. Runs `cargo build --release -p keyla-cli --bin keyla`.
5. Installs the new binary over the running `keyla` executable when writable.
6. If a detached gateway is running, stops it and starts the new binary again.

Use `keyla update --no-restart` when you want to build and install without
restarting the gateway. New embedded SQL migrations are applied automatically
on the next start.

`keyla update` intentionally does **not** work in a binary-only release or
outside a Git checkout. Replace the binary with the new release and run
`keyla restart` instead. If the executable is in a root-owned location, update
the binary with the appropriate permissions; the command will report the built
path instead of silently restarting an old binary.

## CLI reference

| Command | What it does |
|---|---|
| `keyla` / `keyla up` / `keyla serve` | Run the gateway in the foreground |
| `keyla start` | Start a detached process, writing `keyla.pid` and `keyla.log` under the data directory |
| `keyla down` | Send `SIGTERM` to the detached process and wait for drain |
| `keyla restart` | Stop and start the detached process |
| `keyla logs [--lines N]` | Print the last N lines of the detached log (default 100) |
| `keyla setup` | Create/repair `.env` and generate `KEYLA_ENCRYPTION_KEY` if needed |
| `keyla update [--no-restart]` | Pull, build, install, and optionally restart a source checkout |
| `keyla status [--url URL]` | Probe `/health/ready`; exit 1 when not ready |
| `keyla doctor` | Check config, Postgres, migrations, and catalog counts |
| `keyla version` | Print the binary version |
| `keyla help` | Print command help |

The PID and log locations come from the resolved data directory:

- macOS: `~/Library/Application Support/Keyla/`
- Linux: `$XDG_DATA_HOME/Keyla/` or `~/.local/share/Keyla/`
- Windows: `%APPDATA%/Keyla/`

Override with `KEYLA_DATA_DIR`.

## Configuration

Copy `.env.example` to `.env`; never commit `.env`. The most important variables:

| Variable | Default | Notes |
|---|---|---|
| `PORT` | `12800` | Gateway and console listener port |
| `KEYLA_BIND_HOST` | `127.0.0.1` | Use `0.0.0.0` only inside a trusted container/proxy boundary |
| `DATABASE_URL` | — | **Required** PostgreSQL URL. `DATABASE_PRIVATE_URL`, `DATABASE_PUBLIC_URL`, `PGHOST`, `PGPORT`, `PGUSER`, `PGPASSWORD`, `PGDATABASE` are accepted alternatives |
| `KEYLA_ENCRYPTION_KEY` | — | **Required** 32-byte key, base64 or 64-char hex. It decrypts provider credentials and API-key material |
| `KEYLA_PUBLIC_ORIGIN` | — | Public URL used to build OAuth callback URLs |
| `KEYLA_DATA_DIR` | per OS | Writable state root for pid, log, install id, and payload captures |
| `DASHBOARD_DIST` | `./dist/dashboard` | Built dashboard directory; release binaries usually use their embedded copy |
| `LOG_LEVEL` | `info` | `debug`, `info`, `warn`, `error` |
| `REDIS_URL` | — | Optional shared admission/coordination. Falls back to in-process limits when absent |
| `KEYLA_ALLOWED_NETWORKS` | — | Extra private CIDRs allowed for upstreams |
| `KEYLA_ALLOW_PRIVATE_UPSTREAMS` | — | Allow private upstream destinations; keep off unless needed |
| `KEYLA_ANTIGRAVITY_CLIENT_ID` | — | Operator-supplied Antigravity Google OAuth client id |
| `KEYLA_ANTIGRAVITY_CLIENT_SECRET` | — | Operator-supplied Antigravity Google OAuth client secret |

See `.env.example` for the complete list of timeouts, proxy, telemetry, quota,
cooldown, and abuse-policy settings.

### Encryption key

Generate a key:

```bash
openssl rand -base64 32
```

Keep the same `KEYLA_ENCRYPTION_KEY` across backups and restores. Changing it
does not re-encrypt existing provider credentials; those records become
undecryptable. Rotate credentials deliberately through the console.

### PostgreSQL

Create a database and user, for example:

```bash
createdb keyla
export DATABASE_URL='postgres://'"$USER"'@127.0.0.1:5432/keyla'
```

The binary applies the embedded migration ledger at startup. A database with
the old project identifiers is a clean-break installation: export its data and
import into a fresh database rather than pointing the new binary at the old
ledger.

## Docker

Docker Compose lives in `deploy/` and uses the repository root as its build
context:

```bash
cp .env.example .env
# edit .env: DATABASE_URL, KEYLA_ENCRYPTION_KEY, KEYLA_PUBLIC_ORIGIN

docker compose -f deploy/docker-compose.yml up --build -d
docker compose -f deploy/docker-compose.yml logs -f app
```

The Compose file bundles Redis when no `REDIS_URL` is supplied. PostgreSQL is
never bundled; point `DATABASE_URL` at a local or managed instance. The named
`keyla-data` volume holds install identity, logs, and payload captures, not the
database.

To use a different env file:

```bash
KEYLA_ENV_FILE=/absolute/path/to/.env \
  docker compose -f deploy/docker-compose.yml up --build -d
```

## Gateway surfaces

| Path | Purpose |
|---|---|
| `GET /health` | Liveness |
| `GET /health/ready` | Readiness, including database state |
| `GET /metrics` | Prometheus metrics |
| `POST /v1/chat/completions` | OpenAI Chat Completions |
| `POST /v1/responses` | OpenAI Responses |
| `POST /v1/messages` | Anthropic Messages |
| `POST /v1/completions` | Legacy completions |
| `GET /v1/models` | Authorized model catalog |
| `POST /v1/search` | Native web search |
| `/console` | Operator console (session auth) |
| `/console/api/*` | Console API (session + CSRF or scoped bearer) |
| `/share/:token` | Public enrollment/share page |

Point an OpenAI-compatible client at `http://HOST:PORT/v1` and use an API key
created under **Kunci API**. Anthropic clients use `/v1/messages` with the
equivalent key header. Model ids can be provider-qualified or an alias/combo
defined in the console.

## Providers

1. Open **Providers** in the console.
2. Add an API key or complete the provider's OAuth/device flow.
3. Sync/register models.
4. Add the provider to a route/combo or rely on its direct model ids.
5. Check **Kuota**, **Kesehatan**, **Penggunaan**, and **Log** before sending
   production traffic.

Antigravity OAuth needs operator-supplied `KEYLA_ANTIGRAVITY_CLIENT_ID` and
`KEYLA_ANTIGRAVITY_CLIENT_SECRET`; no client secret is shipped in the repo.
Provider-specific upstream behavior that has not been exercised against a live
account is deliberately not claimed as verified.

## Backup and restore

The database is the authoritative store. Use PostgreSQL tooling:

```bash
pg_dump "$DATABASE_URL" --format=custom --file=keyla.dump
pg_restore --clean --if-exists --dbname="$DATABASE_URL" keyla.dump
```

Keep the database dump and `KEYLA_ENCRYPTION_KEY` together. The console's
backup export is convenient for a portable copy, but `pg_dump` is the recovery
path for a full installation. Test a restore into a disposable database before
relying on it.

## Update, restart, and rollback

```bash
keyla update                  # source checkout: pull + build + install + restart
keyla update --no-restart     # build/install only
keyla restart                 # restart the installed binary
keyla logs --lines 200        # inspect the new process
keyla status                  # readiness probe
```

If update fails:

- `working tree is dirty`: commit or stash first; `keyla update` will not mix
  local edits with upstream changes.
- `git pull failed`: resolve the checkout/remote issue, then retry.
- `cannot replace …`: the installed binary is not writable. Run from the
  checkout with proper permissions, or copy `target/release/keyla` manually.
- Gateway restart fails: `keyla logs`, `keyla doctor`, and `keyla status` show
  the database/migration failure without exposing credentials.

To roll back, restore the previous binary and restart. Database migrations are
forward-only; use the tested backup/restore path when a schema rollback is
required.

## Troubleshooting

| Symptom | Check |
|---|---|
| `no PostgreSQL configuration found; serving the shell without /v1` | Set `DATABASE_URL` (or `PGHOST`/`PGPORT`/`PGUSER`/`PGPASSWORD`/`PGDATABASE`) and restart |
| `keyla doctor` says `migrations: pending` | The database user needs schema privileges; start the gateway and inspect `keyla logs` |
| Provider credentials fail to decrypt | The current `KEYLA_ENCRYPTION_KEY` differs from the key that encrypted them; restore the old key or re-enter the credentials |
| Console login loops or returns 401/403 | Check `KEYLA_PUBLIC_ORIGIN`, the operator password, session cookies, and the key/user scopes |
| `keyla status` is unreachable | Check `PORT`, `KEYLA_BIND_HOST`, firewall rules, and whether the detached process is running |
| Port already in use | Change `PORT` and restart; do not run two detached instances against one data dir |
| `keyla update` says working tree is dirty | Commit or stash local edits before updating |
| `keyla update` cannot replace the binary | The installed path is not writable; run with correct permissions or copy `target/release/keyla` manually |
| Dashboard is blank or old after an update | Rebuild with `bun run dashboard:build`; confirm `DASHBOARD_DIST` or the embedded assets match the binary |
| Provider requests fail while the console is up | Check **Kesehatan**, **Kuota**, **Log**, and the provider account's scope/capability |

Useful commands:

```bash
keyla doctor
keyla status
keyla logs --lines 200
curl -fsS http://127.0.0.1:12800/health/ready
```

## Development

```bash
bun install
cargo run -p keyla-gateway     # backend on 127.0.0.1:12800
bun run dashboard:dev          # Vite dashboard against the backend
```

Set `DATABASE_URL` and `KEYLA_ENCRYPTION_KEY` before starting the backend. The
dashboard is a pure HTTP client; it must never import Rust crates, server-only
crypto, or database drivers.

Required gates:

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
bun run dashboard:typecheck
bun run dashboard:test
bun run dashboard:build
```

## Security notes

- Never commit `.env`, provider credentials, API keys, or the encryption key.
- Keep `KEYLA_BIND_HOST=127.0.0.1` until a reverse proxy and TLS are in place.
- Use scoped API keys and per-key model allowlists/budgets.
- Review the **Log**, **Audit**, **Ip Bans**, and **Model Bans** views after
  exposing the gateway.
- Provider OAuth client credentials are operator-supplied; no Antigravity
  client secret is bundled.
- This repository's GitHub remote is
  <https://github.com/clovieflow/keyla-everywhere>.

## License and notices

GPL-3.0-only. See [`LICENSE`](LICENSE) and
[`docs/NOTICE.md`](docs/NOTICE.md) for upstream provenance and attribution.
Development notes live in [`docs/AGENTS.md`](docs/AGENTS.md); release history
lives in [`docs/CHANGELOG.md`](docs/CHANGELOG.md).

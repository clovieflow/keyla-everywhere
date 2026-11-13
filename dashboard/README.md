# Dashboard

`dashboard/` is the React/Vite client for the landing page, authenticated
`/console` surface, and public `/share/:token` enrollment app. One `index.html`
dispatches by pathname. Every app loads the same `src/styles/base.css`
(Tailwind, theme tokens, resets, and shared UI primitives) followed by one
direct, app-specific extension import: `console.css`, `landing.css`, or
`share.css`. There is no CSS barrel or duplicate global theme source.
Console-only shell and route styles stay in `console.css`, with the editorial
surface layer in `editorial.css`; the public landing page is type-led and
self-contained in `landing.css`; Share's public HUD stays in `share.css`. The
gateway serves the built dashboard from `dist/dashboard`, so the binary and the
browser console share one visual release.
- Public share links may include an owner-configured donation or information popup, click-opened from the Base URL card. `share.css` provides the responsive dialog layout for desktop and mobile.
Production serves the built files from `dist/dashboard`.

## Verification

`src/` is production browser code only. `bun run dashboard:typecheck`
typechecks the dashboard and its local wire contract module
`src/data/backend.ts`; `bun run dashboard:test` runs the browser/shared test
suite (425 tests at the last verification).

## Route map

`src/main.tsx` dispatches landing, console, or share from the pathname. The
console app mounts a `BrowserRouter` with basename `/console` and lazy route
chunks:

| Path | Route component | Backend domain mirror |
| --- | --- | --- |
| `/login`, `/setup`, `/banned` | `Login`, `Setup`, `Banned` | `console/auth` |
| `/` | `Overview` | dashboard summary APIs |
| `/usage` | `features/usage/UsagePage` | `console/observability` and usage contracts |
| `/providers` | `features/providers/ProvidersPage` | `console/providers/catalog` |
| `/providers/:providerId` | `ProviderDetail` | `console/providers/detail` and catalog |
| `/combos` | `Combos` | `console/routing/model` |
| `/quota` | `features/quota/QuotaPage` | `console/quota` |
| `/proxy` | `Proxy` | `network/pool` and routing |
| `/model-lab` | `Studio` | `console/domains/studio` |
| `/cli-tools`, `/cli-tools/:toolId` | `CliTools`, `CliToolDetail` | `console/cli-tools` |
| `/console-log` | `features/logs/ConsoleLogPage` | `console/observability` and SSE |
| `/settings` | `Settings` | `console/settings` |
| Overview `API Credentials` row → share | `ShareManagementDialog` | `console/domains/api-keys` and `console/share` |
| Overview `API Credentials` header → `Banned Users` (platform admin only) | `ModelBansDialog` | `console/domains/model-abuse` |
| Overview `API Credentials` create / rotate / share-regenerate | `ApiKeySecretDialog` | `console/domains/api-keys` (one-time secret reveal) |
| `/share/:token` (public root route) | `apps/share/page.tsx` | public key enrollment (`/data`, `/issue`) and personal handoff (`/handoff`) via `src/console/share/share-router.ts` |
Landing's Console links point to `/console`, not `/console/login`: that
protected entry checks the same-origin session cookie and only routes to Login
when the existing session is absent or expired.

Unknown protected paths redirect to `/`. Session transitions clear the shared
query cache and navigate to `/login` or `/banned` rather than rendering stale
tenant data.

## Contracts and parity

- `src/data/contracts.ts` is the dashboard's API mirror. Backend DTOs remain the
  authority; update the mirror in the same change.
- Provider display names in `src/shared/provider-names.ts` mirror the canonical
  bundled provider registry. Keep the exact bundled count and ids synchronized;
  BYOK providers are runtime data, not bundled registry entries.
- `src/components/ProviderIcon.tsx`'s `iconAssets` map is a hand-copied logomap.
  Every bundled provider id needs an entry; custom compatible-provider ids fall
  back to initials by design.
- `src/data/contracts.ts` derives the session mirror from the local contract
  `SessionStatusResponse` (a discriminated union on `status`), so the wire arm
  and the dashboard view cannot drift field-by-field.
- `src/data/contracts.ts` re-exports the `USAGE_DIMENSIONS` tuple as a value
  because the Usage page validates `?dim=` against it at runtime and offers one
  breakdown tab per member.
- `src/data/usage-periods.json` is a small static dashboard data file. Keep its
  values aligned with the backend usage-period contract when that contract changes.
- Query keys, hooks, and route components must use the existing `consoleRequest`
  API boundary instead of constructing another HTTP client or importing backend
  modules.

## Browser-safe boundary

Vite bundles this tree for browsers. Never import Rust source, `node:*` APIs,
database clients, provider adapters, secrets, or server-only crypto into
`dashboard/src`. Keep browser contracts as plain types and values; hand-copy
only the intentionally mirrored display metadata and keep it in sync by hand.
OAuth tokens and provider credentials stay server-side.

For route changes, update the lazy import, protected route map, shell navigation,
API hook, and this table together. For backend contract changes, update the
backend DTO, dashboard mirror, hook/request shape, and affected route together.

## Development and verification

From the repository root, use the dashboard workspace scripts:

```bash
bun run --cwd dashboard dev
bun run dashboard:typecheck
bun run dashboard:build
```

`dev`, `typecheck`, and `build` run the usage-period code generator
first. Use `dashboard:build` before live-verifying a backend-served console.

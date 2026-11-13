# Changelog

## Keyla Everywhere rebrand

- Rebranded the product to **Keyla Everywhere** across the binary, crates,
  environment variables, storage keys, data directory, and migration ledger.
  This is a clean break from the old identifiers.
- Replaced the legacy illustrated landing page with a type-led product site: gateway
  board, protocol cards, provider lineup, routing/console preview, security
  boundary, and a single call to enter the console.
- Rebuilt the console on an editorial dark system with bundled Syne and Clash
  Display fonts and first-party provider marks.
- Replaced the provider directory table with a complete card lineup: every
  provider, including offline nodes, is a full card with model/credential
  state.
- Added editorial heroes and data strips to Overview, Health, Usage, Logs,
  Models, Routing, Simulator, Quota, Bansos, API Keys, Networks, Studio, Help,
  Settings, and About. Login, first-boot setup, 404, system-error, and public
  access states share the same surface.
- Fixed the Vite `/console/api` proxy prefix so `/console/api-keys` reaches the
  SPA instead of the gateway's production fallback in development.

## Rust rewrite

- Replaced the TypeScript gateway with Rust crates for config, database,
  protocol, security, routing, providers, console, gateway, and CLI.
- Ported every provider integration, including bespoke Qoder, Kiro,
  Buddy/CodeBuddy/WorkBuddy, Antigravity, Devin, and Xiaomi MiMo Studio/Desktop
  adapters.
- Ported the console API, dashboard embeds, OAuth/device/browser flows, quota
  collectors, CLI injectors, share stats, Redis admission, and the `keyla`
  lifecycle CLI.
- Deleted the TypeScript backend and its build/test scripts. The dashboard now
  uses local wire contracts and builds against the Rust API.

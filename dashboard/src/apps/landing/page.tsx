import type { ReactElement, ReactNode } from "react";
import {
  Activity,
  ArrowRight,
  ArrowUpRight,
  Check,
  Globe,
  KeyRound,
  Layers,
  Network,
  ShieldCheck,
  Terminal,
  Zap,
} from "lucide-react";
import { GITHUB_REPO_URL, GithubMark } from "../../components/patterns/github-badge";

const CONSOLE_PATH = "/console";
const ASSET_BASE = import.meta.env.BASE_URL;

interface ProviderMark {
  readonly name: string;
  readonly file: string;
  readonly dark?: boolean;
}

const PROVIDERS: readonly ProviderMark[] = [
  { name: "Anthropic", file: "anthropics.webp" },
  { name: "OpenAI", file: "openai-r.webp" },
  { name: "Gemini", file: "gemini.webp" },
  { name: "Codex", file: "codex.webp", dark: true },
  { name: "GitHub", file: "github.webp" },
  { name: "Qoder", file: "qoder.webp" },
  { name: "Antigravity", file: "antigravity.svg", dark: true },
  { name: "Grok", file: "grok-build.svg", dark: true },
  { name: "DeepSeek", file: "deepseek.webp" },
  { name: "Kiro", file: "kiro.webp" },
  { name: "MiMo", file: "mimo.webp" },
  { name: "Mistral", file: "mistral.webp" },
  { name: "OpenRouter", file: "openrouter.webp" },
  { name: "NVIDIA", file: "nvidia.webp" },
  { name: "Cerebras", file: "cerebras.webp" },
  { name: "Ollama", file: "ollama-cloud.webp" },
];

const PROTOCOLS: readonly { name: string; path: string; detail: string }[] = [
  { name: "OpenAI Chat", path: "/v1/chat/completions", detail: "Chat completions, tools, streaming." },
  { name: "OpenAI Responses", path: "/v1/responses", detail: "Responses, compaction, reasoning." },
  { name: "Anthropic Messages", path: "/v1/messages", detail: "Messages API with streaming events." },
  { name: "Native Search", path: "/v1/search", detail: "First-party web search, normalized." },
];

const ROUTING_STEPS: readonly { title: string; body: string }[] = [
  { title: "Resolve", body: "Aliases and combos turn a client's model name into an ordered candidate set." },
  { title: "Qualify", body: "Quota, cooldown, concurrency, and capability checks run before a socket opens." },
  { title: "Dispatch", body: "The first eligible account answers. Failures fall through without changing the client contract." },
];

const TRUST_POINTS: readonly { icon: typeof ShieldCheck; title: string; body: string }[] = [
  { icon: KeyRound, title: "Scoped keys", body: "Per-key model allowlists, budgets, concurrency, and expiry." },
  { icon: ShieldCheck, title: "Boundary first", body: "Origin checks, CSRF, rate limits, and SSRF-safe outbound policy." },
  { icon: Activity, title: "Evidence, not vibes", body: "Every request, token, cost, retry, and latency is recorded." },
  { icon: Globe, title: "Your network", body: "Self-host on a laptop or Postgres-backed VPS. No vendor custody." },
];

function BrandMark(): ReactNode {
  return (
    <span className="ke-mark" aria-hidden="true">
      <span>K</span>
      <i />
    </span>
  );
}

function ProviderTile({ provider, compact = false }: { provider: ProviderMark; compact?: boolean }): ReactNode {
  return (
    <span className={`ke-provider-tile${compact ? " is-compact" : ""}${provider.dark ? " is-dark" : ""}`}>
      <img src={`${ASSET_BASE}providers/${provider.file}`} alt="" loading="lazy" decoding="async" />
      <span>{provider.name}</span>
    </span>
  );
}

export function LandingPage(): ReactElement {
  return (
    <div className="ke-page" id="top">
      <header className="ke-header">
        <a className="ke-brand" href="#top" aria-label="Keyla Everywhere home">
          <BrandMark />
          <span>
            <strong>Keyla</strong>
            <small>EVERYWHERE</small>
          </span>
        </a>
        <nav className="ke-nav" aria-label="Primary">
          <a href="#platform">Platform</a>
          <a href="#providers">Providers</a>
          <a href={CONSOLE_PATH}>Console</a>
          <a href="#security">Security</a>
        </nav>
        <div className="ke-header-actions">
          <a className="ke-github" href={GITHUB_REPO_URL} target="_blank" rel="noreferrer" aria-label="Keyla Everywhere on GitHub">
            <GithubMark size={15} />
          </a>
          <a className="ke-header-cta" href={CONSOLE_PATH}>
            Enter console
            <ArrowUpRight size={14} aria-hidden="true" />
          </a>
        </div>
      </header>

      <nav className="ke-mobile-links" aria-label="Mobile primary">
        <a href="#platform">Platform</a>
        <a href="#providers">Providers</a>
        <a href={CONSOLE_PATH}>Console</a>
        <a href="#security">Security</a>
      </nav>

      <main>
        <section className="ke-hero" aria-labelledby="ke-hero-title">
          <div className="ke-hero-copy">
            <p className="ke-eyebrow">
              <span />
              Self-hosted AI gateway
            </p>
            <h1 id="ke-hero-title">
              <span>One endpoint.</span>
              <em>Everywhere.</em>
            </h1>
            <p className="ke-lede">
              Keyla Everywhere sits between your clients and every model you use. One base URL,
              one key, one routing policy — with the receipts to prove what happened.
            </p>
            <div className="ke-hero-actions">
              <a className="ke-button ke-button-light" href={CONSOLE_PATH}>
                Open the console
                <ArrowRight size={15} aria-hidden="true" />
              </a>
              <a className="ke-button ke-button-ghost" href="#platform">
                See the platform
              </a>
            </div>
            <p className="ke-hero-note">
              <span className="ke-live-dot" /> Rust gateway · React console · GPL-3.0
            </p>
          </div>

          <div className="ke-board" aria-label="A live gateway routing board">
            <div className="ke-board-head">
              <span>GATEWAY / LIVE</span>
              <span className="ke-board-state"><i /> ROUTING</span>
            </div>
            <div className="ke-board-endpoint">
              <span>BASE URL</span>
              <code>https://keyla.your-host/v1</code>
            </div>
            <div className="ke-board-route">
              <span className="ke-board-label">REQUEST</span>
              <div className="ke-board-request">
                <code>claude-sonnet-4-5</code>
                <span>via Anthropic</span>
              </div>
              <div className="ke-board-flow" aria-hidden="true">
                <span />
                <span />
                <span />
              </div>
              <span className="ke-board-ok"><Check size={11} /> 200 · 842 ms</span>
            </div>
            <div className="ke-board-metrics">
              <div>
                <span>ROUTED TODAY</span>
                <strong>12.4k</strong>
              </div>
              <div>
                <span>P95 LATENCY</span>
                <strong>1.2s</strong>
              </div>
              <div>
                <span>FAILOVER</span>
                <strong>armed</strong>
              </div>
            </div>
            <div className="ke-board-providers">
              {PROVIDERS.slice(0, 6).map((provider) => (
                <ProviderTile key={provider.name} provider={provider} compact />
              ))}
            </div>
            <span className="ke-board-glow" aria-hidden="true" />
          </div>

          <div className="ke-stats" aria-label="Platform figures">
            <div><span>Providers</span><strong>45</strong><small>built-in + custom</small></div>
            <div><span>Model rows</span><strong>466</strong><small>seeded catalogue</small></div>
            <div><span>Wire protocols</span><strong>4</strong><small>one gateway</small></div>
            <div><span>Endpoints to learn</span><strong>1</strong><small>your base URL</small></div>
          </div>
        </section>

        <section className="ke-marquee" aria-label="Supported providers">
          <div className="ke-marquee-track">
            {[0, 1].map((copy) => (
              <div className="ke-marquee-set" key={copy} aria-hidden={copy === 1}>
                {PROVIDERS.map((provider) => (
                  <span key={`${copy}-${provider.name}`} className="ke-marquee-item">
                    <i aria-hidden="true" />
                    {provider.name}
                  </span>
                ))}
              </div>
            ))}
          </div>
        </section>

        <section className="ke-section ke-platform" id="platform">
          <div className="ke-section-head">
            <p className="ke-eyebrow"><span />One surface, every contract</p>
            <h2>Your clients don't need to know where the answer came from.</h2>
            <p>
              Keyla translates between the wire formats your tools already speak. Keep the SDK,
              keep the request shape, change the base URL — routing is the gateway's job.
            </p>
          </div>
          <div className="ke-protocol-grid">
            {PROTOCOLS.map((protocol, index) => (
              <article className="ke-protocol" key={protocol.path}>
                <span className="ke-protocol-index">0{index + 1}</span>
                <h3>{protocol.name}</h3>
                <code>{protocol.path}</code>
                <p>{protocol.detail}</p>
                <span className="ke-protocol-arrow"><ArrowUpRight size={15} /></span>
              </article>
            ))}
          </div>
        </section>

        <section className="ke-section ke-routing" id="console">
          <div className="ke-routing-copy">
            <p className="ke-eyebrow"><span />Routing with a memory</p>
            <h2>The route explains itself before it spends a token.</h2>
            <p>
              Simulation runs through the gateway's own eligibility owner. See the winner, the
              fallback order, and every exclusion reason — not a browser-side guess.
            </p>
            <div className="ke-routing-list">
              {ROUTING_STEPS.map((step, index) => (
                <div key={step.title}>
                  <span>0{index + 1}</span>
                  <div>
                    <h3>{step.title}</h3>
                    <p>{step.body}</p>
                  </div>
                </div>
              ))}
            </div>
            <a className="ke-text-link" href={`${CONSOLE_PATH}/simulator`}>
              Open the route simulator <ArrowUpRight size={14} />
            </a>
          </div>

          <div className="ke-console-mock" aria-label="Console preview">
            <div className="ke-console-bar">
              <BrandMark />
              <span>Keyla / Console</span>
              <i />
              <span className="ke-console-live">LIVE</span>
            </div>
            <div className="ke-console-body">
              <div className="ke-console-side">
                {["Overview", "Health", "Usage", "Providers", "Models", "Routing", "Quota"].map((item, index) => (
                  <span key={item} className={index === 5 ? "is-active" : ""}>{item}</span>
                ))}
              </div>
              <div className="ke-console-main">
                <p className="ke-console-kicker">CONTROL / ROUTING</p>
                <h3>Route architecture.</h3>
                <div className="ke-console-stats">
                  <span><b>6</b> combos</span>
                  <span><b>11</b> aliases</span>
                  <span><b>read-only</b> simulator</span>
                </div>
                <div className="ke-console-rows">
                  {[
                    ["claude-opus-4-6", "Anthropic", "READY"],
                    ["gpt-5.4", "OpenAI", "STEADY"],
                    ["gemini-3-pro", "Gemini", "READY"],
                  ].map(([model, provider, state]) => (
                    <div key={model}>
                      <code>{model}</code>
                      <span>{provider}</span>
                      <b>{state}</b>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        </section>

        <section className="ke-section ke-provider-section" id="providers">
          <div className="ke-section-head ke-section-head-row">
            <div>
              <p className="ke-eyebrow"><span />The lineup</p>
              <h2>Bring the model you already trust.</h2>
            </div>
            <p>
              Built-in adapters for the providers people actually use, plus an OpenAI- or
              Anthropic-compatible path for everything else.
            </p>
          </div>
          <div className="ke-provider-grid">
            {PROVIDERS.map((provider) => (
              <div className="ke-provider-card" key={provider.name}>
                <div className={`ke-provider-logo${provider.dark ? " is-dark" : ""}`}>
                  <img src={`${ASSET_BASE}providers/${provider.file}`} alt="" loading="lazy" decoding="async" />
                </div>
                <div>
                  <strong>{provider.name}</strong>
                  <span>Connected through Keyla</span>
                </div>
                <span className="ke-provider-status"><i /> READY</span>
              </div>
            ))}
          </div>
          <p className="ke-provider-foot">
            <Zap size={14} /> 45 providers seeded · 466 model rows · custom endpoints welcome.
          </p>
        </section>

        <section className="ke-section ke-security" id="security">
          <div className="ke-security-copy">
            <p className="ke-eyebrow"><span />Boundary first</p>
            <h2>A gateway is a trust boundary. Treat it like one.</h2>
            <p>
              The console and the wire API share one authentication boundary, one audit trail,
              and one policy owner. Nothing leaves without a reason the operator can inspect.
            </p>
            <div className="ke-trust-grid">
              {TRUST_POINTS.map((point) => {
                const Icon = point.icon;
                return (
                  <article key={point.title}>
                    <Icon size={16} aria-hidden="true" />
                    <h3>{point.title}</h3>
                    <p>{point.body}</p>
                  </article>
                );
              })}
            </div>
          </div>
          <div className="ke-security-board" aria-hidden="true">
            <div className="ke-security-head">
              <ShieldCheck size={15} />
              <span>REQUEST BOUNDARY</span>
              <b>ENFORCED</b>
            </div>
            {[
              ["Authentication", "key → tenant", "scoped"],
              ["Origin + CSRF", "console mutations", "verified"],
              ["Rate + concurrency", "per key · per provider", "bounded"],
              ["Outbound policy", "SSRF-safe destinations", "allowlisted"],
              ["Telemetry", "payload retention", "operator-owned"],
            ].map(([label, detail, status]) => (
              <div className="ke-security-row" key={label}>
                <span>{label}</span>
                <small>{detail}</small>
                <b>{status}</b>
              </div>
            ))}
            <div className="ke-security-foot">
              <span>No vendor custody.</span>
              <span>Your database. Your keys.</span>
            </div>
          </div>
        </section>

        <section className="ke-cta">
          <p className="ke-eyebrow"><span />Ready when you are</p>
          <h2>Point it at your stack.<br /><em>Keep the keys.</em></h2>
          <div className="ke-cta-actions">
            <a className="ke-button ke-button-light" href={CONSOLE_PATH}>
              Enter the console <ArrowRight size={15} />
            </a>
            <a className="ke-button ke-button-ghost" href={GITHUB_REPO_URL} target="_blank" rel="noreferrer">
              <GithubMark size={15} /> Source on GitHub
            </a>
          </div>
          <p className="ke-cta-note">Already have a key? Your gateway is waiting at <code>/v1</code>.</p>
        </section>
      </main>

      <footer className="ke-footer">
        <div className="ke-footer-brand">
          <BrandMark />
          <div>
            <strong>Keyla Everywhere</strong>
            <span>One endpoint. Everywhere.</span>
          </div>
        </div>
        <nav aria-label="Footer">
          <a href={CONSOLE_PATH}>Console</a>
          <a href="#platform">Platform</a>
          <a href="#providers">Providers</a>
          <a href={GITHUB_REPO_URL} target="_blank" rel="noreferrer">GitHub</a>
        </nav>
        <p>
          <Terminal size={12} /> GPL-3.0-only · <Network size={12} /> Rust + React · <Layers size={12} /> Self-hosted
        </p>
      </footer>
    </div>
  );
}

export default LandingPage;

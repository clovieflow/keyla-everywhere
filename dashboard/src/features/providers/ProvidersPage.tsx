import { ArrowUpRight, Plus, RefreshCw, Search, Trash2 } from "lucide-react";
import { memo, useEffect, useMemo, useState, type ReactNode } from "react";
import { Link } from "react-router-dom";
import {
  HeaderPairsEditor,
  pairsToHeaders,
  type HeaderPair,
} from "../../components/HeaderPairsEditor";
import { ProviderCardGrid } from "../../components/ProviderCardGrid";
import { ProviderIcon } from "../../components/ProviderIcon";
import { modelCoolingCount } from "../../components/AccountCooldown";
import { Badge } from "../../components/ui/badge";
import { Button } from "../../components/ui/button";
import { Card } from "../../components/ui/card";
import { Dialog } from "../../components/ui/dialog";
import { Input } from "../../components/ui/input";
import { Select } from "../../components/ui/select";
import { EmptyState, ErrorState, LoadingState } from "../../components/ui/state";
import { PageHead } from "../../components/PageHead";
import { useAllModelsCatalog } from "../../components/ModelPicker";
import { Switch } from "../../components/ui/switch";
import { Inline } from "../../components/ui/inline";
import { Stack } from "../../components/ui/stack";
import type {
  CreateProviderRequest,
  ProviderAccountResponse,
  ProviderResponse,
} from "../../data/contracts";
import {
  useCreateProvider,
  useCreateProviderAccount,
  useDeleteProvider,
  useProviderAccounts,
  useProviderModels,
  useProviders,
  useSyncProviderModels,
  useTestByokConnection,
} from "../../hooks/providers";
import { getErrorMessage } from "../../shared/helpers";

const wireFamilies = ["chat", "responses", "messages"] as const;
type WireFamily = (typeof wireFamilies)[number];
type DashboardServiceKind = "llm" | "websearch";

const SEARCH_PROVIDER_ORDER = ["exa", "gemini", "codex"] as const;

function providerServiceKinds(provider: ProviderResponse): readonly string[] {
  const kinds = provider.serviceKinds;
  return Array.isArray(kinds) && kinds.length > 0 ? kinds : ["llm"];
}


// ── Custom Compatible Provider Modal ──────────────────────────────────────────

function AddCompatibleModal({
  variant,
  open,
  onClose,
}: {
  variant: "openai-compatible" | "anthropic-compatible";
  open: boolean;
  onClose: () => void;
}): ReactNode {
  const create = useCreateProvider();
  const createAccount = useCreateProviderAccount();
  const syncModels = useSyncProviderModels();
  const testConnection = useTestByokConnection();
  const [label, setLabel] = useState("");
  const [providerId, setProviderId] = useState("");
  const [baseUrl, setBaseUrl] = useState("");
  const [credential, setCredential] = useState("");
  const [autoFetchModels, setAutoFetchModels] = useState(false);
  const [sendCliIdentity, setSendCliIdentity] = useState(true);
  const [headerPairs, setHeaderPairs] = useState<readonly HeaderPair[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [testResult, setTestResult] = useState<{
    ok: boolean;
    message: string;
  } | null>(null);
  const [testing, setTesting] = useState(false);

  const isAnthropic = variant === "anthropic-compatible";
  const defaultWire: WireFamily = isAnthropic ? "messages" : "chat";
  const [wireFamily, setWireFamily] = useState<WireFamily>(defaultWire);

  useEffect(() => {
    if (!open) return;
    setLabel("");
    setCredential("");
    setWireFamily(defaultWire);
    setBaseUrl("");
    setAutoFetchModels(false);
    setSendCliIdentity(true);
    setHeaderPairs([]);
    setError(null);
    setTestResult(null);
  }, [open]);

  const pasteInto = async (setter: (value: string) => void) => {
    try {
      const text = await navigator.clipboard.readText();
      if (text.trim()) setter(text.trim());
    } catch {
      setError("Clipboard access denied — paste manually instead.");
    }
  };

  const runTest = async () => {
    if (!baseUrl.trim()) {
      setTestResult({ ok: false, message: "Base URL is required to test the connection." });
      return;
    }
    setTesting(true);
    setTestResult(null);
    setError(null);
    try {
      const extraHeaders = pairsToHeaders(headerPairs);
      const result = await testConnection.mutateAsync({
        baseUrl: baseUrl.trim(),
        apiKey: credential.trim(),
        wireFamily,
        cliIdentity: sendCliIdentity,
        ...(Object.keys(extraHeaders).length > 0 ? { extraHeaders } : {}),
      });
      if (result.ok) {
        const models =
          typeof result.modelCount === "number" ? ` — upstream advertised ${result.modelCount} model(s)` : "";
        setTestResult({ ok: true, message: `Connected successfully (${result.latencyMs}ms)${models}.` });
      } else {
        setTestResult({
          ok: false,
          message: result.error ?? "Connection failed.",
        });
      }
    } catch (err) {
      setTestResult({ ok: false, message: getErrorMessage(err, "Connection test failed") });
    } finally {
      setTesting(false);
    }
  };

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!label.trim()) {
      setError("Display Name is required");
      return;
    }
    if (!providerId.trim()) {
      setError("Provider ID (slug) is required");
      return;
    }
    if (!baseUrl.trim()) {
      setError("Base URL is required");
      return;
    }

    const extraHeaders = pairsToHeaders(headerPairs);
    const id = providerId.trim().toLowerCase();

    setSubmitting(true);
    setError(null);
    try {
      const req: CreateProviderRequest = {
        providerId: id,
        label: label.trim(),
        baseUrl: baseUrl.trim(),
        wireFamily,
        compatibilityProfile: {
          cli_identity: sendCliIdentity,
          ...(Object.keys(extraHeaders).length > 0 ? { extra_headers: extraHeaders } : {}),
        },
      };
      await create.mutateAsync(req);
      if (credential.trim()) {
        await createAccount.mutateAsync({
          providerId: id,
          request: { credentialKind: "api_key", secret: credential.trim() },
        });
      }
      if (autoFetchModels) {
        await syncModels.mutateAsync(id);
      }
      onClose();
    } catch (err) {
      setError(getErrorMessage(err, "Failed to create provider"));
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <Dialog
      open={open}
      onClose={onClose}
      title={isAnthropic ? "Add Custom Anthropic Provider" : "Add Custom OpenAI Provider"}
    >
      <form onSubmit={submit} style={{ display: "flex", flexDirection: "column", gap: "12px" }}>
        {error ? <div style={{ color: "var(--red)", fontSize: "12px" }}>{error}</div> : null}
        <Input
          label="Display Name"
          hint="Required. A friendly label for this node."
          id="compat-label"
          value={label}
          onChange={(e) => setLabel(e.target.value)}
          placeholder={isAnthropic ? "Anthropic Compatible (Prod)" : "OpenAI Compatible (Prod)"}
          required
        />
        <Input
          label="Provider ID / Slug"
          hint="Required. Used as the provider prefix for model IDs."
          id="compat-slug"
          value={providerId}
          onChange={(e) => setProviderId(e.target.value)}
          placeholder={isAnthropic ? "ac-prod" : "oc-prod"}
          required
        />
        <div className="form-group">
          <label className="form-label" htmlFor="compat-url">
            <span>Base URL</span>
          </label>
          <Inline gap="8px">
            <div style={{ flex: 1, minWidth: 0 }}>
              <Input
                id="compat-url"
                value={baseUrl}
                onChange={(e) => setBaseUrl(e.target.value)}
                placeholder={
                  isAnthropic ? "https://api.anthropic.com/v1" : "https://api.openai.com/v1"
                }
                required
              />
            </div>
            <Button type="button" variant="secondary" onClick={() => pasteInto(setBaseUrl)}>
              Paste
            </Button>
          </Inline>
        </div>
        {isAnthropic ? null : (
          <Select
            id="compat-wire"
            label="API format"
            value={wireFamily}
            onValueChange={(value) => setWireFamily(value as WireFamily)}
            options={[
              { value: "chat", label: "Chat completions" },
              { value: "responses", label: "Responses" },
            ]}
          />
        )}
        <div className="form-group">
          <label className="form-label" htmlFor="compat-credential">
            <span>API Key</span>
            <span className="form-hint">
              Optional — saved with this provider and used to authenticate every request.
            </span>
          </label>
          <Inline gap="8px">
            <div style={{ flex: 1, minWidth: 0 }}>
              <Input
                id="compat-credential"
                type="password"
                placeholder="sk-..."
                value={credential}
                onChange={(e) => setCredential(e.target.value)}
              />
            </div>
            <Button
              type="button"
              variant="secondary"
              disabled={testing}
              onClick={() => void runTest()}
            >
              {testing ? "Testing..." : "Test connection"}
            </Button>
            <Button type="button" variant="secondary" onClick={() => pasteInto(setCredential)}>
              Paste
            </Button>
          </Inline>
          {testResult ? (
            <div
              style={{
                marginTop: "6px",
                fontSize: "12px",
                lineHeight: "1.4",
                color: testResult.ok ? "var(--green)" : "var(--red)",
                wordBreak: "break-word",
              }}
            >
              {testResult.ok ? "✓ " : "✗ "}
              {testResult.message}
            </div>
          ) : null}
        </div>
        <div
          style={{
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            padding: "10px 12px",
            borderRadius: "10px",
            border: "1px solid var(--inner-border)",
          }}
        >
          <div>
            <div style={{ fontSize: "13px", fontWeight: 600 }}>Auto-fetch models</div>
            <div style={{ fontSize: "11px", color: "var(--text-tertiary)" }}>
              Discover this provider's model list automatically after creation
            </div>
          </div>
          <Switch checked={autoFetchModels} onChange={setAutoFetchModels} id="compat-autofetch" />
        </div>
        <div
          style={{
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            padding: "10px 12px",
            borderRadius: "10px",
            border: "1px solid var(--inner-border)",
          }}
        >
          <div>
            <div style={{ fontSize: "13px", fontWeight: 600 }}>
              {isAnthropic ? "Send request as Claude CLI" : "Send request as Codex CLI"}
            </div>
            <div style={{ fontSize: "11px", color: "var(--text-tertiary)" }}>
              {isAnthropic
                ? "Emits official Claude CLI User-Agent and Stainless headers to upstream"
                : "Emits official codex_cli_rs User-Agent and originator headers to upstream"}
            </div>
          </div>
          <Switch checked={sendCliIdentity} onChange={setSendCliIdentity} id="compat-cli-identity" />
        </div>
        <HeaderPairsEditor pairs={headerPairs} onChange={setHeaderPairs} />
        <Inline justify="flex-end" gap="8px" style={{ marginTop: "8px" }}>
          <Button variant="secondary" type="button" onClick={onClose}>
            Cancel
          </Button>
          <Button variant="primary" type="submit" disabled={submitting}>
            {submitting ? "Creating..." : "Add Provider"}
          </Button>
        </Inline>
      </form>
    </Dialog>
  );
}

// ── Custom Providers Section ──────────────────────────────────────────────────

function CustomProviderCard({ customProvider }: { customProvider: ProviderResponse }): ReactNode {
  const deleteMutation = useDeleteProvider();
  const [deleteOpen, setDeleteOpen] = useState(false);
  // Same data the builtin card reads: connection badges and model counts
  // come from the same hooks. Collectorless custom endpoints never refresh
  // quota, so a stale manufactured error is not rendered: the row shows
  // "No quota data" on its detail page instead of a red herring here.
  const modelsQuery = useProviderModels(customProvider.providerId);
  const modelCount = modelsQuery.data?.length;
  const accountsQuery = useProviderAccounts(customProvider.providerId);
  const accounts = accountsQuery.data;
  const counts = summarizeAccounts(accounts ?? []);
  // Any non-active account is a connection of some state: the neutral badge
  // only shows when every account is active and healthy.
  return (
    <Card
      className="provider-card provider-card-custom"
      style={{
        position: "relative",
        display: "flex",
        flexDirection: "column",
        border: "1px solid var(--inner-border)",
        borderRadius: "12px",
        transition:
          "transform var(--dur-micro) var(--ease-spring), border-color var(--dur-micro) var(--ease-spring), box-shadow var(--dur-micro) var(--ease-spring)",
      }}
    >
      <ProviderVersionBadge clientVersion={customProvider.clientVersion} />
      <Link
        to={`/providers/${encodeURIComponent(customProvider.providerId)}`}
        style={{
          textDecoration: "none",
          color: "inherit",
          // See the builtin card: `flex: 1` keeps the clickable area as tall as
          // the stretched card instead of only as tall as the content.
          display: "block",
          flex: 1,
          padding: "12px",
          paddingRight: "40px",
          minHeight: "76px",
        }}
      >
        <Inline gap="10px">
          <ProviderIcon
            icon={customProvider.wireFamilyDefault === "messages" ? "anthropic" : "openai"}
            name={customProvider.label || customProvider.providerId}
            size={32}
          />
          <div style={{ minWidth: 0, flex: 1 }}>
            <div
              style={{
                fontSize: "13px",
                fontWeight: 600,
                overflow: "hidden",
                textOverflow: "ellipsis",
                whiteSpace: "nowrap",
              }}
            >
              {customProvider.label || customProvider.providerId}
            </div>
            <div style={{ marginTop: "3px", display: "flex", flexWrap: "wrap", gap: "4px" }}>
              {accounts === undefined ? (
                <SecondaryQueryBadge
                  kind="accounts"
                  isPending={accountsQuery.isPending}
                  isError={accountsQuery.isError}
                  hasData={false}
                />
              ) : accounts.length === 0 ? (
                <Badge>No connections</Badge>
              ) : (
                <AccountStatusBadges counts={counts} total={accounts.length} />
              )}
              {accountsQuery.isError && accounts !== undefined ? (
                <Badge tone="warn">Connections unavailable</Badge>
              ) : null}

            </div>
          </div>

          <div
            style={{
              display: "flex",
              flexDirection: "column",
              alignItems: "flex-end",
              gap: "3px",
              flexShrink: 0,
            }}
          >
            <span
              style={{
                fontFamily: "var(--font-mono)",
                fontSize: "10px",
                fontWeight: 600,
                background: "var(--kbd-bg)",
                padding: "1px 5px",
                borderRadius: "4px",
                color: "var(--text-secondary)",
              }}
            >
              {customProvider.providerId}/
            </span>
            {modelCount !== undefined && modelCount > 0 ? (
              <Badge tone="info">{modelCount} models</Badge>
            ) : null}
            {modelsQuery.isError ? (
              <Badge tone="warn">Models unavailable</Badge>
            ) : modelCount === undefined ? (
              <SecondaryQueryBadge
                kind="models"
                isPending={modelsQuery.isPending}
                isError={false}
                hasData={false}
              />
            ) : modelCount === 0 ? (
              <SecondaryQueryBadge
                kind="models"
                isPending={false}
                isError={false}
                hasData
                isEmpty
              />
            ) : null}
          </div>
        </Inline>
      </Link>
      <Button
        variant="ghost"
        size="sm"
        icon={<Trash2 size={12} />}
        onClick={() => setDeleteOpen(true)}
        style={{
          position: "absolute",
          top: "4px",
          right: "4px",
          color: "var(--text-tertiary)",
          padding: "4px",
        }}
        title={`Delete ${customProvider.label || customProvider.providerId}`}
      />
      <Dialog open={deleteOpen} onClose={() => setDeleteOpen(false)} title="Delete Custom Provider">
        <Stack gap="12px">
          <p style={{ fontSize: "13px", color: "var(--text-secondary)" }}>
            Are you sure you want to delete custom provider{" "}
            <strong>{customProvider.label || customProvider.providerId}</strong>? Its models,
            accounts, and routing preferences are deleted together, and requests to this
            provider will no longer route.
          </p>
          {deleteMutation.isError ? (
            <p style={{ fontSize: "12px", color: "var(--red)" }}>
              {getErrorMessage(deleteMutation.error, "Delete failed")}
            </p>
          ) : null}
          <div
            style={{ display: "flex", justifyContent: "flex-end", gap: "8px", marginTop: "8px" }}
          >
            <Button variant="secondary" onClick={() => setDeleteOpen(false)}>
              Cancel
            </Button>
            <Button
              variant="danger"
              onClick={() => {
                deleteMutation.mutate(customProvider.providerId, {
                  onSuccess: () => setDeleteOpen(false),
                  onError: () => undefined,
                });
              }}
              disabled={deleteMutation.isPending}
            >
              {deleteMutation.isPending ? "Deleting..." : "Delete Provider"}
            </Button>
          </div>
        </Stack>
      </Dialog>
    </Card>
  );
}

// ── Provider Card ─────────────────────────────────────────────────────────────

/**
 * Connection counts for one provider's card.
 *
 * Computed once here because both card variants render the same badges from the
 * same accounts, and keeping two copies is what let the per-model case go
 * missing from the list: an account throttled for one model keeps
 * `status: "active"` (see `account-health-service.ts`), so a rollup built from
 * `status === "cooldown"` alone reported it as a healthy connection while its
 * own detail page said "1 model cooling".
 *
 * `active` and `cooling` are therefore separate counts over the same account,
 * and both are meant to show at once: a cooling account IS connected and
 * routable for its other models, it is just not being routed to for the models
 * named in `modelCooldowns`. The card keeps every status in its own badge so
 * one account is not counted as unhealthy merely because it is cooling or in
 * cooldown.
 */
interface AccountStatusCounts {
  readonly active: number;
  readonly cooldown: number;
  readonly disabled: number;
  readonly cooling: number;
}

function summarizeAccounts(accounts: readonly ProviderAccountResponse[]): AccountStatusCounts {
  return {
    active: accounts.filter((account) => account.status === "active").length,
    cooldown: accounts.filter((account) => account.status === "cooldown").length,
    disabled: accounts.filter((account) => account.status === "disabled").length,
    cooling: modelCoolingCount(accounts),
  };
}

function AccountStatusBadges({
  counts,
  total,
}: {
  readonly counts: AccountStatusCounts;
  readonly total: number;
}): ReactNode {
  const hasBadge =
    counts.active > 0 ||
    counts.cooldown > 0 ||
    counts.cooling > 0 ||
    counts.disabled > 0;
  if (!hasBadge) return <Badge tone="warn" dot>{total} Connected</Badge>;
  return (
    <>
      {counts.active > 0 ? <Badge tone="ok" dot>{counts.active} Healthy</Badge> : null}
      {counts.cooldown > 0 ? <Badge tone="warn" dot>{counts.cooldown} Cooldown</Badge> : null}
      {counts.cooling > 0 ? <Badge tone="warn" dot>{counts.cooling} Cooling</Badge> : null}
      {counts.disabled > 0 ? <Badge tone="warn" dot>{counts.disabled} Unhealthy</Badge> : null}
    </>
  );
}

function SecondaryQueryBadge({
  kind,
  isPending,
  isError,
  hasData,
  isEmpty = false,
}: {
  kind: "models" | "accounts";
  isPending: boolean;
  isError: boolean;
  hasData: boolean;
  isEmpty?: boolean;
}): ReactNode {
  const label = kind === "models" ? "Models" : "Connections";
  if (isError) return <Badge tone="warn">{label} unavailable</Badge>;
  if (isPending && !hasData) return <Badge tone="info">Loading {label.toLowerCase()}…</Badge>;
  if (isEmpty) return <Badge>{kind === "models" ? "No models" : "No connections"}</Badge>;
  return null;
}

function ProviderVersionBadge({
  clientVersion,
}: {
  readonly clientVersion: ProviderResponse["clientVersion"];
}): ReactNode {
  if (!clientVersion) return null;
  return (
    <Badge
      className="provider-version-badge"
      tone={clientVersion.source === "latest" ? "teal" : "default"}
      title={
        clientVersion.source === "latest"
          ? "Latest discovered client version"
          : "Pinned fallback; background discovery has not succeeded yet"
      }
    >
      v{clientVersion.version} · {clientVersion.source}
    </Badge>
  );
}

const ProviderCard = memo(function ProviderCard({
  provider,
  serviceKind,
  featured = false,
}: {
  provider: ProviderResponse;
  serviceKind?: DashboardServiceKind;
  featured?: boolean;
}): ReactNode {
  const displayName = provider.label || provider.displayName;
  const modelsQuery = useProviderModels(provider.providerId);
  const modelCount = modelsQuery.data?.filter(
    (model) =>
      serviceKind === undefined ||
      model.serviceKind === serviceKind ||
      (serviceKind === "llm" && model.serviceKind === undefined),
  ).length;
  const accountsQuery = useProviderAccounts(provider.providerId);
  const accounts = accountsQuery.data ?? [];
  const live = Boolean(provider.enabled && (provider.configured || !provider.requiresAccount));
  const kindLabel = provider.isBuiltIn
    ? provider.oauthFlows
      ? "OAuth · built-in"
      : "API key · built-in"
    : "Custom · compatible";
  const ghost = displayName
    .split(/[\s-]+/)
    .filter(Boolean)
    .slice(0, 2)
    .map((part) => part[0])
    .join("")
    .toUpperCase();
  const darkLogo = new Set([
    "antigravity",
    "cb",
    "cbcn",
    "codex",
    "grok",
    "grok-build",
    "kiro",
  ]).has(provider.providerId.toLowerCase());

  return (
    <Link
      to={`/providers/${encodeURIComponent(provider.providerId)}${
        serviceKind === undefined ? "" : `?service=${serviceKind}`
      }`}
      className={`ed-provider-card${featured ? " ed-provider-card--feature" : ""}${
        live ? "" : " ed-provider-card--offline"
      }`}
      style={{ textDecoration: "none", color: "inherit" }}
      aria-label={`${displayName} provider details`}
    >
      <div className="ed-provider-card__top">
        <span className={`ed-provider-card__logo${darkLogo ? " ed-provider-card__logo--dark" : ""}`}>
          <ProviderIcon
            icon={provider.providerId}
            name={displayName}
            size={featured ? 44 : 32}
            style={{ width: "100%", height: "100%", border: 0, background: "transparent" }}
          />
        </span>
        <span
          className={`ed-provider-card__status${live ? " ed-provider-card__status--live" : ""}`}
        >
          {live ? "Live" : "Offline"}
        </span>
        <span className="ed-provider-card__arrow" aria-hidden="true">
          <ArrowUpRight size={12} />
        </span>
      </div>

      <div className="ed-provider-card__type">
        {kindLabel} · {provider.providerId}
      </div>
      <div className="ed-provider-card__name">{displayName}</div>

      <div className="ed-provider-card__metrics">
        <div>
          <div className="ed-provider-card__metric-label">Models</div>
          <div className="ed-provider-card__metric-value">
            {modelCount === undefined ? "—" : modelCount}
          </div>
        </div>
        <div>
          <div className="ed-provider-card__metric-label">
            {live ? "Connections" : "Credential"}
          </div>
          <div className="ed-provider-card__metric-value">
            {accountsQuery.isPending
              ? "…"
              : live
                ? accounts.length || "local"
                : provider.requiresAccount
                  ? "required"
                  : "ready"}
          </div>
        </div>
        {featured ? (
          <div>
            <div className="ed-provider-card__metric-label">Health</div>
            <div className="ed-provider-card__metric-value">
              {accounts.some((account) => account.status === "active")
                ? "healthy"
                : live
                  ? "ready"
                  : "—"}
            </div>
          </div>
        ) : null}
      </div>

      <span className="ed-provider-card__ghost" aria-hidden="true">
        {ghost}
      </span>
    </Link>
  );
});

function compareConfiguredProviders(a: ProviderResponse, b: ProviderResponse): number {
  const configuredRank = Number(Boolean(b.configured)) - Number(Boolean(a.configured));
  if (configuredRank !== 0) return configuredRank;
  return (a.label || a.displayName).localeCompare(b.label || b.displayName);
}

// ── Main Page ─────────────────────────────────────────────────────────────────

export default function Providers(): ReactNode {
  const q = useProviders();
  const catalog = useAllModelsCatalog(true);
  const allProviders = useMemo(() => q.data ?? [], [q.data]);
  const customProviders = useMemo(
    () => [...allProviders.filter((p) => !p.isBuiltIn)].sort(compareConfiguredProviders),
    [allProviders],
  );
  const searchProviders = useMemo(
    () => allProviders.filter((p) => providerServiceKinds(p).includes("websearch")),
    [allProviders],
  );
  const llmProviders = useMemo(
    () => allProviders.filter((p) => providerServiceKinds(p).includes("llm")),
    [allProviders],
  );
  const [serviceTab, setServiceTab] = useState<"llm" | "search">("llm");
  const [statusFilter, setStatusFilter] = useState<"all" | "live" | "offline">("all");
  const [search, setSearch] = useState("");
  const [showAnthropic, setShowAnthropic] = useState(false);
  const [showOpenAI, setShowOpenAI] = useState(false);
  const orderedSearch = useMemo(() => {
    const rank = new Map<string, number>(SEARCH_PROVIDER_ORDER.map((id, index) => [id, index]));
    return [...searchProviders].sort((a, b) => {
      const rankDiff =
        (rank.get(a.providerId.toLowerCase()) ?? SEARCH_PROVIDER_ORDER.length) -
        (rank.get(b.providerId.toLowerCase()) ?? SEARCH_PROVIDER_ORDER.length);
      if (rankDiff !== 0) return rankDiff;
      return (a.label || a.displayName).localeCompare(b.label || b.displayName);
    });
  }, [searchProviders]);

  const isLive = (provider: ProviderResponse): boolean =>
    Boolean(provider.enabled && (provider.configured || !provider.requiresAccount));
  const liveCount = allProviders.filter(isLive).length;
  const filtered = useMemo(() => {
    const needle = search.trim().toLowerCase();
    const source = serviceTab === "search" ? orderedSearch : llmProviders;
    return source
      .filter((provider) => {
        if (statusFilter === "live" && !isLive(provider)) return false;
        if (statusFilter === "offline" && isLive(provider)) return false;
        if (needle.length === 0) return true;
        return `${provider.label ?? ""} ${provider.displayName} ${provider.providerId}`
          .toLowerCase()
          .includes(needle);
      })
      .sort((a, b) => {
        const liveRank = Number(isLive(b)) - Number(isLive(a));
        if (liveRank !== 0) return liveRank;
        return (a.label || a.displayName).localeCompare(b.label || b.displayName);
      });
  }, [search, serviceTab, statusFilter, orderedSearch, llmProviders]);

  const featured = filtered[0];
  const visible = filtered;

  if (q.isPending && !q.data) return <LoadingState label="Loading providers..." />;
  if (q.isError)
    return (
      <ErrorState
        message={getErrorMessage(q.error, "Failed to load providers")}
        onRetry={() => q.refetch()}
      />
    );

  return (
    <div className="dashboard-page">
      <PageHead
        eyebrow="Control / Provider index"
        title={"Providers\nin session."}
        description="Satu gateway, seluruh upstream. Kredensial, akun, dan katalog model yang siap dirutekan — dengan status sesi yang jujur."
        stats={[
          { label: "Total providers", value: String(allProviders.length), meta: "Built-in + custom" },
          { label: "Live sessions", value: String(liveCount), meta: `${allProviders.length - liveCount} menunggu kredensial` },
          {
            label: "Registered models",
            value: catalog.items.length > 0 ? catalog.items.length.toLocaleString("id-ID") : "—",
            meta: "Enabled in this install",
          },
          { label: "Search nodes", value: String(searchProviders.length), meta: "Native web search" },
        ]}
        actions={
          <Button
            variant="secondary"
            size="sm"
            icon={<RefreshCw size={13} className={q.isFetching ? "animate-spin" : ""} />}
            onClick={() => {
              void q.refetch();
              catalog.refetch();
            }}
            disabled={q.isFetching}
          >
            {q.isFetching ? "Menyegarkan…" : "Refresh katalog"}
          </Button>
        }
      />

      <div className="ed-provider-toolbar">
        <label className="ed-search">
          <Search size={14} aria-hidden="true" />
          <input
            type="search"
            value={search}
            onChange={(event) => setSearch(event.target.value)}
            placeholder="Cari provider atau ID…"
            aria-label="Cari provider"
          />
        </label>

        <div className="ed-segment" role="group" aria-label="Status provider">
          {(["all", "live", "offline"] as const).map((value) => (
            <button
              key={value}
              type="button"
              aria-pressed={statusFilter === value}
              onClick={() => setStatusFilter(value)}
            >
              {value === "all" ? "All" : value === "live" ? "Live" : "Offline"}
            </button>
          ))}
        </div>

        <div className="ed-segment" role="group" aria-label="Jenis layanan">
          {(["llm", "search"] as const).map((value) => (
            <button
              key={value}
              type="button"
              aria-pressed={serviceTab === value}
              onClick={() => setServiceTab(value)}
            >
              {value === "llm" ? `LLM ${llmProviders.length}` : `Search ${searchProviders.length}`}
            </button>
          ))}
        </div>

        <div style={{ marginLeft: "auto", display: "flex", gap: 6, alignItems: "center" }}>
          <Button
            variant="secondary"
            size="sm"
            icon={<Plus size={12} />}
            onClick={() => setShowAnthropic(true)}
          >
            Custom Anthropic
          </Button>
          <Button
            variant="secondary"
            size="sm"
            icon={<Plus size={12} />}
            onClick={() => setShowOpenAI(true)}
          >
            Custom OpenAI
          </Button>
        </div>
        <span style={{ fontSize: 9, letterSpacing: "0.1em", textTransform: "uppercase", color: "#6d6861" }}>
          {filtered.length} nodes · connected first
        </span>
      </div>

      {customProviders.length > 0 ? (
        <section style={{ display: "flex", flexDirection: "column", gap: 10, marginBottom: 8 }}>
          <div className="ed-provider-section-title">
            <h3>Custom endpoints</h3>
            <span>{customProviders.length} configured</span>
          </div>
          <ProviderCardGrid>
            {customProviders.map((provider) => (
              <CustomProviderCard key={provider.providerId} customProvider={provider} />
            ))}
          </ProviderCardGrid>
        </section>
      ) : null}

      {filtered.length === 0 ? (
        <EmptyState
          title="Tidak ada provider yang cocok"
          message="Ubah kata kunci atau filter status untuk melihat katalog."
          action={
            <Button
              variant="secondary"
              size="sm"
              onClick={() => {
                setSearch("");
                setStatusFilter("all");
              }}
            >
              Reset filter
            </Button>
          }
        />
      ) : (
        <>
          <div className="ed-provider-grid">
            {visible.map((provider, index) => (
              <ProviderCard
                key={provider.providerId}
                provider={provider}
                serviceKind={serviceTab === "search" ? "websearch" : "llm"}
                featured={provider.providerId === featured?.providerId && index === 0}
              />
            ))}
          </div>

        </>
      )}

      <AddCompatibleModal
        variant="anthropic-compatible"
        open={showAnthropic}
        onClose={() => setShowAnthropic(false)}
      />
      <AddCompatibleModal
        variant="openai-compatible"
        open={showOpenAI}
        onClose={() => setShowOpenAI(false)}
      />
    </div>
  );
}

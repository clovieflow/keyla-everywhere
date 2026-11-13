/**
 * Dashboard-facing contract and runtime constants that used to be imported
 * directly from the TypeScript backend.
 *
 * The gateway is Rust now; this module is the browser's local declaration of
 * the wire shapes plus the pure values the UI validates against. Complex
 * response types are intentionally structural aliases so the dashboard never
 * blocks on backend-only modules.
 */

export const healthStatus = {
  enumValues: ["active", "cooldown", "disabled"] as const,
};
export type HealthStatus = (typeof healthStatus.enumValues)[number];

export type SessionStatusResponse = any;
export type DeleteAllScope = any;
export type BackupPayload = any;
export type ImportResult = any;
export interface ImportReport {
  readonly imported: Record<string, number>;
  readonly skipped: readonly string[];
  readonly remapped: readonly string[];
  readonly [key: string]: any;
}

export type SystemHealthResponse = any;
export type UsageByResponse = any;
export type UsageByRow = any;
export type UsageChartResponse = any;
export type UsageRequestDetail = any;
export type UsageRequestItem = any;
export type UsageRequestsResponse = any;
export type UsageSummaryResponse = any;
export type UsageSummaryTotals = any;

export type AccountInflightReading = any;
export interface ProviderOAuthFlows {
  readonly browser: boolean;
  readonly device: boolean;
  readonly import: boolean;
  readonly browserLoginFields: readonly any[];
  readonly deviceLoginFields: readonly any[];
  readonly importFields: readonly any[];
}

export interface ProviderResponse {
  readonly [key: string]: any;
  readonly providerId: string;
  readonly displayName: string;
  readonly oauthFlows?: ProviderOAuthFlows;
  readonly isBuiltIn: boolean;
  readonly requiresAccount: boolean;
  readonly hasAdapterUserAgent: boolean;
}
export type CreateProviderRequest = any;
export type UpdateProviderRequest = any;
export type ModelCatalogResponse = any;
export type ModelCatalogEntry = any;
export interface FlatModelCatalogEntry {
  readonly [key: string]: any;
  readonly entry: {
    readonly reasoning: boolean;
    readonly toolCall: boolean;
    readonly vision: boolean;
    readonly document: boolean;
    readonly audio: boolean;
    readonly mediaGeneration: boolean;
    readonly serviceKind: string;
    readonly contextLimit?: number | null;
    readonly outputLimit?: number | null;
    readonly wireFamily: string;
    readonly route?: string;
    readonly enabled?: boolean;
    readonly providerId?: string;
    readonly modelId?: string;
  };
}
export type OAuthDevicePollResponse = any;
export type ProviderRoutingResponse = any;
export type UpdateProviderRoutingRequest = any;
export type CreateProviderAccountRequest = any;
export type CredentialKind = "api_key" | "oauth" | "none";
export type CredentialMode = any;
export type UpdateProviderAccountRequest = any;
export type ProviderAccountResponse = any;
export type ProviderAccountExport = any;
export type ProviderAccountsExportResponse = any;
export type ProbeAllAccountsResult = any;
export type ProbeModelRequest = any;
export type ProbeModelResult = any;
export type ByokConnectionTestRequest = any;
export type ByokConnectionTestResult = any;
export type SetModelEnabledRequest = any;
export type AccountHealthEventRecord = any;

export type ComboStrategy = any;
export type ModelAliasRow = any;
export type ModelAliasCreateInput = any;
export type ModelAliasPatchInput = any;
export type ModelComboRow = any;
export type ModelComboCreateInput = any;
export type ModelComboPatchInput = any;
export type ModelComboCloneResult = any;

export type CreateApiKeyRequest = any;
export type ApiKeyResponse = any;
export type CreateApiKeyResponse = any;
export type UpdateApiKeyResponse = any;
export type ShareKeyResponse = any;
export type ApiKeyModelAccessMode = "whitelist" | "blacklist" | null;

export type ModelAbuseBan = any;
export type SharedKeySummary = any;
export type SharedKeyActivityDetail = any;
export type SharedKeyModelUsage = any;
export type SharedKeyRequestEvent = any;
export type AuditEntry = any;
export type AuditListPage = any;

export type StudioMessage = any;
export type StudioAttachment = any;
export type StudioMediaResult = any;
export type StudioSessionView = any;
export type StudioSessionSummary = any;

export type RuntimeSettingsResponse = any;
export type UpdateRuntimeSettingsRequest = any;
export type RedisBackend = any;

export type CreateNetworkPoolRequest = any;
export type NetworkPoolResponse = any;
export type HealthCheckResult = any;
export type PoolSpeedTestResult = any;
export type PoolStrategySetting = any;
export type PoolBatchProbeResult = any;
export type RelayDeployRequest = any;
export type RelayDeployResult = any;
export type RelayTarget = "cloudflare" | "vercel" | "deno";
export type PoolHealthEvent = any;

export type ToolDef = any;
export type ToolRegistryEntry = any;
export type ToolStatus = any;
export type ApplyInput = any;
export type ApplyConfigResult = any;
export type DownloadResult = any;
export type CliMappingInput = any;
export type CliMappingSettings = any;

export type UsageDimension = (typeof USAGE_DIMENSIONS)[number];
export const USAGE_DIMENSIONS = ["model", "provider", "key", "client", "client_ip"] as const;

export const TENANT_KEY_SCOPES = [
  "routing:invoke",
  "routing:cli_mapping",
  "search:invoke",
  "dashboard:read",
  "dashboard:write",
  "providers:read",
  "providers:write",
  "models:read",
  "models:write",
] as const;
export type TenantScope = (typeof TENANT_KEY_SCOPES)[number];

export const SHARE_POPUP_IMAGE_MAX_BYTES = 2 * 1024 * 1024;
export const SHARE_POPUP_IMAGE_MIMES = [
  "image/png",
  "image/jpeg",
  "image/webp",
  "image/gif",
] as const;

export const CLIENT_ROUTERS = [
  {
    id: "9router",
    label: "9Router and OmniRoute",
    signals: [
      { field: "x-msh-platform", equals: "9router", description: "9Router's platform header" },
      { field: "x-client-type", equals: "9router", description: "9Router's client-type header" },
      {
        field: "user-agent",
        pattern: /(^|[^a-z0-9])9router([^a-z0-9]|$)/i,
        description: "User-Agent naming 9Router",
      },
      { field: "x-omniroute-peer-trace", description: "OmniRoute's peer-trace header" },
      { field: "x-omniroute-fallback-hint", description: "OmniRoute's fallback-hint header" },
      {
        field: "user-agent",
        equals: "mozilla/5.0 (compatible; openai compatible)",
        description: "OmniRoute's rewritten OpenAI-compatible User-Agent",
      },
      {
        field: "user-agent",
        pattern: /^node(?:\/[\w.+-]+)?$/i,
        description: "Node's default User-Agent, sent bare by this router",
      },
    ],
  },
] as const;

export const CLIENT_ROUTER_IDS = CLIENT_ROUTERS.map((router) => router.id);

export function normalizeClientRouterId(value: string): string | undefined {
  const normalized = value.trim().toLowerCase();
  if (normalized === "omniroute") return "9router";
  return CLIENT_ROUTERS.some((router) => router.id === normalized) ? normalized : undefined;
}

export interface ModelAccessPolicy {
  readonly model_access_mode?: ApiKeyModelAccessMode;
  readonly model_list?: readonly string[] | ReadonlySet<string> | null;
}

function listIncludes(
  list: readonly string[] | ReadonlySet<string> | null | undefined,
  value: string,
): boolean {
  if (list == null) return false;
  if (Array.isArray(list)) return list.includes(value);
  return (list as ReadonlySet<string>).has(value);
}

export function isModelAllowed(
  policy: ModelAccessPolicy,
  targetModel: string,
  targetProvider?: string,
  requestedModel?: string,
): boolean {
  const slash = targetModel.lastIndexOf("/");
  const bare = slash < 0 ? targetModel : targetModel.slice(slash + 1);
  const qualified = targetProvider ? `${targetProvider}/${bare}` : undefined;
  const names = [targetModel, bare, ...(qualified ? [qualified] : [])];
  if (requestedModel && requestedModel !== targetModel) names.push(requestedModel);
  if (policy.model_access_mode === "blacklist") {
    return !names.some((name) => listIncludes(policy.model_list, name));
  }
  if (policy.model_list == null) return true;
  const empty = Array.isArray(policy.model_list)
    ? policy.model_list.length === 0
    : (policy.model_list as ReadonlySet<string>).size === 0;
  if (empty) return true;
  return names.some((name) => listIncludes(policy.model_list, name));
}

export const PROBE_REASONING_EFFORTS = [
  "auto",
  "minimal",
  "low",
  "medium",
  "high",
  "xhigh",
  "max",
] as const;
export type ProbeReasoningEffort = (typeof PROBE_REASONING_EFFORTS)[number];

export function formatThinkingSuffix(
  model: string,
  level: string | null,
): string {
  return level === null ? model : `${model}(${level})`;
}

export const SPEED_TEST_MIN_BYTES = 1_000_000;
export const SPEED_TEST_MAX_BYTES = 100_000_000;
export const SPEED_TEST_DEFAULT_BYTES = 5_000_000;

export const RELAY_TARGETS: readonly RelayTarget[] = ["cloudflare", "vercel", "deno"];

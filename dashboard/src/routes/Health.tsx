/**
 * Health: process, storage, gateway, connectivity, readiness, and runtime —
 * with a remediation line whenever something is actually wrong.
 *
 * ── Two sources, two questions ─────────────────────────────────────────────
 * `/console/api/system/health` (authenticated) reports how the process is
 * doing: memory, CPU, latency, request counters, DB latency, pool state.
 * `/health/ready` (public) reports whether the process will accept traffic at
 * all. They are shown separately because they can disagree in the one case
 * that matters most: a draining or migration-pending process still answers the
 * console snapshot while refusing new requests.
 *
 * ── Readiness is a checklist, not a boolean ────────────────────────────────
 * `/console/api/system/readiness` owns the five operator steps (admin,
 * provider, model, key, first request). The page renders those steps with
 * their measured details and routes, so a red verdict always has a next move.
 *
 * ── No secrets ─────────────────────────────────────────────────────────────
 * The console health payload contains no credentials or environment values,
 * and this page renders only the fields that endpoint declares. Nothing here
 * reads `process.env`, and the readiness probe's `reason` is the gateway's own
 * fixed vocabulary ("dependency not ready"), never a connection string.
 */
import { useEffect, useMemo, useState, type ReactNode } from "react";
import { Link } from "react-router-dom";
import {
  Activity,
  AlertTriangle,
  ArrowUpRight,
  CheckCircle2,
  Cpu,
  Database,
  Gauge,
  ListChecks,
  Network,
  RefreshCw,
  Server,
  ShieldCheck,
  Timer,
  XCircle,
} from "lucide-react";
import { Badge } from "../components/ui/badge";
import { Card, CardBody, CardHeader } from "../components/ui/card";
import { Button } from "../components/ui/button";
import { Stack } from "../components/ui/stack";
import { LoadingState, ErrorState } from "../components/ui/state";
import { PageHead } from "../components/PageHead";
import { RequestActivity } from "../features/overview/RequestActivity";
import { useReadiness, useReadinessProbe } from "../hooks/readiness";
import { useInFlight } from "../hooks/live";
import {
  useSystemHealth,
  useSystemHealthStream,
  useUpdateStatus,
  useUsageChart,
} from "../hooks/system";
import { useT, type TranslateFn } from "../shared/locale-context";
import { formatAgo, formatBytes, formatDuration, formatNumber } from "../shared/format";
import type { MessageKey } from "../shared/i18n";

/** One label/value pair inside a health group. */
function Fact({
  label,
  value,
  tone,
}: {
  readonly label: string;
  readonly value: ReactNode;
  readonly tone?: "ok" | "danger" | "warn";
}): ReactNode {
  return (
    <div className="health-fact">
      <span className="health-fact-label">{label}</span>
      <span
        className="health-fact-value"
        style={
          tone === "ok"
            ? { color: "var(--green)" }
            : tone === "danger"
              ? { color: "var(--red)" }
              : tone === "warn"
                ? { color: "var(--orange)" }
                : undefined
        }
      >
        {value}
      </span>
    </div>
  );
}

/** A labelled proportion bar used for memory, CPU, and latency spread. */
function Meter({
  value,
  tone = "accent",
  label,
}: {
  readonly value: number;
  readonly tone?: "accent" | "green" | "orange" | "red";
  readonly label?: string;
}): ReactNode {
  const width = Math.max(0, Math.min(100, Number.isFinite(value) ? value : 0));
  return (
    <div className="health-meter" aria-label={label} aria-valuemin={0} aria-valuemax={100} aria-valuenow={Math.round(width)} role="meter">
      <span className={`health-meter-fill health-meter-fill--${tone}`} style={{ width: `${width}%` }} />
    </div>
  );
}

const STATUS_LABEL_KEY: Readonly<Record<"healthy" | "degraded" | "unhealthy", MessageKey>> = {
  healthy: "health.status.healthy",
  degraded: "health.status.degraded",
  unhealthy: "health.status.unhealthy",
};

const REMEDIATION_KEY: Readonly<Record<"healthy" | "degraded" | "unhealthy", MessageKey>> = {
  healthy: "health.remediation.none",
  degraded: "health.remediation.degraded",
  unhealthy: "health.remediation.unhealthy",
};

/** Sub-second resolution for the live process clock; longer spans stay compact. */
function formatLiveUptime(seconds: number | undefined): string {
  if (seconds === undefined || !Number.isFinite(seconds)) return "—";
  const value = Math.max(0, seconds);
  const days = Math.floor(value / 86_400);
  const hours = Math.floor((value % 86_400) / 3_600);
  const minutes = Math.floor((value % 3_600) / 60);
  const secs = (value % 60).toFixed(2);
  if (days > 0) return `${days}d ${hours}h ${minutes}m ${secs}s`;
  if (hours > 0) return `${hours}h ${minutes}m ${secs}s`;
  return minutes > 0 ? `${minutes}m ${secs}s` : `${secs}s`;
}

/**
 * The server snapshot is sampled, but uptime is a clock. Advance it locally
 * between snapshots so the figure never sits still for a whole poll interval,
 * then re-anchor when a fresh snapshot arrives.
 */
function useLiveUptime(serverSeconds: number | undefined, updatedAt: number): number | undefined {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const timer = window.setInterval(() => setNow(Date.now()), 100);
    return () => window.clearInterval(timer);
  }, []);
  if (serverSeconds === undefined) return undefined;
  return serverSeconds + Math.max(0, now - updatedAt) / 1000;
}

function endpointBadge(
  connected: boolean | undefined,
  t: TranslateFn,
): ReactNode {
  if (connected === undefined) return <Badge tone="warn">{t("common.unavailable")}</Badge>;
  return connected ? (
    <Badge tone="ok" dot>
      {t("health.connected")}
    </Badge>
  ) : (
    <Badge tone="err" dot>
      {t("health.disconnected")}
    </Badge>
  );
}

export default function Health(): ReactNode {
  const t = useT();
  const healthQuery = useSystemHealth(5_000);
  const streamLive = useSystemHealthStream();
  const probeQuery = useReadinessProbe(1_000);
  const readiness = useReadiness();
  const inFlight = useInFlight();
  const chartQuery = useUsageChart("24h");
  const updateQuery = useUpdateStatus();
  const health = healthQuery.data;
  const liveUptime = useLiveUptime(health?.uptime_seconds, healthQuery.dataUpdatedAt);

  const dbConnected = probeQuery.data?.db
    ? probeQuery.data.db === "connected"
    : health?.database_healthy;
  const redisConnected = probeQuery.data?.redis
    ? probeQuery.data.redis === "connected"
    : health?.redis_healthy;
  const migrations = probeQuery.data?.migrations;

  // The single worst signal decides the headline: a healthy process with a
  // failing readiness probe is not "healthy", and saying so would be the exact
  // false reassurance this page exists to prevent.
  const overall = useMemo<"healthy" | "degraded" | "unhealthy" | undefined>(() => {
    if (!health) return undefined;
    if (dbConnected === false || health.status === "unhealthy") return "unhealthy";
    if (redisConnected === false) return "degraded";
    if (probeQuery.data && !probeQuery.data.ready) return "degraded";
    return health.status;
  }, [health, probeQuery.data, dbConnected, redisConnected]);

  // Storage-specific remediation wins over the generic one: "check DATABASE_URL"
  // is actionable where "gateway degraded" is not.
  const remediationKey = useMemo<MessageKey>(() => {
    if (!health) return "health.remediation.none";
    if (dbConnected === false) return "health.remediation.db";
    if (redisConnected === false) return "health.remediation.redis";
    if (overall === undefined) return "health.remediation.none";
    return REMEDIATION_KEY[overall];
  }, [health, overall, dbConnected, redisConnected]);

  const remediationTone = overall === "healthy" ? "ok" : overall === "unhealthy" ? "danger" : undefined;
  const requestCount = health?.request_count ?? 0;
  const errorCount = health?.error_count ?? 0;
  const errorRate =
    health?.error_rate_percent ??
    (requestCount > 0 ? (errorCount / requestCount) * 100 : 0);
  const p50 = health?.latency_p50_ms ?? 0;
  const p95 = health?.latency_p95_ms ?? 0;
  const p99 = health?.latency_p99_ms ?? 0;
  const avgLatency = health?.latency_avg_ms ?? 0;
  const tailGap = Math.max(0, p95 - avgLatency);
  const memoryPercent = health?.memory_percent ?? 0;
  const cpuPercent = health?.cpu_percent ?? 0;
  const readinessPercent =
    readiness.totalRequired > 0
      ? Math.round((readiness.completedRequired / readiness.totalRequired) * 100)
      : 0;
  const latest = updateQuery.data;

  return (
    <div className="dashboard-page">
      <PageHead
        eyebrow="Monitor / Runtime health"
        title={"Health\nin detail."}
        description={t("health.subtitle")}
        stats={[
          {
            label: "Verdict",
            value: health ? t(`health.status.${overall ?? "healthy"}` as never) : "—",
            meta: health ? `${health.version} · ${health.platform}` : "Menunggu snapshot",
          },
          {
            label: "Uptime",
            value: formatLiveUptime(liveUptime),
            meta: "Since process start",
          },
          {
            label: "Requests · 24h",
            value: health ? formatNumber(requestCount) : "—",
            meta: `${formatNumber(errorCount)} errors · ${formatNumber(errorRate, undefined)}%`,
          },
          {
            label: "Latency p95",
            value: health ? formatDuration(p95) : "—",
            meta: health ? `avg ${formatDuration(avgLatency)} · p99 ${formatDuration(p99)}` : "No data",
          },
          {
            label: "Memory",
            value: health ? formatBytes(health.memory_bytes) : "—",
            meta: health ? `${formatNumber(memoryPercent)}% of limit` : "No data",
          },
          {
            label: "CPU",
            value: health ? `${formatNumber(cpuPercent, undefined)}%` : "—",
            meta: health ? `${health.cpu_cores} cores · load ${formatNumber(health.load_average_1, undefined)}` : "No data",
          },
        ]}
      />

      {healthQuery.isPending ? (
        <LoadingState label={t("state.loading")} />
      ) : healthQuery.isError || !health ? (
        <ErrorState
          title={t("state.error.title")}
          message={t("state.error.retryHint")}
          onRetry={() => void healthQuery.refetch()}
          retrying={healthQuery.isFetching}
        />
      ) : (
        <Stack gap="14px">
          <Card>
            <CardHeader
              title={t("health.overall")}
              subtitle={`${health.version} · ${health.platform} · ${health.architecture ?? ""}`}
              icon={<Gauge size={15} />}
              action={
                <div style={{ display: "flex", alignItems: "center", gap: "8px", flexWrap: "wrap" }}>
                  {/* A live figure with no timestamp is indistinguishable from a
                      frozen one. This says when the numbers beside it were read,
                      and the dot marks the moment a poll is in flight — so a
                      stalled refresh is visible instead of silently stale. */}
                  <span className="health-freshness" aria-live="polite">
                    <span
                      className={`health-freshness-dot${healthQuery.isFetching ? " is-live" : ""}`}
                      aria-hidden="true"
                    />
                    {t("health.lastChecked", {
                      time: formatAgo(new Date(healthQuery.dataUpdatedAt)),
                    })}
                  </span>
                  <span className={`health-live${streamLive ? " is-live" : ""}`}>
                    <span className="health-live-dot" aria-hidden="true" />
                    {streamLive ? t("health.live") : t("health.connecting")}
                  </span>
                  <Button
                    variant="secondary"
                    size="sm"
                    icon={<RefreshCw size={13} className={healthQuery.isFetching ? "animate-spin" : ""} />}
                    onClick={() => {
                      void healthQuery.refetch();
                      void probeQuery.refetch();
                      readiness.refresh();
                      void chartQuery.refetch();
                    }}
                    disabled={healthQuery.isFetching}
                  >
                    {healthQuery.isFetching ? t("action.refreshing") : t("action.refresh")}
                  </Button>
                </div>
              }
            />
            <CardBody>
              <Stack gap="12px">
                <div
                  style={{ display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap" }}
                  role="status"
                  aria-live="polite"
                >
                  {overall === "healthy" ? (
                    <CheckCircle2 size={20} style={{ color: "var(--green)" }} aria-hidden="true" />
                  ) : (
                    <AlertTriangle size={20} style={{ color: "var(--red)" }} aria-hidden="true" />
                  )}
                  <span
                    style={{
                      fontSize: 15,
                      fontWeight: 700,
                      color: overall === "healthy" ? "var(--green)" : "var(--red)",
                    }}
                  >
                    {overall === undefined ? t("state.loading") : t(STATUS_LABEL_KEY[overall])}
                  </span>
                  <span className="health-live" style={{ marginLeft: "auto" }}>
                    {streamLive ? t("health.streamConnected") : t("health.streamDisconnected")}
                  </span>
                </div>

                <p className="health-remediation" data-tone={remediationTone}>
                  {overall === "healthy" ? (
                    <CheckCircle2 size={15} aria-hidden="true" style={{ flexShrink: 0, marginTop: 1 }} />
                  ) : (
                    <AlertTriangle size={15} aria-hidden="true" style={{ flexShrink: 0, marginTop: 1 }} />
                  )}
                  <span>
                    <strong style={{ display: "block", marginBottom: 2 }}>
                      {t("health.remediation")}
                    </strong>
                    {t(remediationKey)}
                  </span>
                </p>
              </Stack>
            </CardBody>
          </Card>

          <Card>
            <CardHeader
              title={t("health.readiness")}
              subtitle={t("health.readinessSubtitle")}
              icon={<ListChecks size={15} />}
              action={
                <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                  <Badge tone={readiness.ready ? "ok" : "warn"} dot>
                    {readiness.ready ? t("health.ready") : t("health.notReady")}
                  </Badge>
                  <Button
                    variant="secondary"
                    size="sm"
                    icon={<RefreshCw size={13} className={readiness.isRefreshing ? "animate-spin" : ""} />}
                    onClick={readiness.refresh}
                    disabled={readiness.isRefreshing}
                  >
                    {t("action.refresh")}
                  </Button>
                </div>
              }
            />
            <CardBody>
              {readiness.isLoading ? (
                <LoadingState label={t("state.loading")} />
              ) : readiness.isError ? (
                <ErrorState message={t("health.readinessUnavailable")} onRetry={readiness.refresh} />
              ) : (
                <Stack gap="10px">
                  <div className="health-readiness-summary">
                    <span>
                      <strong>{readiness.completedRequired}</strong> / {readiness.totalRequired}{" "}
                      {t("health.requiredSteps")}
                    </span>
                    <span>{readinessPercent}%</span>
                  </div>
                  <div className="health-meter" role="progressbar" aria-valuemin={0} aria-valuemax={100} aria-valuenow={readinessPercent}>
                    <span
                      className={`health-meter-fill ${readiness.ready ? "health-meter-fill--green" : "health-meter-fill--orange"}`}
                      style={{ width: `${readinessPercent}%` }}
                    />
                  </div>
                  <div className="health-readiness-list">
                    {readiness.steps.map((step) => (
                      <Link
                        key={step.id}
                        to={step.route}
                        className="health-readiness-item"
                        data-state={step.state}
                      >
                        <span className="health-readiness-mark" aria-hidden="true">
                          {step.state === "done" ? (
                            <CheckCircle2 size={15} />
                          ) : step.state === "todo" ? (
                            <XCircle size={15} />
                          ) : (
                            <AlertTriangle size={15} />
                          )}
                        </span>
                        <span className="health-readiness-copy">
                          <span className="health-readiness-title">
                            {t(step.titleKey)}
                            {step.required ? null : (
                              <span className="health-readiness-optional">{t("health.optional")}</span>
                            )}
                          </span>
                          {step.detail ? (
                            <span className="health-readiness-detail">{step.detail}</span>
                          ) : null}
                          {step.remediation ? (
                            <span className="health-readiness-remediation">{step.remediation}</span>
                          ) : null}
                        </span>
                        <ArrowUpRight size={13} aria-hidden="true" className="health-readiness-arrow" />
                      </Link>
                    ))}
                  </div>
                </Stack>
              )}
            </CardBody>
          </Card>

          <div className="health-grid">
            <Card>
              <CardHeader title={t("health.performance")} subtitle={t("health.performanceSubtitle")} icon={<Timer size={15} />} />
              <CardBody>
                <Fact label={t("health.latency")} value={formatDuration(avgLatency)} />
                <Fact label="p50" value={formatDuration(p50)} />
                <Fact label={t("health.latencyP95")} value={formatDuration(p95)} />
                <Fact label="p99" value={formatDuration(p99)} />
                <Fact label={t("health.tailGap")} value={formatDuration(tailGap)} tone={tailGap > 2_000 ? "warn" : undefined} />
                <Fact
                  label={t("health.errorRate")}
                  value={`${formatNumber(errorRate, undefined)}%`}
                  tone={errorRate >= 5 ? "danger" : errorRate >= 1 ? "warn" : "ok"}
                />
                <div className="health-meter-row">
                  <span>p50</span>
                  <Meter value={(p50 / Math.max(1, p99)) * 100} label="p50 share of p99" />
                  <span>p99</span>
                </div>
              </CardBody>
            </Card>

            <Card>
              <CardHeader title={t("health.process")} subtitle={t("health.processSubtitle")} icon={<Cpu size={15} />} />
              <CardBody>
                <Fact label={t("health.uptime")} value={formatLiveUptime(liveUptime)} />
                <Fact label={t("health.pid")} value={health.pid} />
                <Fact label={t("health.platform")} value={`${health.platform} · ${health.architecture ?? "—"}`} />
                <Fact label={t("health.cpuCores")} value={health.cpu_cores} />
                <Fact
                  label="CPU"
                  value={`${formatNumber(cpuPercent, undefined)}%`}
                  tone={cpuPercent > 90 ? "danger" : cpuPercent > 70 ? "warn" : undefined}
                />
                <Meter value={cpuPercent} tone={cpuPercent > 90 ? "red" : cpuPercent > 70 ? "orange" : "accent"} label="CPU usage" />
                <Fact
                  label={t("health.memory")}
                  value={`${formatBytes(health.memory_bytes)} · ${formatNumber(memoryPercent)}%`}
                  tone={memoryPercent > 90 ? "danger" : undefined}
                />
                <Meter value={memoryPercent} tone={memoryPercent > 90 ? "red" : "accent"} label="Memory usage" />
                <Fact label={t("health.memoryLimit")} value={formatBytes(health.memory_limit_bytes)} />
                <Fact label={t("health.virtualMemory")} value={formatBytes(health.virtual_memory_bytes)} />
                <Fact label={t("health.threads")} value={health.thread_count ? formatNumber(health.thread_count) : "—"} />
                <Fact label={t("health.systemMemory")} value={`${formatBytes(health.system_memory_used_bytes)} / ${formatBytes(health.system_memory_bytes)}`} />
                <Fact label={t("health.availableMemory")} value={formatBytes(health.system_memory_available_bytes)} />
                <Fact label={t("health.loadAverage")} value={`${formatNumber(health.load_average_1, undefined)} · ${formatNumber(health.load_average_5, undefined)} · ${formatNumber(health.load_average_15, undefined)}`} />
              </CardBody>
            </Card>

            <Card>
              <CardHeader title={t("health.storage")} subtitle={t("health.storageSubtitle")} icon={<Database size={15} />} />
              <CardBody>
                <Fact
                  label={t("health.database")}
                  value={endpointBadge(dbConnected, t)}
                  tone={dbConnected === false ? "danger" : dbConnected ? "ok" : undefined}
                />
                <Fact label={t("health.databaseLatency")} value={formatDuration(health.database_latency_ms)} tone={(health.database_latency_ms ?? 0) > 100 ? "warn" : "ok"} />
                <Fact label={t("health.pool")} value={`${formatNumber(health.database_pool_size)} total · ${formatNumber(health.database_pool_idle)} idle`} />
                <Fact
                  label={t("health.redis")}
                  value={endpointBadge(redisConnected, t)}
                  tone={redisConnected === false ? "danger" : redisConnected ? "ok" : undefined}
                />
                <Fact
                  label={t("health.redisMode")}
                  value={health.redis_mode === "external" ? t("health.redisExternal") : t("health.redisInMemory")}
                />
                <Fact
                  label={t("health.migrations")}
                  value={
                    migrations === "applied"
                      ? t("health.applied")
                      : migrations === "pending"
                        ? t("health.pending")
                        : t("common.unavailable")
                  }
                  tone={migrations === "applied" ? "ok" : migrations === "pending" ? "danger" : undefined}
                />
                <Fact
                  label={t("health.readinessProbe")}
                  value={
                    probeQuery.isPending
                      ? t("state.loading")
                      : probeQuery.isError
                        ? t("state.offline")
                        : probeQuery.data?.ready
                          ? t("health.readinessReady")
                          : t("health.readinessNotReady", { reason: probeQuery.data?.reason ?? "unknown" })
                  }
                  tone={probeQuery.data?.ready ? "ok" : probeQuery.isError ? "danger" : undefined}
                />
              </CardBody>
            </Card>

            <Card>
              <CardHeader title={t("health.gateway")} subtitle={t("health.gatewaySubtitle")} icon={<Server size={15} />} />
              <CardBody>
                <Fact label={t("health.version")} value={health.version} />
                <Fact label={t("health.requestsWindow")} value={formatNumber(requestCount)} />
                <Fact label={t("health.successes")} value={formatNumber(health.success_count ?? requestCount - errorCount)} tone="ok" />
                <Fact
                  label={t("health.errors")}
                  value={formatNumber(errorCount)}
                  tone={errorCount > 0 ? "danger" : undefined}
                />
                <Fact
                  label={t("health.errorRate")}
                  value={`${formatNumber(errorRate, undefined)}%`}
                  tone={errorRate >= 5 ? "danger" : errorRate >= 1 ? "warn" : "ok"}
                />
                <Fact label={t("health.tokensPerSec")} value={formatNumber(health.avg_tokens_per_sec)} />
                <Fact label={t("health.cacheHit")} value={`${formatNumber(health.cache_hit_rate_percent)}%`} />
                <Fact label={t("health.inputTokens")} value={formatNumber(health.input_tokens)} />
                <Fact label={t("health.outputTokens")} value={formatNumber(health.output_tokens)} />
                <Fact label={t("health.cachedTokens")} value={formatNumber(health.cached_tokens)} />
              </CardBody>
            </Card>
          </div>

          <Card>
            <CardHeader
              title={t("health.activityTitle")}
              subtitle={t("health.activitySubtitle")}
              icon={<Activity size={15} />}
              action={<Badge tone="info">{t("health.window24h")}</Badge>}
            />
            <CardBody>
              <RequestActivity
                chart={chartQuery.data}
                pending={chartQuery.isPending}
                error={chartQuery.isError}
                onRetry={() => void chartQuery.refetch()}
                errorCount={errorCount}
              />
            </CardBody>
          </Card>

          <div className="health-grid">
            <Card>
              <CardHeader
                title={t("health.traffic")}
                icon={<Activity size={15} />}
                action={
                  <span className={`health-live${inFlight.live ? " is-live" : ""}`}>
                    <span className="health-live-dot" aria-hidden="true" />
                    {inFlight.live ? t("health.live") : t("health.connecting")}
                  </span>
                }
              />
              <CardBody>
                <Fact
                  label={t("health.inFlight")}
                  value={inFlight.count === null ? "—" : formatNumber(inFlight.count)}
                  tone={inFlight.count ? "ok" : undefined}
                />
                <Fact
                  label={t("health.uniqueIps")}
                  value={inFlight.uniqueIps === null ? "—" : formatNumber(inFlight.uniqueIps)}
                />
                <Fact label={t("health.stream")} value={streamLive ? t("health.streamConnected") : t("health.streamDisconnected")} tone={streamLive ? "ok" : "warn"} />
                <Fact label={t("health.lastChecked")} value={formatAgo(new Date(healthQuery.dataUpdatedAt))} />
              </CardBody>
            </Card>

            <Card>
              <CardHeader title={t("health.connectivity")} subtitle={t("health.connectivitySubtitle")} icon={<Network size={15} />} />
              <CardBody>
                <Stack gap="0px">
                  <a className="health-endpoint" href="/health/ready" target="_blank" rel="noreferrer">
                    <span><code>/health/ready</code><small>{t("health.publicProbe")}</small></span>
                    {endpointBadge(probeQuery.data?.ready, t)}
                  </a>
                  <a className="health-endpoint" href="/console/api/system/health" target="_blank" rel="noreferrer">
                    <span><code>/console/api/system/health</code><small>{t("health.consoleSnapshot")}</small></span>
                    <ArrowUpRight size={13} aria-hidden="true" />
                  </a>
                  <a className="health-endpoint" href="/metrics" target="_blank" rel="noreferrer">
                    <span><code>/metrics</code><small>{t("health.metrics")}</small></span>
                    <ArrowUpRight size={13} aria-hidden="true" />
                  </a>
                  <a className="health-endpoint" href="/health" target="_blank" rel="noreferrer">
                    <span><code>/health</code><small>{t("health.liveness")}</small></span>
                    <ArrowUpRight size={13} aria-hidden="true" />
                  </a>
                </Stack>
              </CardBody>
            </Card>

            <Card>
              <CardHeader title={t("health.release")} subtitle={t("health.releaseSubtitle")} icon={<ShieldCheck size={15} />} />
              <CardBody>
                <Fact label={t("health.currentVersion")} value={health.version} />
                <Fact
                  label={t("health.latestVersion")}
                  value={latest?.latestVersion ?? (latest?.checkDisabled ? t("health.checkDisabled") : updateQuery.isError ? t("common.unavailable") : "—")}
                />
                <Fact
                  label={t("health.updateStatus")}
                  value={
                    latest?.updateAvailable
                      ? t("health.updateAvailable")
                      : latest?.checkDisabled
                        ? t("health.checkDisabled")
                        : latest?.checkFailed
                          ? t("health.releaseCheckUnavailable")
                          : t("health.upToDate")
                  }
                  tone={latest?.updateAvailable ? "warn" : latest?.checkFailed ? "danger" : "ok"}
                />
                {latest?.releaseUrl ? (
                  <a className="health-release-link" href={latest.releaseUrl} target="_blank" rel="noreferrer">
                    {latest.releaseName ?? latest.releaseUrl}
                    <ArrowUpRight size={13} aria-hidden="true" />
                  </a>
                ) : null}
                <Fact label={t("health.releaseChecked")} value={latest ? formatAgo(latest.checkedAt) : "—"} />
              </CardBody>
            </Card>
          </div>
        </Stack>
      )}
    </div>
  );
}

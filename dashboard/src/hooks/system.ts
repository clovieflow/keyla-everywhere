import { consoleRequest, fetchSessionUser } from "../data/api";
import type { ApiErrorShape } from "../data/api";
import { queryKeys } from "../data/query-keys";
import type { SessionUser, UsageDimension } from "../data/contracts";
import { assertAuditListPage, assertSystemHealth, assertUsageBy, assertUsageChart, assertUsageRequestDetail, assertUsageRequests, assertUsageSummary, querySignal } from "./common";
import { DASHBOARD_QUERY_OPTIONS } from "../data/query-policy";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";



/**
 * Subscribes the shared health query to the gateway's SSE snapshot. Every
 * frame replaces the cached snapshot, so process, request, and latency fields
 * move together without a browser-side poll. The normal query remains mounted
 * as a slower fallback; this hook only closes the perceived gap.
 */
export function useSystemHealthStream() {
  const queryClient = useQueryClient();
  const [live, setLive] = useState(false);

  useEffect(() => {
    let stopped = false;
    let source: EventSource | undefined;
    let retryTimer: ReturnType<typeof setTimeout> | undefined;

    const apply = (raw: string) => {
      if (stopped) return;
      try {
        const parsed = assertSystemHealth(JSON.parse(raw) as unknown);
        queryClient.setQueryData(queryKeys.system.health, parsed);
        setLive(true);
      } catch {
        // A malformed frame leaves the last snapshot in place.
      }
    };

    const connect = () => {
      source = new EventSource("/console/api/system/health/stream");
      source.addEventListener("init", (event) => apply((event as MessageEvent).data as string));
      source.addEventListener("health", (event) => apply((event as MessageEvent).data as string));
      source.onerror = () => {
        if (stopped) return;
        source?.close();
        source = undefined;
        setLive(false);
        retryTimer = setTimeout(() => {
          if (!stopped) connect();
        }, 1_000);
      };
    };

    connect();
    return () => {
      stopped = true;
      if (retryTimer !== undefined) clearTimeout(retryTimer);
      source?.close();
    };
  }, [queryClient]);

  return live;
}

export interface UpdateStatus {
  readonly currentVersion: string;
  readonly latestVersion: string | null;
  readonly updateAvailable: boolean;
  readonly releaseUrl: string | null;
  readonly releaseName: string | null;
  readonly publishedAt: string | null;
  readonly checkFailed: boolean;
  readonly checkDisabled: boolean;
  readonly checkedAt: string;
}

/** Cached latest-release check served by the gateway. */
export function useUpdateStatus() {
  return useQuery<UpdateStatus, ApiErrorShape>({
    queryKey: queryKeys.system.update,
    queryFn: (context) =>
      consoleRequest<UpdateStatus>("/system/update", { signal: querySignal(context) }),
    staleTime: 15 * 60_000,
    refetchInterval: 15 * 60_000,
    retry: 1,
  });
}

/** Loads the current signed-in console user, including `isPlatformAdmin`,
 * so pages can hide (never solely rely on hiding — the server remains the
 * real enforcement) controls the user's scope cannot use. */
export function useSessionUser() {
  return useQuery<SessionUser | null>({
    queryKey: queryKeys.session.current,
    queryFn: () => fetchSessionUser(),
    staleTime: 60_000,
    gcTime: 300_000,
    retry: false,
    refetchOnWindowFocus: false,
  });
}

/**
 * Loads the process health snapshot.
 *
 * `intervalMs` defaults to the console-wide cadence. The Health page passes a
 * faster one because it answers "is the gateway healthy right now", where a
 * quarter-minute-old figure cannot: a process that started refusing traffic two
 * seconds ago would still read as healthy. The shell's status dot reads the
 * same query and does not need that resolution, so it keeps the slower default.
 *
 * React Query shares one cache entry across both observers, so while the Health
 * page is open its interval drives the refetch and the shell's dot benefits;
 * when the page closes, the slower default applies again.
 */
export function useSystemHealth(intervalMs = 15_000) {
  return useQuery({
    queryKey: queryKeys.system.health,
    queryFn: (context) =>
      consoleRequest<unknown>("/system/health", { signal: querySignal(context) }).then(
        assertSystemHealth,
      ),
    ...DASHBOARD_QUERY_OPTIONS,
    refetchInterval: intervalMs,
  });
}

/** Loads the 20-beta-style usage summary for a period. */
export function useUsageSummary(period: string) {
  return useQuery({
    queryKey: queryKeys.usageAnalytics.summary(period),
    queryFn: (context) =>
      consoleRequest<unknown>(`/system/usage/summary?period=${encodeURIComponent(period)}`, {
        signal: querySignal(context),
      }).then(assertUsageSummary),
    ...DASHBOARD_QUERY_OPTIONS,
    refetchInterval: 3_000,
  });
}

/** Loads time-series buckets for the traffic chart. */
export function useUsageChart(period: string) {
  return useQuery({
    queryKey: queryKeys.usageAnalytics.chart(period),
    queryFn: (context) =>
      consoleRequest<unknown>(`/system/usage/chart?period=${encodeURIComponent(period)}`, {
        signal: querySignal(context),
      }).then(assertUsageChart),
    ...DASHBOARD_QUERY_OPTIONS,
    refetchInterval: 3_000,
  });
}

/** Loads one usage breakdown dimension (see `USAGE_DIMENSIONS`). */
export function useUsageBy(period: string, dimension: UsageDimension) {
  return useQuery({
    queryKey: queryKeys.usageAnalytics.by(period, dimension),
    queryFn: (context) =>
      consoleRequest<unknown>(
        `/system/usage/by-${dimension}?period=${encodeURIComponent(period)}`,
        { signal: querySignal(context) },
      ).then(assertUsageBy),
    ...DASHBOARD_QUERY_OPTIONS,
    refetchInterval: 3_000,
  });
}

/** Loads the most recent requests for the live table. */
export function useUsageRequests(
  period: string,
  limit = 50,
  httpStatus?: number | null,
) {
  const statusParam = httpStatus === null || httpStatus === undefined
    ? ""
    : `&httpStatus=${encodeURIComponent(String(httpStatus))}`;
  return useQuery({
    queryKey: queryKeys.usageAnalytics.requests(period, limit, httpStatus),
    queryFn: (context) =>
      consoleRequest<unknown>(
        `/system/usage/requests?period=${encodeURIComponent(period)}&limit=${encodeURIComponent(String(limit))}${statusParam}`,
        { signal: querySignal(context) },
      ).then(assertUsageRequests),
    ...DASHBOARD_QUERY_OPTIONS,
    // Same cadence as the summary cards: one page, one rhythm. Two
    // different intervals let the table refresh while the totals beside
    // it still showed the previous second, which reads as a disagreement.
    refetchInterval: 3_000,
  });
}

/** Loads one request's detail for the inspector dialog. */
export function useUsageRequestDetail(requestId: string | null) {
  return useQuery({
    queryKey: queryKeys.usageAnalytics.requestDetail(requestId ?? "_"),
    queryFn: (context) => {
      if (!requestId) throw { status: 400, code: "invalid_request", message: "Request is required" } satisfies ApiErrorShape;
      return consoleRequest<unknown>(`/system/usage/requests/${encodeURIComponent(requestId)}`, {
        signal: querySignal(context),
      }).then(assertUsageRequestDetail);
    },
    enabled: requestId !== null,
    ...DASHBOARD_QUERY_OPTIONS,
  });
}

export function useAuditTrail(filters?: {
  action?: string;
  actor?: string;
  cursor?: string;
  limit?: number;
}) {
  return useQuery({
    queryKey: queryKeys.audit.list(filters ?? {}),
    queryFn: (context) => {
      const search = new URLSearchParams();
      if (filters?.action) search.set("action", filters.action);
      if (filters?.actor) search.set("actor", filters.actor);
      if (filters?.cursor) search.set("cursor", filters.cursor);
      if (filters?.limit) search.set("limit", String(filters.limit));
      const suffix = search.toString() ? `?${search.toString()}` : "";
      return consoleRequest<unknown>(`/audit${suffix}`, { signal: querySignal(context) }).then(
        assertAuditListPage,
      );
    },
    ...DASHBOARD_QUERY_OPTIONS,
  });
}

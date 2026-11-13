import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { consoleRequest, type ApiErrorShape } from "../data/api";
import { queryKeys } from "../data/query-keys";
import { DASHBOARD_QUERY_OPTIONS } from "../data/query-policy";
import { querySignal } from "./common";

export type PromptInjectionPlacement = "developer" | "system";

export interface PromptInjectionSettings {
  readonly enabled: boolean;
  readonly prompt: string;
  readonly targetModels: readonly string[];
  readonly placement: PromptInjectionPlacement;
  readonly updatedAt: string;
}

export interface UpdatePromptInjectionSettings {
  readonly enabled?: boolean;
  readonly prompt?: string;
  readonly targetModels?: readonly string[];
  readonly placement?: PromptInjectionPlacement;
}

/** Loads the tenant Prompt Injection policy used by the request path. */
export function usePromptInjection() {
  return useQuery<PromptInjectionSettings, ApiErrorShape>({
    queryKey: queryKeys.settings.promptInjection,
    queryFn: (context) =>
      consoleRequest<PromptInjectionSettings>("/prompt-injection", {
        signal: querySignal(context),
      }),
    ...DASHBOARD_QUERY_OPTIONS,
  });
}

/** Saves a partial policy and refreshes the page from the server. */
export function useUpdatePromptInjection() {
  const queryClient = useQueryClient();
  return useMutation<PromptInjectionSettings, ApiErrorShape, UpdatePromptInjectionSettings>({
    mutationFn: (request) =>
      consoleRequest<PromptInjectionSettings>("/prompt-injection", {
        method: "PATCH",
        body: JSON.stringify(request),
      }),
    onSuccess: async (settings) => {
      queryClient.setQueryData(queryKeys.settings.promptInjection, settings);
      await queryClient.invalidateQueries({ queryKey: queryKeys.settings.promptInjection });
    },
  });
}

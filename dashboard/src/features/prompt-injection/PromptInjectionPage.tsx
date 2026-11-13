/**
 * Prompt Injection — trusted request instructions before dispatch.
 *
 * The operator's text is appended to the canonical developer/system block, not
 * to a user message. Target-model selection is real routing input: an empty
 * list means every model, a non-empty list matches the requested or resolved
 * model id.
 */
import { AlertTriangle, ArrowRight, Check, Layers, Sparkles, X } from "lucide-react";
import { useEffect, useMemo, useState, type ReactNode } from "react";
import { Badge } from "../../components/ui/badge";
import { Button } from "../../components/ui/button";
import { Card, CardBody, CardHeader } from "../../components/ui/card";
import { ErrorState, LoadingState } from "../../components/ui/state";
import { Select } from "../../components/ui/select";
import { Stack } from "../../components/ui/stack";
import { Switch } from "../../components/ui/switch";
import { Textarea } from "../../components/ui/input";
import { ModelPickerModal } from "../../components/ModelPicker";
import { PageHead } from "../../components/PageHead";
import { usePromptInjection, useUpdatePromptInjection, type PromptInjectionSettings } from "../../hooks/prompt-injection";
import { useT } from "../../shared/locale-context";
import { getErrorMessage } from "../../shared/helpers";
import { toast } from "../../shared/toast";

const PROMPT_MAX_CHARS = 32_000;

const pipeline = [
  { titleKey: "promptInjection.stageRequest", bodyKey: "promptInjection.stageRequestBody" },
  { titleKey: "promptInjection.stagePreflight", bodyKey: "promptInjection.stagePreflightBody" },
  { titleKey: "promptInjection.stageModel", bodyKey: "promptInjection.stageModelBody" },
] as const;

function sameDraft(left: PromptInjectionSettings, right: PromptInjectionSettings): boolean {
  return (
    left.enabled === right.enabled &&
    left.prompt === right.prompt &&
    left.placement === right.placement &&
    left.targetModels.length === right.targetModels.length &&
    left.targetModels.every((value, index) => value === right.targetModels[index])
  );
}

export default function PromptInjectionPage(): ReactNode {
  const t = useT();
  const query = usePromptInjection();
  const update = useUpdatePromptInjection();
  const [draft, setDraft] = useState<PromptInjectionSettings | null>(null);
  const [pickerOpen, setPickerOpen] = useState(false);

  useEffect(() => {
    if (query.data !== undefined) setDraft(query.data);
  }, [query.data]);

  const settings = draft ?? query.data;
  const dirty = settings !== undefined && query.data !== undefined && !sameDraft(settings, query.data);
  const active = settings?.enabled === true && (settings.prompt.trim().length ?? 0) > 0;
  const canSave = dirty && (!settings?.enabled || (settings?.prompt.trim().length ?? 0) > 0);
  const selectedModels = settings?.targetModels ?? [];

  const modelSummary = useMemo(
    () =>
      selectedModels.length === 0
        ? t("promptInjection.targetsAll")
        : t("promptInjection.targetsSelected").replace("{count}", String(selectedModels.length)),
    [selectedModels.length, t],
  );

  if (query.isPending && settings === undefined) {
    return <LoadingState label={t("promptInjection.loading")} />;
  }
  if (query.isError && settings === undefined) {
    return (
      <ErrorState
        message={getErrorMessage(query.error, t("promptInjection.loadFailed"))}
        onRetry={() => void query.refetch()}
      />
    );
  }
  if (settings === undefined) return null;

  const patch = (next: Partial<PromptInjectionSettings>) => {
    setDraft({ ...settings, ...next });
  };

  const save = () => {
    update.mutate(
      {
        enabled: settings.enabled,
        prompt: settings.prompt,
        targetModels: settings.targetModels,
        placement: settings.placement,
      },
      {
        onSuccess: (saved) => {
          setDraft(saved);
          toast.success(t("promptInjection.savedTitle"), t("promptInjection.savedBody"));
        },
        onError: (error) =>
          toast.error(
            t("promptInjection.saveFailedTitle"),
            getErrorMessage(error, t("promptInjection.saveFailedBody")),
          ),
      },
    );
  };

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "12px" }}>
      <PageHead
        eyebrow={t("promptInjection.eyebrow")}
        title={"Injection\nlayer."}
        description={t("promptInjection.description")}
        stats={[
          {
            label: t("promptInjection.statEngine"),
            value: active ? t("promptInjection.active") : t("promptInjection.inactive"),
            meta: active ? t("promptInjection.engineNote") : t("promptInjection.inactiveNote"),
          },
          {
            label: t("promptInjection.statMode"),
            value: settings.placement === "system"
              ? t("promptInjection.placementSystem")
              : t("promptInjection.placementDeveloper"),
            meta: t("promptInjection.placementHint"),
          },
          {
            label: t("promptInjection.statScope"),
            value: modelSummary,
            meta: t("promptInjection.targetsHint"),
          },
        ]}
      />

      <Card>
        <CardHeader
          title={t("promptInjection.configTitle")}
          subtitle={t("promptInjection.configSubtitle")}
          icon={<Sparkles size={16} />}
          action={
            <Badge tone={active ? "ok" : "disabled"} dot>
              {active ? t("promptInjection.active") : t("promptInjection.inactive")}
            </Badge>
          }
        />
        <CardBody>
          <Stack gap="16px">
            <div
              style={{
                display: "flex",
                alignItems: "center",
                justifyContent: "space-between",
                gap: "12px",
                flexWrap: "wrap",
                padding: "10px 12px",
                border: "1px solid var(--inner-border)",
                borderRadius: "10px",
                background: "var(--surface-2)",
              }}
            >
              <div style={{ minWidth: 0 }}>
                <div style={{ fontSize: "12px", fontWeight: 700 }}>
                  {t("promptInjection.enableLabel")}
                </div>
                <p
                  style={{
                    margin: "3px 0 0",
                    fontSize: "11px",
                    color: "var(--text-tertiary)",
                    lineHeight: 1.45,
                  }}
                >
                  {t("promptInjection.enableHint")}
                </p>
              </div>
              <Switch
                checked={settings.enabled}
                onChange={(enabled) => patch({ enabled })}
                aria-label={t("promptInjection.enableLabel")}
              />
            </div>

            <Textarea
              id="prompt-injection-text"
              label={t("promptInjection.promptLabel")}
              hint={t("promptInjection.promptHint")}
              value={settings.prompt}
              maxLength={PROMPT_MAX_CHARS}
              rows={9}
              placeholder={t("promptInjection.promptPlaceholder")}
              onChange={(event) => patch({ prompt: event.target.value })}
              style={{ minHeight: "180px" }}
            />
            <div
              style={{
                display: "flex",
                justifyContent: "space-between",
                gap: "8px",
                marginTop: "-10px",
                fontSize: "10.5px",
                color: "var(--text-tertiary)",
              }}
            >
              <span>
                {settings.enabled && settings.prompt.trim().length === 0
                  ? t("promptInjection.promptRequired")
                  : t("promptInjection.promptFootnote")}
              </span>
              <span>
                {settings.prompt.length} / {PROMPT_MAX_CHARS}
              </span>
            </div>

            <Select
              label={t("promptInjection.placementLabel")}
              id="prompt-injection-placement"
              value={settings.placement}
              onValueChange={(value) =>
                patch({ placement: value === "system" ? "system" : "developer" })
              }
              options={[
                {
                  value: "developer",
                  label: t("promptInjection.placementDeveloper"),
                },
                { value: "system", label: t("promptInjection.placementSystem") },
              ]}
            />
            <p style={{ margin: "-8px 0 0", fontSize: "11px", color: "var(--text-tertiary)" }}>
              {t("promptInjection.placementHelp")}
            </p>

            <div>
              <div
                style={{
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "space-between",
                  gap: "8px",
                  flexWrap: "wrap",
                }}
              >
                <div>
                  <div style={{ fontSize: "12px", fontWeight: 700 }}>
                    {t("promptInjection.targetsLabel")}
                  </div>
                  <p
                    style={{
                      margin: "3px 0 0",
                      fontSize: "11px",
                      color: "var(--text-tertiary)",
                    }}
                  >
                    {t("promptInjection.targetsHint")}
                  </p>
                </div>
                <div style={{ display: "flex", gap: "6px", flexWrap: "wrap" }}>
                  {selectedModels.length > 0 ? (
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => patch({ targetModels: [] })}
                    >
                      {t("promptInjection.targetsClear")}
                    </Button>
                  ) : null}
                  <Button
                    variant="secondary"
                    size="sm"
                    onClick={() => setPickerOpen(true)}
                    icon={<Layers size={13} />}
                  >
                    {selectedModels.length === 0
                      ? t("promptInjection.targetsChoose")
                      : t("promptInjection.targetsEdit")}
                  </Button>
                </div>
              </div>
              <div
                style={{
                  display: "flex",
                  flexWrap: "wrap",
                  gap: "6px",
                  marginTop: "9px",
                  minHeight: "28px",
                }}
              >
                {selectedModels.length === 0 ? (
                  <Badge tone="default">{t("promptInjection.targetsAllBadge")}</Badge>
                ) : (
                  selectedModels.map((model) => (
                    <span
                      key={model}
                      style={{
                        display: "inline-flex",
                        alignItems: "center",
                        gap: "4px",
                        padding: "3px 6px 3px 8px",
                        borderRadius: "7px",
                        border: "1px solid var(--accent)",
                        background: "var(--accent-soft)",
                        color: "var(--accent)",
                        fontSize: "11px",
                        fontFamily: "var(--font-mono)",
                        maxWidth: "100%",
                      }}
                    >
                      <span
                        style={{
                          overflow: "hidden",
                          textOverflow: "ellipsis",
                          whiteSpace: "nowrap",
                        }}
                      >
                        {model}
                      </span>
                      <button
                        type="button"
                        aria-label={`Remove ${model}`}
                        onClick={() =>
                          patch({
                            targetModels: selectedModels.filter((value) => value !== model),
                          })
                        }
                        style={{
                          display: "inline-flex",
                          border: 0,
                          background: "transparent",
                          color: "inherit",
                          padding: 0,
                          cursor: "pointer",
                          flexShrink: 0,
                        }}
                      >
                        <X size={12} />
                      </button>
                    </span>
                  ))
                )}
              </div>
            </div>

            <div style={{ display: "flex", gap: "8px", flexWrap: "wrap" }}>
              <Button
                variant="primary"
                onClick={save}
                disabled={!canSave || update.isPending}
                loading={update.isPending}
                icon={<Check size={13} />}
              >
                {update.isPending ? t("promptInjection.saving") : t("promptInjection.save")}
              </Button>
              {dirty ? (
                <Button
                  variant="ghost"
                  onClick={() => setDraft(query.data ?? null)}
                  disabled={update.isPending}
                >
                  {t("promptInjection.reset")}
                </Button>
              ) : null}
              <span
                style={{
                  alignSelf: "center",
                  fontSize: "10.5px",
                  color: "var(--text-tertiary)",
                }}
              >
                {t("promptInjection.cacheHint")}
              </span>
            </div>
          </Stack>
        </CardBody>
      </Card>

      <Card>
        <CardHeader
          title={t("promptInjection.pipelineTitle")}
          subtitle={t("promptInjection.pipelineSubtitle")}
          icon={<ArrowRight size={16} />}
        />
        <CardBody>
          <div style={{ display: "flex", alignItems: "stretch", gap: "8px", flexWrap: "wrap" }}>
            {pipeline.map((stage, index) => (
              <div
                key={stage.titleKey}
                style={{ display: "flex", alignItems: "center", gap: "8px", flex: "1 1 190px" }}
              >
                <div
                  style={{
                    flex: 1,
                    minWidth: 0,
                    border: "1px solid var(--inner-border)",
                    borderRadius: "10px",
                    padding: "11px 12px",
                    background: index === 1 ? "var(--surface-2)" : "var(--surface-1)",
                  }}
                >
                  <div
                    style={{
                      fontSize: "9.5px",
                      fontWeight: 700,
                      letterSpacing: "0.08em",
                      color: index === 1 ? "var(--accent)" : "var(--text-tertiary)",
                    }}
                  >
                    {String(index + 1).padStart(2, "0")}
                  </div>
                  <div style={{ marginTop: "3px", fontSize: "12.5px", fontWeight: 600 }}>
                    {t(stage.titleKey)}
                  </div>
                  <p
                    style={{
                      marginTop: "4px",
                      marginBottom: 0,
                      fontSize: "11px",
                      lineHeight: 1.45,
                      color: "var(--text-tertiary)",
                    }}
                  >
                    {t(stage.bodyKey)}
                  </p>
                </div>
                {index < pipeline.length - 1 ? (
                  <ArrowRight
                    size={14}
                    aria-hidden="true"
                    style={{ color: "var(--text-tertiary)", flexShrink: 0 }}
                  />
                ) : null}
              </div>
            ))}
          </div>
        </CardBody>
      </Card>

      <Card>
        <CardHeader
          title={t("promptInjection.previewTitle")}
          subtitle={t("promptInjection.previewSubtitle")}
          icon={<Layers size={16} />}
        />
        <CardBody>
          <div
            style={{
              border: "1px solid var(--inner-border)",
              borderRadius: "9px",
              background: "var(--surface-1)",
              padding: "11px 12px",
              fontFamily: "var(--font-mono)",
              fontSize: "11.5px",
              lineHeight: 1.55,
              whiteSpace: "pre-wrap",
              overflowWrap: "anywhere",
              color: settings.prompt.trim() ? "var(--text-secondary)" : "var(--text-tertiary)",
              minHeight: "58px",
            }}
          >
            {settings.prompt.trim() || t("promptInjection.previewEmpty")}
          </div>
          <p style={{ margin: "8px 0 0", fontSize: "10.5px", color: "var(--text-tertiary)" }}>
            {settings.placement === "system"
              ? t("promptInjection.previewSystem")
              : t("promptInjection.previewDeveloper")}
          </p>
        </CardBody>
      </Card>

      <Card>
        <CardHeader
          title={t("promptInjection.boundaryTitle")}
          subtitle={t("promptInjection.boundarySubtitle")}
          icon={<AlertTriangle size={16} />}
        />
        <CardBody>
          <p style={{ margin: 0, fontSize: "12px", lineHeight: 1.55, color: "var(--text-secondary)" }}>
            {t("promptInjection.boundaryBody")}
          </p>
        </CardBody>
      </Card>

      <ModelPickerModal
        open={pickerOpen}
        onClose={() => setPickerOpen(false)}
        selected={[...selectedModels]}
        onToggle={(value) =>
          patch({
            targetModels: selectedModels.includes(value)
              ? selectedModels.filter((model) => model !== value)
              : [...selectedModels, value],
          })
        }
        title={t("promptInjection.targetsPickerTitle")}
        filter={(entry) =>
          entry.kind === "model" &&
          entry.entry.serviceKind === "llm" &&
          entry.entry.enabled !== false
        }
      />
    </div>
  );
}

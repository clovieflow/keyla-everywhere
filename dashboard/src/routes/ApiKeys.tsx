/**
 * API Keys route.
 *
 * The panel itself is the canonical owner of key CRUD, one-time secret
 * display, share links, rotation and revocation — it has been reachable from
 * Overview but had no navigation entry of its own, which made "where do I
 * create a key" a search problem. This route gives the existing, tested panel
 * a real address instead of reimplementing any of it.
 */
import { type ReactNode } from "react";
import { ApiKeysPanel } from "../components/ApiKeysPanel";
import { PageHead } from "../components/PageHead";
import { useT } from "../shared/locale-context";
import { useApiKeys } from "../hooks/api-keys";

export default function ApiKeys(): ReactNode {
  const t = useT();
  const keysQuery = useApiKeys();
  const keys = keysQuery.data ?? [];
  const active = keys.filter((key) => key.isActive !== false).length;
  return (
    <div className="dashboard-page">
      <PageHead
        eyebrow="System / Access surface"
        title={"Access\nkeys."}
        description={t("models.aliasSectionHint")}
        stats={[
          { label: "Keys", value: String(keys.length), meta: "Issued to this tenant" },
          { label: "Active", value: String(active), meta: "Currently accepted" },
          { label: "Bansos", value: String(keys.filter((key) => key.bansosEnabled === true).length), meta: "Published for subsidized access" },
        ]}
      />
      <ApiKeysPanel />
    </div>
  );
}

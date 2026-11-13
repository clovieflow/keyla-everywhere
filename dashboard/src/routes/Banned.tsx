import type { ReactNode } from "react";
import { Button } from "../components/ui/button";
import { useT } from "../shared/locale-context";

/**
 * Security lockout surface (HTTP 403).
 *
 * Reached when the gateway refuses this client's address. The page states the
 * cause and the one action that helps — waiting, then reloading — because the
 * tempting alternative (keep retrying the password) is what extends the
 * lockout.
 */
export default function Banned(): ReactNode {
  const t = useT();
  return (
    <main className="auth-viewport">
      <div className="card-solid auth-window ke-auth-card" style={{ border: "1px solid #4a2722" }}>
        <div className="auth-header">
          <div className="ke-auth-kicker">BOUNDARY / 403</div>
          <h1 className="auth-title">{t("banned.title")}</h1>
          <p className="auth-desc">{t("banned.desc")}</p>
        </div>

        <div
          style={{
            display: "flex",
            flexDirection: "column",
            gap: 10,
            padding: "14px",
            borderRadius: "12px",
            background: "var(--surface-2)",
            border: "1px solid var(--inner-border)",
            fontSize: "12.5px",
            color: "var(--text-secondary)",
            lineHeight: 1.55,
          }}
          role="alert"
        >
          <div>
            <strong style={{ display: "block", color: "var(--text-primary)", marginBottom: "4px" }}>
              HTTP 403 Forbidden
            </strong>
            {t("banned.body")}
          </div>
          <div style={{ color: "var(--orange)" }}>{t("banned.retryHint")}</div>
        </div>

        <Button
          variant="secondary"
          style={{ width: "100%", marginTop: 14, height: 40 }}
          onClick={() => window.location.reload()}
        >
          {t("banned.reload")}
        </Button>
      </div>
    </main>
  );
}

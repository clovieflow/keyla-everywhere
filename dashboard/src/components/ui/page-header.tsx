import { ArrowLeft } from "lucide-react";
import type { ReactNode } from "react";
import { Link } from "react-router-dom";

export interface BackLinkProps {
  readonly to: string;
  readonly label: string;
}

/** Consistent detail-page back link. */
export function BackLink({ to, label }: BackLinkProps): ReactNode {
  return (
    <Link
      to={to}
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: "6px",
        color: "var(--accent)",
        fontSize: "12px",
        textDecoration: "none",
      }}
    >
      <ArrowLeft size={14} aria-hidden="true" />
      {label}
    </Link>
  );
}

export interface PageHeaderProps {
  readonly title: string;
  readonly description?: string;
  readonly icon?: ReactNode;
  readonly badges?: ReactNode;
  readonly actions?: ReactNode;
  readonly back?: BackLinkProps;
}

/** Detail-page identity header with optional navigation and actions. */
export function PageHeader({
  title,
  description,
  icon,
  badges,
  actions,
  back,
}: PageHeaderProps): ReactNode {
  return (
    <section className="ed-detail-head">
      {back ? <BackLink {...back} /> : null}
      <div className="ed-detail-head__row">
        <div className="ed-detail-head__copy">
          {icon ? <div className="ed-detail-head__icon">{icon}</div> : null}
          <div style={{ minWidth: 0 }}>
            <div className="ed-detail-head__badges">{badges}</div>
            <h1 className="ed-detail-head__title">{title}</h1>
            {description ? <p className="ed-detail-head__description">{description}</p> : null}
          </div>
        </div>
        {actions ? <div className="ed-detail-head__actions">{actions}</div> : null}
      </div>
    </section>
  );
}

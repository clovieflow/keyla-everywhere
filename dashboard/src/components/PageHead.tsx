/**
 * Page hero.
 *
 * The shell's topbar names the route in small type; this surface owns the
 * editorial statement and the page-local actions/figures. The art vignettes
 * are intentionally gone: the console's visual identity is now type, rules and
 * data, not a repeated anime illustration.
 */
import { useId, type CSSProperties, type ReactNode } from "react";

export interface PageStat {
  readonly label: string;
  readonly value: string;
  readonly meta?: string;
}

export interface PageHeadProps {
  /** Display title. A newline makes the following line outlined. */
  readonly title?: string;
  readonly description?: string;
  /** Optional leading element, rendered above the title (eyebrow, badge row). */
  readonly eyebrow?: ReactNode;
  /** Legacy illustration key; accepted for call-site compatibility, not rendered. */
  readonly art?: string;
  /** Trailing controls, right-aligned on wide viewports. */
  readonly actions?: ReactNode;
  readonly level?: 1 | 2;
  /** Optional figures rendered as a ruled strip beneath the hero. */
  readonly stats?: readonly PageStat[];
}

function splitTitle(title: string): readonly string[] {
  return title
    .split(/\n|<br\s*\/?>/i)
    .map((line) => line.trim())
    .filter(Boolean);
}

export function PageHead({
  title,
  description,
  eyebrow,
  actions,
  stats,
}: PageHeadProps): ReactNode {
  const id = useId();
  const lines = title ? splitTitle(title) : [];
  if (lines.length === 0 && description === undefined && actions === undefined && !stats?.length) {
    return null;
  }

  return (
    <section className="page-head ed-hero" aria-labelledby={lines.length > 0 ? id : undefined}>
      <div className="ed-hero__top">
        <div className="ed-hero__copy">
          <div className="ed-hero__eyebrow">
            {eyebrow ?? "Keyla / operator console"}
          </div>
          {lines.length > 0 ? (
            <h2 className="ed-hero__title" id={id}>
              {lines.map((line, index) => (
                <span
                  key={`${line}-${index}`}
                  className={
                    index === 0
                      ? "ed-hero__title-line"
                      : "ed-hero__title-line ed-hero__title-line--outline"
                  }
                >
                  {line}
                </span>
              ))}
            </h2>
          ) : null}
          {description ? <p className="ed-hero__description">{description}</p> : null}
        </div>
        {actions ? <div className="ed-hero__actions">{actions}</div> : null}
      </div>

      {stats && stats.length > 0 ? (
        <div
          className="ed-hero__stats"
          style={{ "--stat-cols": stats.length } as CSSProperties}
        >
          {stats.map((stat) => (
            <div className="ed-stat" key={stat.label}>
              <div className="ed-stat__label">{stat.label}</div>
              <div className="ed-stat__value">{stat.value}</div>
              {stat.meta ? <div className="ed-stat__meta">{stat.meta}</div> : null}
            </div>
          ))}
        </div>
      ) : null}
    </section>
  );
}

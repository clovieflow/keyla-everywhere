/**
 * The Ringkasan hero.
 *
 * A type-led statement instead of a photographic banner: the operator's first
 * question is "what is happening", and a 100px sentence answers it faster than
 * art. The surrounding data strip supplies the evidence.
 */
import type { ReactNode } from "react";
import { useT } from "../../shared/locale-context";

export function OverviewHero(): ReactNode {
  const t = useT();
  const display = t("overview.hero.display" as never).split("\n");

  return (
    <section className="cl-hero" aria-labelledby="cl-hero-title">
      <div className="cl-hero__copy">
        <p className="cl-hero__eyebrow">{t("overview.hero.eyebrow" as never)}</p>
        <h2 className="cl-hero__title" id="cl-hero-title">
          {display[0]}
          {display[1] ? <em>{display[1]}</em> : null}
        </h2>
        <p className="cl-hero__lede">{t("overview.hero.lede" as never)}</p>
      </div>
    </section>
  );
}

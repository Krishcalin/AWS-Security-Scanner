/**
 * cap.ts — a rendered list must say when it is not the whole list.
 *
 * WHY THIS EXISTS
 * ---------------
 * The backend now declares every truncation it performs: `capped()` in
 * cnapp_service emits `<field>`, `<field>_total` and `<field>_truncated`, and an
 * AST ratchet fails the build when a new undeclared cap appears.
 *
 * The console had the same defect and the ratchet could not see it. A row showed
 * three compliance frameworks of seven, the Overview showed five attack paths of
 * however many, and the exported HTML report showed "top 25" findings with no
 * hint that a twenty-sixth existed. A report is the worst case: it leaves the
 * building and is read as complete by someone who cannot go and check.
 *
 * THE RULE
 * --------
 * If a list is cut, say so, next to the list. Not in a tooltip, not inferable by
 * comparing two numbers — visible where the truncation happened.
 *
 * `capNote` returns null when nothing was dropped, so the caller renders nothing
 * in the common case and cannot accidentally print "+0 more".
 */

/** The label for a truncated list, or null when the list is complete. */
export function capNote(shown: number, total: number): string | null {
  const hidden = Math.max(0, Math.floor(total) - Math.floor(shown))
  return hidden > 0 ? `+${hidden} more` : null
}

/**
 * "5 of 47" for a heading, or "5" when that is all there is.
 *
 * Used where the count is the headline rather than an aside — a panel title, a
 * report table caption. Deliberately not "5/47": a slash reads as a fraction or
 * a date, and this is neither.
 */
export function ofTotal(shown: number, total: number): string {
  const s = Math.floor(shown)
  const t = Math.floor(total)
  return t > s ? `${s} of ${t}` : `${s}`
}

/**
 * Cut a list and report what the cut cost, in one call.
 *
 * Mirrors the shape the backend emits so a component reads the same three facts
 * whether the cap happened server-side (`*_total` / `*_truncated` on the wire) or
 * here in the browser.
 */
export function cap<T>(items: readonly T[] | null | undefined, limit: number): {
  shown: T[]
  total: number
  truncated: boolean
  note: string | null
} {
  const all = items ?? []
  const shown = all.slice(0, limit)
  return {
    shown,
    total: all.length,
    truncated: all.length > limit,
    note: capNote(shown.length, all.length),
  }
}

/**
 * The note for a list the SERVER already cut.
 *
 * `total` is the wire's `<field>_total`. When it is absent — an older hub, or an
 * endpoint that does not declare — this returns null rather than guessing, because
 * inventing "+0 more" would assert completeness nobody established. The absence of
 * a declaration is not evidence that nothing was dropped.
 */
export function serverCapNote(shown: number, total: number | undefined | null): string | null {
  return typeof total === 'number' ? capNote(shown, total) : null
}

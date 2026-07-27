// Pure helpers for the MTTR tile + issue burn-down chart (DriftCard). No React/DOM so the
// node-env vitest can exercise them. MTTR seconds come from aws_state.mttr (GET .../mttr).

/** Humanize a remediation duration in seconds → "3.2d" / "18h" / "45m" / "—" (null). */
export function formatDuration(seconds: number | null | undefined): string {
  if (seconds == null || !isFinite(seconds)) return '—'
  const d = seconds / 86400
  if (d >= 1) return `${d >= 10 ? Math.round(d) : d.toFixed(1)}d`
  const h = seconds / 3600
  if (h >= 1) return `${Math.round(h)}h`
  return `${Math.max(1, Math.round(seconds / 60))}m`
}

/** Normalize a numeric series to [0,1] over its own min..max (flat series → all 0.5). */
export function normalizeSeries(values: number[]): number[] {
  if (values.length === 0) return []
  const min = Math.min(...values)
  const max = Math.max(...values)
  if (max === min) return values.map(() => 0.5)
  return values.map((v) => (v - min) / (max - min))
}

/** Burn-down trend direction over the open-issue backlog: down = improving. */
export function burndownTrend(open: number[]): 'down' | 'up' | 'flat' {
  if (open.length < 2) return 'flat'
  const d = open[open.length - 1] - open[0]
  return d < 0 ? 'down' : d > 0 ? 'up' : 'flat'
}

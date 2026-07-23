// Client-side port of aws_live_scanner.crosswalk_scorecard — used ONLY in sample
// mode so the offline console derives the same 30+ framework scorecards the backend
// would, from a native scorecard + the bundled crosswalk.json. Live mode uses the
// API's derived block instead. Keep in lockstep with the Python fold.
import type { ComplianceScorecard, CrosswalkData, ComplianceFramework } from '../api/types'

const RANK: Record<string, number> = { low: 0, medium: 1, high: 2 }

function minPresent(mix: { high: number; medium: number; low: number }): 'high' | 'medium' | 'low' {
  if (mix.low > 0) return 'low'
  if (mix.medium > 0) return 'medium'
  return 'high'
}

// Match Python's round(x, 1) (round-half-to-even) so the offline sample fold produces
// byte-identical pass_rate to the live backend at exact .05 boundaries.
export function round1(x: number): number {
  const y = x * 10
  const f = Math.floor(y)
  const d = y - f
  const r = d > 0.5 ? f + 1 : d < 0.5 ? f : (f % 2 === 0 ? f : f + 1)
  return r / 10
}

export function deriveCrosswalk(native: ComplianceScorecard, cw: CrosswalkData,
  minConfidence?: string | null): ComplianceScorecard {
  const floor = minConfidence ? (RANK[minConfidence] ?? 0) : 0
  const failedNist = new Set(native['NIST']?.failed_controls ?? [])
  const out: ComplianceScorecard = {}
  for (const meta of cw.frameworks) {
    if (meta.native) continue
    const universe = new Set<string>()
    const failed = new Set<string>()
    const prov: Record<string, { control: string; via_nist: string[]; confidence: string; note: string; sources: string[] }> = {}
    // sort by NIST id (code-point) to match the Python fold's `for n in sorted(nist_all)`
    const nistSorted = Object.keys(cw.crosswalk).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0))
    for (const nist of nistSorted) {
      const fwmap = cw.crosswalk[nist]
      const edge = fwmap[meta.id]
      if (!edge) continue
      if ((RANK[edge.confidence] ?? 0) < floor) continue
      for (const t of edge.targets) {
        universe.add(t)
        const p = (prov[t] ??= { control: t, via_nist: [], confidence: 'low', note: edge.note, sources: meta.sources })
        p.via_nist.push(nist)
        if ((RANK[edge.confidence] ?? 0) > (RANK[p.confidence] ?? 0)) p.confidence = edge.confidence
        if (failedNist.has(nist)) failed.add(t)
      }
    }
    if (universe.size === 0) continue
    const failedIn = [...failed].filter((t) => universe.has(t)).sort()
    const total = universe.size
    const mix = { high: 0, medium: 0, low: 0 }
    for (const t of universe) mix[prov[t].confidence as 'high' | 'medium' | 'low']++
    const passed = total - failedIn.length
    const card: ComplianceFramework = {
      controls_total: total, controls_passed: passed, controls_failed: failedIn.length,
      pass_rate: total ? round1((100 * passed) / total) : 100,
      failed_controls: failedIn, derived: true, via: 'NIST-800-53',
      confidence_mix: mix, min_confidence: minPresent(mix),
      control_provenance: Object.fromEntries(failedIn.map((t) => [t,
        { ...prov[t], via_nist: [...new Set(prov[t].via_nist)].sort() }])),
    }
    out[meta.id] = card
  }
  return out
}

// Client-side blast radius over a persisted graph — the exact mirror of
// cnapp_service.get_blast_radius, so SAMPLE mode (BFS over the account_*_graph.json
// fixture) matches the live hub byte-for-byte. Pure + testable (no React, no DOM).
import type { GraphFull, GNode, BlastRow, BlastRadius } from '../api/types'

// mirror aws_correlate.E_PATH — the traversable attack-edge universe (annotations
// like HAS_VULN / RUNS_IMAGE / THREAT_ON are deliberately excluded).
export const E_PATH = new Set([
  'EXPOSED_TO', 'ATTACHED_TO', 'HAS_INSTANCE_PROFILE', 'HAS_ROLE',
  'CAN_ASSUME', 'CAN_PRIVESC_TO', 'CAN_READ_DATA', 'TARGETS',
])

// mirror cnapp_service._seg: rsplit('/') then rsplit(':')
export function seg(id: string): string {
  const a = id.split('/').pop() ?? id
  return a.split(':').pop() ?? a
}

// Code-point id comparison — must match Python's raw-string tie-break (str < str), NOT
// localeCompare (which folds case + variable-weights punctuation), so SAMPLE and LIVE order
// identical graphs identically. e.g. "…/Zeus" sorts before "…/apollo" (Z=0x5A < a=0x61).
export function cmpId(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0
}

/** Bounded BFS returning {id: shortest path}; `prepend` builds the reverse (source..start) order. */
function bfs(
  adj: Map<string, string[]>, start: string, maxHops: number, prepend: boolean,
): Map<string, string[]> {
  const seen = new Set([start])
  const out = new Map<string, string[]>()
  const q: [string, string[]][] = [[start, [start]]]
  while (q.length) {
    const [cur, path] = q.shift()!
    if (path.length - 1 >= maxHops) continue
    for (const nxt of adj.get(cur) ?? []) {
      if (seen.has(nxt)) continue
      seen.add(nxt)
      const npath = prepend ? [nxt, ...path] : [...path, nxt]
      out.set(nxt, npath)
      q.push([nxt, npath])
    }
  }
  return out
}

export function computeBlastRadius(graph: GraphFull, node: string, maxHops = 8): BlastRadius {
  const hops = Math.max(1, Math.min(Math.trunc(maxHops || 8), 12))
  const byId = new Map<string, GNode>(graph.nodes.map((n) => [n.id, n]))
  const out = new Map<string, string[]>()
  const inn = new Map<string, string[]>()
  const push = (m: Map<string, string[]>, k: string, v: string) => {
    const cur = m.get(k)
    if (cur) cur.push(v)
    else m.set(k, [v])
  }
  for (const e of graph.edges) {
    if (!E_PATH.has(e.kind)) continue
    push(out, e.source, e.target)
    push(inn, e.target, e.source)
  }

  const row = (id: string, path: string[], terminal: BlastRow['terminal'] = null): BlastRow => {
    const n = byId.get(id)
    return { id, kind: n?.kind ?? 'Unknown', label: (n?.name as string) || seg(id), path, terminal }
  }

  if (!byId.has(node)) {
    return { node, exists: false, kind: null, label: seg(node), reaches: [], reached_by: [],
      internet_reachable: false, max_hops: hops, counts: { crowns: 0, admins: 0, sources: 0 } }
  }

  const fwd = bfs(out, node, hops, false)
  const rev = bfs(inn, node, hops, true)
  const crowns = new Set(graph.nodes.filter((n) => n.crown_jewel).map((n) => n.id))
  const admins = new Set(graph.nodes.filter((n) => n.kind === 'AdminCapability').map((n) => n.id))

  const reaches: BlastRow[] = []
  for (const [id, path] of fwd) {
    const terminal: BlastRow['terminal'] = crowns.has(id) ? 'data' : admins.has(id) ? 'admin' : null
    if (terminal) reaches.push(row(id, path, terminal))
  }
  reaches.sort((a, b) =>
    Number(a.terminal !== 'data') - Number(b.terminal !== 'data') || a.path.length - b.path.length || cmpId(a.id, b.id))

  const reached_by: BlastRow[] = [...rev].map(([id, path]) => row(id, path))
  reached_by.sort((a, b) => a.path.length - b.path.length || cmpId(a.id, b.id))
  const internet_reachable = [...rev.keys()].some((id) => byId.get(id)?.kind === 'InternetSource')

  const n = byId.get(node)!
  return {
    node, exists: true, kind: n.kind, label: (n.name as string) || seg(node),
    reaches, reached_by, internet_reachable, max_hops: hops,
    counts: {
      crowns: reaches.filter((r) => r.terminal === 'data').length,
      admins: reaches.filter((r) => r.terminal === 'admin').length,
      sources: reached_by.length,
    },
  }
}

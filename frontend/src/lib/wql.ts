// wql.ts — the byte-for-byte TS mirror of aws_wql.py, so SAMPLE mode (querying the graph
// fixture client-side) returns exactly what the LIVE hub would. Reuses blast.ts's E_PATH /
// seg / cmpId (the parity primitives) and projects.ts's globMatch (fnmatchcase). Guarded by a
// shared cross-language fixture (wql.test.ts) — any drift from aws_wql.py reddens CI.
import type { GraphFull, GNode } from '../api/types'
import { E_PATH, seg, cmpId } from './blast'
import { globMatch } from './projects'

export const WQL_MAX_HOPS = 12
export const WQL_DEFAULT_LIMIT = 500
export const WQL_MAX_LIMIT = 5000
export const WQL_MAX_DEPTH = 32          // predicate-tree nesting cap (mirror aws_wql)
export const WQL_MAX_PREDS = 128         // total predicate count cap (mirror aws_wql)

const BOOL_OPS = new Set(['and', 'or', 'not'])
const LEAF_PREDS = new Set(['kind', 'has_prop', 'prop', 'prop_glob', 'has_edge', 'reachable_from', 'reaches', 'crown_jewel'])
const CMP_OPS = new Set(['eq', 'neq', 'in', 'gt', 'gte', 'lt', 'lte', 'exists', 'contains'])
const TOP_KEYS = new Set(['select', 'kind', 'kind_in', 'where', 'limit', 'max_hops'])
const WHERE_PROPS = new Set([
  'crown_jewel', 'DataStore', 'public', 'encrypted', 'sensitivity', 'name', 'account', 'external',
  'cidr', 'runtime_monitored', 'severity', 'kev', 'epss', 'exploit_available', 'cve',
  'reachable_service', 'conditioned', 'verified', 'scan_source', 'digest', 'region',
  'data_types', 'sensitivity_tier', 'classifier',       // DSPM read-time enrichment (aws_dspm)
])

export class WQLError extends Error {}

export interface WqlRow { id: string; kind: string; label: string; props: Record<string, unknown> }
export interface WqlResult { count: number; nodes: WqlRow[] }
type Pred = Record<string, unknown>
export interface WqlQuery { select: 'node'; kind: string | null; kind_in: string[] | null; where: Pred | null; limit: number; max_hops: number }

const isInt = (v: unknown): v is number => typeof v === 'number' && Number.isInteger(v)
// mirror Python dict.get(k, default): default ONLY when the key is ABSENT — an explicit null
// is kept (and then fails the type/enum check), so SAMPLE rejects exactly what LIVE rejects.
const own = (o: Record<string, unknown>, k: string): boolean => Object.prototype.hasOwnProperty.call(o, k)

// ── parse (typecheck + normalize; the security boundary) ──────────────────────
export function parse(obj: unknown): WqlQuery {
  if (obj === null || typeof obj !== 'object' || Array.isArray(obj)) throw new WQLError('query must be an object')
  const o = obj as Record<string, unknown>
  for (const k of Object.keys(o)) if (!TOP_KEYS.has(k)) throw new WQLError(`unknown query field: ${k}`)
  if ((own(o, 'select') ? o.select : 'node') !== 'node') throw new WQLError("select must be 'node' (v1)")
  const kind = o.kind
  if (kind != null && typeof kind !== 'string') throw new WQLError('kind must be a string')
  const kindIn = o.kind_in
  if (kindIn != null && !(Array.isArray(kindIn) && kindIn.every((k) => typeof k === 'string'))) throw new WQLError('kind_in must be a list of strings')
  const where = o.where != null ? parsePred(o.where, 0, { n: 0 }) : null
  const lim = own(o, 'limit') ? o.limit : WQL_DEFAULT_LIMIT
  if (!isInt(lim) || lim <= 0) throw new WQLError('limit must be a positive integer')
  const mh = own(o, 'max_hops') ? o.max_hops : WQL_MAX_HOPS
  if (!isInt(mh) || mh <= 0) throw new WQLError('max_hops must be a positive integer')
  return {
    select: 'node', kind: (kind as string) ?? null, kind_in: (kindIn as string[]) ?? null,
    where, limit: Math.min(lim, WQL_MAX_LIMIT), max_hops: Math.min(mh, WQL_MAX_HOPS),
  }
}

function parsePred(p: unknown, depth = 0, counter = { n: 0 }): Pred {
  if (depth > WQL_MAX_DEPTH) throw new WQLError(`predicate nesting exceeds ${WQL_MAX_DEPTH}`)
  if (++counter.n > WQL_MAX_PREDS) throw new WQLError(`query has more than ${WQL_MAX_PREDS} predicates`)
  if (p === null || typeof p !== 'object' || Array.isArray(p)) throw new WQLError('predicate must be an object')
  const o = p as Record<string, unknown>
  const op = o.op
  if (typeof op === 'string' && BOOL_OPS.has(op)) {
    const of = o.of
    if (!Array.isArray(of) || of.length === 0) throw new WQLError(`boolean '${op}' needs a non-empty 'of' list`)
    if (op === 'not' && of.length !== 1) throw new WQLError("'not' takes exactly one child predicate")
    return { op, of: of.map((c) => parsePred(c, depth + 1, counter)) }
  }
  const pred = o.pred
  if (typeof pred !== 'string' || !LEAF_PREDS.has(pred)) throw new WQLError(`unknown predicate: ${String(pred)}`)
  if (pred === 'kind') {
    const kop = own(o, 'op') ? o.op : 'eq'
    if (kop !== 'eq' && kop !== 'in') throw new WQLError('kind pred op must be eq|in')
    if (kop === 'eq' && typeof o.value !== 'string') throw new WQLError('kind eq needs a string value')
    if (kop === 'in' && !(Array.isArray(o.value) && o.value.every((v) => typeof v === 'string'))) throw new WQLError('kind in needs a list of strings')
    return { pred: 'kind', op: kop, value: o.value }
  }
  if (pred === 'has_prop' || pred === 'prop' || pred === 'prop_glob') {
    const field = o.field
    if (typeof field !== 'string' || !WHERE_PROPS.has(field)) throw new WQLError(`prop ${String(field)} not queryable`)
    if (pred === 'prop') {
      const pop = o.op
      if (typeof pop !== 'string' || !CMP_OPS.has(pop)) throw new WQLError('invalid prop op')
      if (pop === 'in' && !Array.isArray(o.value)) throw new WQLError("prop 'in' needs a list value")
      return { pred: 'prop', field, op: pop, value: o.value }
    }
    if (pred === 'prop_glob') {
      if (typeof o.value !== 'string') throw new WQLError('prop_glob needs a string pattern')
      return { pred: 'prop_glob', field, value: o.value }
    }
    return { pred: 'has_prop', field, value: o.value }
  }
  if (pred === 'has_edge') {
    if (typeof o.kind !== 'string') throw new WQLError("has_edge needs a string 'kind'")
    const d = own(o, 'dir') ? o.dir : 'out'
    if (d !== 'out' && d !== 'in') throw new WQLError('has_edge dir must be out|in')
    return { pred: 'has_edge', kind: o.kind, dir: d }
  }
  if (pred === 'reachable_from') {
    if (o.target !== 'internet') throw new WQLError("reachable_from target must be 'internet' (v1)")
    return { pred: 'reachable_from', target: 'internet' }
  }
  if (pred === 'reaches') {
    if (o.target !== 'crown' && o.target !== 'admin') throw new WQLError('reaches target must be crown|admin')
    return { pred: 'reaches', target: o.target }
  }
  return { pred: 'crown_jewel' }
}

// ── evaluate ──────────────────────────────────────────────────────────────────
// GraphFull flattens props onto the node ({id,kind,...props}); edges are {source,target,kind,...props}.

// mirror of aws_graph.reachable / reverse_reachable UNIONED over `starts`, exactly as _Ctx does:
// each start runs its OWN bounded BFS that excludes only that start, and the reached ids are
// unioned. So a start reachable from ANOTHER start within maxHops IS included (matching Python's
// ∪ reachable(A)); a lone start is not. Level-capped at maxHops edges (nodes at exactly maxHops
// are reached but not expanded), matching `len(path)-1 >= max_hops`.
function unionReach(adj: Map<string, string[]>, starts: Iterable<string>, maxHops: number): Set<string> {
  const acc = new Set<string>()
  for (const start of starts) {
    const seen = new Set([start])
    let frontier: string[] = [start]
    for (let hop = 0; hop < maxHops && frontier.length; hop++) {
      const next: string[] = []
      for (const cur of frontier) for (const nxt of adj.get(cur) ?? []) {
        if (!seen.has(nxt)) { seen.add(nxt); next.push(nxt); acc.add(nxt) }
      }
      frontier = next
    }
  }
  return acc
}

class Ctx {
  private out = new Map<string, string[]>()      // E_PATH forward adjacency
  private inn = new Map<string, string[]>()       // E_PATH reverse adjacency
  private outEdge = new Set<string>()             // `${source}|${kind}` over ALL edges
  private inEdge = new Set<string>()              // `${target}|${kind}` over ALL edges
  private _exposed?: Set<string>
  private _rc?: Set<string>
  private _ra?: Set<string>
  private _crowns?: Set<string>
  private g: GraphFull
  private maxHops: number
  constructor(g: GraphFull, maxHops: number) {
    this.g = g
    this.maxHops = maxHops
    const push = (m: Map<string, string[]>, k: string, v: string) => {
      const cur = m.get(k)
      if (cur) cur.push(v)
      else m.set(k, [v])
    }
    for (const e of g.edges) {
      this.outEdge.add(`${e.source}|${e.kind}`)
      this.inEdge.add(`${e.target}|${e.kind}`)
      if (E_PATH.has(e.kind)) { push(this.out, e.source, e.target); push(this.inn, e.target, e.source) }
    }
  }
  // mirror aws_correlate.crown_nodes: node ids whose crown_jewel prop is truthy.
  crowns(): Set<string> {
    if (!this._crowns) this._crowns = new Set(this.g.nodes.filter((n) => n.crown_jewel).map((n) => n.id))
    return this._crowns
  }
  exposed(): Set<string> {
    if (!this._exposed) this._exposed = unionReach(this.out, this.g.nodes.filter((n) => n.kind === 'InternetSource').map((n) => n.id), this.maxHops)
    return this._exposed
  }
  reachesCrown(): Set<string> {
    if (!this._rc) this._rc = unionReach(this.inn, this.crowns(), this.maxHops)
    return this._rc
  }
  reachesAdmin(): Set<string> {
    if (!this._ra) this._ra = unionReach(this.inn, this.g.nodes.filter((n) => n.kind === 'AdminCapability').map((n) => n.id), this.maxHops)
    return this._ra
  }
  hasOutEdge(id: string, kind: string): boolean { return this.outEdge.has(`${id}|${kind}`) }
  hasInEdge(id: string, kind: string): boolean { return this.inEdge.has(`${id}|${kind}`) }
}

// mirror aws_wql._num == Python float(): bool→0/1, ''→None, non-numeric string/null/obj→None.
const asNum = (x: unknown): number | null => {
  if (typeof x === 'number') return Number.isFinite(x) ? x : null
  if (typeof x === 'boolean') return x ? 1 : 0
  if (typeof x === 'string') {
    if (x.trim() === '') return null
    const n = Number(x)
    return Number.isFinite(n) ? n : null
  }
  return null
}

function cmp(actual: unknown, op: string, value: unknown, present: boolean): boolean {
  if (op === 'exists') return present
  if (!present) return op === 'neq'
  if (op === 'eq') return actual === value
  if (op === 'neq') return actual !== value
  if (op === 'in') return Array.isArray(value) && value.includes(actual)
  if (op === 'contains') { try { return typeof actual === 'string' && typeof value === 'string' ? actual.includes(value) : Array.isArray(actual) && actual.includes(value) } catch { return false } }
  const a = asNum(actual), b = asNum(value)
  if (a === null || b === null) return false
  return op === 'gt' ? a > b : op === 'gte' ? a >= b : op === 'lt' ? a < b : a <= b
}

function evalPred(pred: Pred, node: GNode, ctx: Ctx): boolean {
  const op = pred.op as string | undefined
  if (op && BOOL_OPS.has(op)) {
    const of = pred.of as Pred[]
    if (op === 'and') return of.every((c) => evalPred(c, node, ctx))
    if (op === 'or') return of.some((c) => evalPred(c, node, ctx))
    return !evalPred(of[0], node, ctx)
  }
  const p = pred.pred as string
  if (p === 'kind') return pred.op === 'eq' ? node.kind === pred.value : (pred.value as string[]).includes(node.kind)
  if (p === 'has_prop') {
    const field = pred.field as string
    return pred.value != null ? node[field] === pred.value : !!node[field]
  }
  if (p === 'prop') {
    const field = pred.field as string
    return cmp(node[field], pred.op as string, pred.value, field in node)
  }
  // mirror aws_state._glob: an empty pattern means "*" (match-all).
  if (p === 'prop_glob') return globMatch((pred.value as string) || '*', String(node[pred.field as string] ?? ''))
  if (p === 'has_edge') return pred.dir === 'out' ? ctx.hasOutEdge(node.id, pred.kind as string) : ctx.hasInEdge(node.id, pred.kind as string)
  if (p === 'reachable_from') return ctx.exposed().has(node.id)
  if (p === 'reaches') return (pred.target === 'crown' ? ctx.reachesCrown() : ctx.reachesAdmin()).has(node.id)
  return !!node.crown_jewel || ctx.crowns().has(node.id)   // crown_jewel
}

function row(node: GNode): WqlRow {
  const { id, kind, ...props } = node
  return { id, kind, label: (node.name as string) || seg(id), props }
}

export function evaluate(obj: unknown, graph: GraphFull): WqlResult {
  const q = parse(obj)
  let candidates: GNode[]
  if (q.kind != null) candidates = graph.nodes.filter((n) => n.kind === q.kind)
  else if (q.kind_in != null) { const ks = new Set(q.kind_in); candidates = graph.nodes.filter((n) => ks.has(n.kind)) }
  else candidates = graph.nodes
  const ctx = new Ctx(graph, q.max_hops)
  const matched = candidates.filter((n) => q.where === null || evalPred(q.where, n, ctx))
  matched.sort((a, b) => cmpId(a.kind, b.kind) || cmpId(a.id, b.id))
  return { count: Math.min(matched.length, q.limit), nodes: matched.slice(0, q.limit).map(row) }
}

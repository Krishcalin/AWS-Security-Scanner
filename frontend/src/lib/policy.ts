// policy.ts — the byte-for-byte TS mirror of aws_policy.py, so a policy-as-code rule produces the
// same POLICY-xx WARN finding + rollup in SAMPLE mode as the live hub. Reuses the parity-proven
// wql.ts engine for the graph clause and projects.ts globMatch for the check_id glob. Guarded by
// the shared cross-language fixture (policy.test.ts).
import type { GraphFull, FindingCatalogEntry } from '../api/types'
import { evaluate as evalWql } from './wql'
import { globMatch } from './projects'

export const POLICY_SECTION = 'Policy'
export const POLICY_PREFIX = 'POLICY-'
const SEV = new Set(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'])
const SEV_RANK: Record<string, number> = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0 }
const FINDING_FIELDS = new Set(['check_id_glob', 'section', 'severity', 'severity_op', 'status',
  'compliance_framework', 'compliance_control'])
const MATCH_KEYS = new Set(['op', 'graph', 'finding'])

export class PolicyError extends Error {}

export interface PolicyDef {
  id: string
  name?: string
  section?: string
  severity?: string
  pack?: string
  description?: string
  impact?: string
  remediation_cmd?: string
  steps?: string[]
  compliance?: Record<string, string>
  match: { op?: 'any' | 'all'; graph?: unknown; finding?: Record<string, unknown> }
}
export interface PolicyRollup {
  id: string; name: string; severity: string; section: string; pack: string
  description: string; match: unknown; match_count: number; accounts_matched: string[]; status: 'WARN' | 'PASS'
}
export interface PolicyMatch { nodes: { id: string }[]; findings: FindingCatalogEntry[] }

export function policySeverity(policy: PolicyDef): string {
  return policy.severity && SEV.has(policy.severity) ? policy.severity : 'MEDIUM'
}

// mirror aws_policy.parse — the config boundary (raises PolicyError on a malformed rule).
export function parse(policy: unknown): PolicyDef {
  if (policy === null || typeof policy !== 'object' || Array.isArray(policy)) throw new PolicyError('policy must be an object')
  const p = policy as Record<string, unknown>
  if (!p.id) throw new PolicyError('policy needs an id')
  const match = p.match
  if (match === null || typeof match !== 'object' || Array.isArray(match)) throw new PolicyError("policy needs a 'match' object")
  const m = match as Record<string, unknown>
  for (const k of Object.keys(m)) if (!MATCH_KEYS.has(k)) throw new PolicyError(`unknown match field: ${k}`)
  const op = (m.op ?? 'any')
  if (op !== 'any' && op !== 'all') throw new PolicyError('match op must be any|all')
  if (m.graph != null) {
    try { evalWqlParse(m.graph) } catch (e) { throw new PolicyError(`invalid graph clause: ${e instanceof Error ? e.message : e}`) }
  }
  if (m.finding != null) parseFinding(m.finding)
  if (m.graph == null && m.finding == null) throw new PolicyError("policy match needs a 'graph' and/or a 'finding' clause")
  return policy as PolicyDef
}

// wql.ts has no standalone parse export; a throwaway evaluate over an empty graph validates the
// query shape (and throws WQLError on a bad one) without needing a real graph.
function evalWqlParse(q: unknown): void {
  evalWql(q, { directed: true, multigraph: false, nodes: [], edges: [] })
}

function parseFinding(f: unknown): void {
  if (f === null || typeof f !== 'object' || Array.isArray(f) || Object.keys(f).length === 0) throw new PolicyError('finding predicate must be a non-empty object')
  const o = f as Record<string, unknown>
  for (const k of Object.keys(o)) if (!FINDING_FIELDS.has(k)) throw new PolicyError(`unknown finding field: ${k}`)
  for (const k of ['check_id_glob', 'section', 'status', 'compliance_framework', 'compliance_control']) {
    if (k in o && typeof o[k] !== 'string') throw new PolicyError(`finding.${k} must be a string`)
  }
  // hasOwnProperty (not `in`) — else JS prototype keys ('constructor'/'toString'/'__proto__')
  // would pass the severity whitelist that Python's `in _SEV_RANK` (a dict) rejects.
  if ('severity' in o && !(typeof o.severity === 'string' && Object.prototype.hasOwnProperty.call(SEV_RANK, o.severity))) throw new PolicyError('finding.severity must be a known severity')
  if ('severity_op' in o && !['eq', 'gte', 'lte'].includes(o.severity_op as string)) throw new PolicyError('finding.severity_op must be eq|gte|lte')
  if ('compliance_control' in o && !('compliance_framework' in o)) throw new PolicyError('finding.compliance_control needs a compliance_framework')
}

// mirror aws_policy._eval_finding — a finding matches when ALL specified conditions hold.
function evalFinding(pred: Record<string, unknown>, f: FindingCatalogEntry): boolean {
  // mirror aws_state._glob: an empty pattern means "*" (match all), NOT a literal empty string.
  if ('check_id_glob' in pred && !globMatch((pred.check_id_glob as string) || '*', String(f.check_id ?? ''))) return false
  if ('section' in pred && f.section !== pred.section) return false
  if ('status' in pred && String(f.status ?? '').toUpperCase() !== (pred.status as string).toUpperCase()) return false
  if ('severity' in pred) {
    const want = SEV_RANK[pred.severity as string]
    const got = SEV_RANK[String(f.severity ?? '').toUpperCase()]
    if (got === undefined) return false
    const op = (pred.severity_op as string) ?? 'eq'
    if (!(op === 'eq' ? got === want : op === 'gte' ? got >= want : got <= want)) return false
  }
  if ('compliance_framework' in pred) {
    const comp = f.compliance || {}
    const fw = (pred.compliance_framework as string).toLowerCase()
    const key = Object.keys(comp).find((k) => String(k).toLowerCase() === fw)
    if (key === undefined) return false
    if ('compliance_control' in pred && String(comp[key]) !== pred.compliance_control) return false
  }
  return true
}

// mirror aws_policy.evaluate — {nodes, findings} of matched items when the policy FIRES, else null.
export function evaluate(policy: PolicyDef, graph: GraphFull | null, catalog: FindingCatalogEntry[]): PolicyMatch | null {
  const m = policy.match || {}
  const gq = m.graph, fp = m.finding, op = m.op ?? 'any'
  const nodes = (gq != null && graph != null) ? evalWql(gq, graph).nodes : []
  const findings = fp != null ? (catalog || []).filter((f) => evalFinding(fp, f)) : []
  const fired = (gq != null && fp != null)
    ? (op === 'all' ? (nodes.length > 0 && findings.length > 0) : (nodes.length > 0 || findings.length > 0))
    : (nodes.length > 0 || findings.length > 0)
  if (!fired) return null
  return { nodes, findings }
}

// mirror aws_policy.policy_finding — the POLICY-xx WARN entry (always display-only).
export function policyFinding(policy: PolicyDef, account: string, matched: PolicyMatch): FindingCatalogEntry {
  const affected = matched.nodes.map((n) => n.id).concat(matched.findings.map((f) => `finding:${f.check_id}`))
  const name = policy.name || policy.id
  const n = affected.length
  return {
    check_id: POLICY_PREFIX + String(policy.id),
    section: policy.section || POLICY_SECTION,
    severity: policySeverity(policy),
    status: 'WARN',
    compliance: policy.compliance || {},
    remediation_cmd: policy.remediation_cmd || '',
    risk: policy.description || `Policy '${name}' matched ${n} item(s).`,
    impact: policy.impact || '',
    steps: policy.steps || [],
    affected: affected.slice(0, 500),
    count: n,
    distinct: new Set(affected).size,
    account,
  }
}

export function policyMeta(policy: PolicyDef): Omit<PolicyRollup, 'match_count' | 'accounts_matched' | 'status'> {
  return {
    id: String(policy.id),
    name: policy.name || String(policy.id),
    severity: policySeverity(policy),
    section: policy.section || POLICY_SECTION,
    pack: policy.pack || '',
    description: policy.description || '',
    match: policy.match,
  }
}

export function needsGraph(policy: PolicyDef): boolean {
  return (policy.match || {}).graph != null
}

// mirror cnapp_service._policies_for_account: the POLICY-xx overlay for one account (bad rule inert).
export function policiesForAccount(defs: PolicyDef[], account: string, graph: GraphFull | null, catalog: FindingCatalogEntry[]): FindingCatalogEntry[] {
  const out: FindingCatalogEntry[] = []
  for (const pol of defs) {
    let matched: PolicyMatch | null
    try {
      parse(pol)
      matched = evaluate(pol, graph, catalog)
    } catch {
      continue
    }
    if (matched) out.push(policyFinding(pol, account, matched))
  }
  return out
}

// mirror cnapp_service.list_policies: org roll-up (match count + which accounts), WARN when a
// policy fires anywhere, else PASS. Each account supplies its graph + REAL finding catalog.
export function rollupPolicies(defs: PolicyDef[], accounts: { account: string; graph: GraphFull | null; catalog: FindingCatalogEntry[] }[]): PolicyRollup[] {
  return defs.map((pol) => {
    let count = 0
    const matched: string[] = []
    for (const { account, graph, catalog } of accounts) {
      let m: PolicyMatch | null
      try { parse(pol); m = evaluate(pol, graph, catalog) } catch { continue }
      if (m) { count += m.nodes.length + m.findings.length; matched.push(account) }
    }
    return { ...policyMeta(pol), match_count: count, accounts_matched: matched, status: count ? 'WARN' : 'PASS' }
  })
}

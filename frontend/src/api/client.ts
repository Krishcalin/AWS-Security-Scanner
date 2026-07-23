// Data layer with a build-time toggle between the bundled SAMPLE fixtures and the
// LIVE FastAPI hub. Same fetch shape either way, so screens are source-agnostic.
//   VITE_DATA_SOURCE = 'sample' (default) | 'live'
//   VITE_API_BASE    = '/api' (default; the Vite dev-proxy forwards to :8000)
import type {
  OrgOverview, Account, AccountSummary, Finding, AttackPath, FindingCatalogEntry,
  OnboardRequest, OnboardResult, ValidationResult, GraphFull,
  Connector, ConnectorRule, TestResult, Delivery, PreviewHit,
  CrosswalkData, CrosswalkEdge, AccountCompliance, ComplianceFrameworkMeta,
  TrendRow, DriftDigest, DigestDelivery,
  IngestedVuln, IngestDoc, IngestResult,
} from './types'
import { deriveCrosswalk } from '../lib/crosswalk'

const MODE = (import.meta.env.VITE_DATA_SOURCE as string) ?? 'sample'
const API_BASE = (import.meta.env.VITE_API_BASE as string) ?? '/api'
export const DATA_MODE = MODE
const SAMPLE = MODE !== 'live'

function endpoint(livePath: string, sampleFile: string): string {
  return MODE === 'live' ? `${API_BASE}${livePath}` : `/sample/${sampleFile}`
}

async function get<T>(u: string): Promise<T> {
  const r = await fetch(u, { headers: { Accept: 'application/json' } })
  if (!r.ok) throw new Error(`${r.status} ${r.statusText}`)
  return (await r.json()) as T
}

async function send<T>(method: string, livePath: string, body?: unknown): Promise<T> {
  const r = await fetch(`${API_BASE}${livePath}`, {
    method, headers: { 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  })
  if (!r.ok) throw new Error(`${r.status} ${r.statusText}`)
  const txt = await r.text()
  return (txt ? JSON.parse(txt) : {}) as T
}
const post = <T>(p: string, b: unknown) => send<T>('POST', p, b)
const put = <T>(p: string, b: unknown) => send<T>('PUT', p, b)
const del = (p: string) => send<Record<string, never>>('DELETE', p)

// ── sample-mode write mocks (the write routes are admin/private; no fixture) ──
function randHex(n: number): string {
  const a = new Uint8Array(n)
  crypto.getRandomValues(a)
  return Array.from(a, (b) => b.toString(16).padStart(2, '0')).join('')
}
const HUB_ROLE = 'arn:aws:iam::999900001111:role/CnappHubRole'
const CFN_TEMPLATE = 'https://kizen-cnapp-cfn.s3.amazonaws.com/cnapp-scanner-role.yaml'

function mockOnboard(req: OnboardRequest): OnboardResult {
  const eid = randHex(20)
  const region = req.region ?? 'us-east-1'
  const url = `https://console.aws.amazon.com/cloudformation/home?region=${region}#/stacks/quickcreate`
    + `?templateURL=${encodeURIComponent(CFN_TEMPLATE)}&stackName=CnappScannerRole`
    + `&param_HubRoleArn=${encodeURIComponent(HUB_ROLE)}&param_ExternalId=${eid}`
  const cli = `aws cloudformation create-stack --stack-name CnappScannerRole --template-url ${CFN_TEMPLATE} `
    + `--capabilities CAPABILITY_NAMED_IAM --parameters ParameterKey=HubRoleArn,ParameterValue=${HUB_ROLE} `
    + `ParameterKey=ExternalId,ParameterValue=${eid}`
  return {
    account_id: req.account_id, role_name: 'CnappScannerRole',
    external_id_ref: `secretsmanager://kizen/cnapp/externalid/${req.account_id}`,
    reused: false, cfn_launch_url: url, cli, external_id: eid,
  }
}

function mockValidate(id: string, orgMode: boolean): ValidationResult {
  return {
    expected_account_id: id, observed_account_id: id,
    role_arn: `arn:aws:iam::${id}:role/CnappScannerRole`, region: 'us-east-1', org_mode: orgMode,
    health: 'healthy', ok: true,
    summary: 'Assumed the read-only role, the account id matches, and the SecurityAudit canary read succeeded.',
    next_revalidation_epoch: null, org_account_count: orgMode ? 5 : null,
    checks: [
      { name: 'Assume role', ok: true, detail: 'sts:AssumeRole with ExternalId succeeded' },
      { name: 'Account match', ok: true, detail: `GetCallerIdentity resolved to ${id}` },
      { name: 'SecurityAudit read', ok: true, detail: 'iam:GetAccountSummary canary succeeded' },
      ...(orgMode ? [{ name: 'Organizations list', ok: true, detail: '5 member accounts visible' }] : []),
    ],
  }
}

// ── sample-mode connector store (default mode has no backend, so CRUD is an ────
// in-memory mock seeded from a fixture — the screen is fully interactive offline).
interface SampleDB { conns: Connector[]; rules: ConnectorRule[]; deliveries: Delivery[]; seeded: boolean }
const S: SampleDB = { conns: [], rules: [], deliveries: [], seeded: false }
const nowEpoch = () => Math.floor(Date.now() / 1000)
const newId = (p: string) => p + randHex(6)

async function seed(): Promise<void> {
  if (S.seeded) return
  S.seeded = true
  try {
    const f = await get<{ connectors: Connector[]; rules: ConnectorRule[]; deliveries: Delivery[] }>(
      '/sample/connectors.json')
    S.conns = f.connectors ?? []
    S.rules = f.rules ?? []
    S.deliveries = f.deliveries ?? []
  } catch { /* no fixture → start empty */ }
}

const RANK: Record<string, number> = { CRITICAL: 5, HIGH: 4, MEDIUM: 3, LOW: 2, INFO: 1 }
// mirror aws_state._glob (fnmatchcase): case-sensitive * and ? — so the offline
// Preview matches the backend rules engine rather than over-reporting.
function glob(pattern: string, value: string): boolean {
  const re = '^' + pattern.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*').replace(/\?/g, '.') + '$'
  return new RegExp(re).test(value)
}
const blankRule = (connector_id: string, id: number, spec: Partial<ConnectorRule>): ConnectorRule => ({
  id, connector_id, name: spec.name ?? '', enabled: spec.enabled ?? true, priority: spec.priority ?? 100,
  min_severity: spec.min_severity ?? 'HIGH', severities: [], sections: spec.sections ?? [],
  check_globs: spec.check_globs ?? [], not_check_globs: [], account_globs: spec.account_globs ?? [],
  on_attack_path: spec.on_attack_path ?? null, statuses: spec.statuses ?? ['FAIL'],
  frameworks: spec.frameworks ?? [], controls: [], min_count: 0, min_distinct: spec.min_distinct ?? 0,
  dedup_mode: spec.dedup_mode ?? 'notify_once', throttle_seconds: spec.throttle_seconds ?? 0,
  renotify_on_escalation: true, notify_on_resolve: spec.notify_on_resolve ?? false, stop_on_match: false,
  connector_ids: [connector_id], tags: [], message_template: null, severity_override: null,
})

const connectorApi = {
  listConnectors: async (): Promise<Connector[]> => {
    if (!SAMPLE) return get<Connector[]>(`${API_BASE}/connectors`)
    await seed(); return S.conns.map((c) => ({ ...c }))
  },
  createConnector: async (b: { type: Connector['type']; name: string; config: Record<string, unknown>; secret?: string }): Promise<Connector> => {
    if (!SAMPLE) return post<Connector>('/connectors', b)
    await seed()
    const c: Connector = {
      connector_id: newId('conn-'), type: b.type, name: b.name, enabled: false,
      config: b.config ?? {}, secret_configured: !!b.secret, created_by: 'you',
      last_test_at: null, last_test_status: null, last_test_detail: null,
      created_at: nowEpoch(), updated_at: nowEpoch(),
    }
    S.conns.push(c); return { ...c }
  },
  updateConnector: async (id: string, b: { name?: string; config?: Record<string, unknown> }): Promise<Connector> => {
    if (!SAMPLE) return put<Connector>(`/connectors/${id}`, b)
    await seed(); const c = S.conns.find((x) => x.connector_id === id)!
    if (b.name !== undefined) c.name = b.name
    if (b.config !== undefined) c.config = b.config
    c.updated_at = nowEpoch(); return { ...c }
  },
  enableConnector: async (id: string, enabled: boolean): Promise<Connector> => {
    if (!SAMPLE) return post<Connector>(`/connectors/${id}/enable`, { enabled })
    await seed(); const c = S.conns.find((x) => x.connector_id === id)!
    c.enabled = enabled; c.updated_at = nowEpoch(); return { ...c }
  },
  rotateSecret: async (id: string, secret: string): Promise<Connector> => {
    if (!SAMPLE) return post<Connector>(`/connectors/${id}/rotate-secret`, { secret })
    await seed(); const c = S.conns.find((x) => x.connector_id === id)!
    c.secret_configured = true; c.updated_at = nowEpoch(); return { ...c }
  },
  testConnector: async (id: string): Promise<TestResult> => {
    if (!SAMPLE) return post<TestResult>(`/connectors/${id}/test`, {})
    await seed(); const c = S.conns.find((x) => x.connector_id === id)!
    const ok = c.enabled && c.secret_configured
    c.last_test_at = nowEpoch(); c.last_test_status = ok ? 'ok' : 'failed'
    c.last_test_detail = ok ? 'reachable · credentials valid' : 'enable + set a secret first'
    return { ok, http_status: ok ? 200 : 0, detail: c.last_test_detail, error: ok ? null : c.last_test_detail, external_ref: null }
  },
  deleteConnector: async (id: string): Promise<void> => {
    if (!SAMPLE) { await del(`/connectors/${id}`); return }
    await seed(); S.conns = S.conns.filter((c) => c.connector_id !== id)
    S.rules = S.rules.filter((r) => r.connector_id !== id)
  },
  listRules: async (id: string): Promise<ConnectorRule[]> => {
    if (!SAMPLE) return get<ConnectorRule[]>(`${API_BASE}/connectors/${id}/rules`)
    await seed(); return S.rules.filter((r) => r.connector_id === id).map((r) => ({ ...r }))
  },
  createRule: async (id: string, spec: Partial<ConnectorRule>): Promise<ConnectorRule> => {
    if (!SAMPLE) return post<ConnectorRule>(`/connectors/${id}/rules`, { spec })
    await seed(); const r = blankRule(id, (S.rules.reduce((m, x) => Math.max(m, x.id), 0) + 1), spec)
    S.rules.push(r); return { ...r }
  },
  updateRule: async (id: string, ruleId: number, spec: Partial<ConnectorRule>): Promise<ConnectorRule> => {
    if (!SAMPLE) return put<ConnectorRule>(`/connectors/${id}/rules/${ruleId}`, { spec })
    await seed(); const r = S.rules.find((x) => x.id === ruleId)!
    Object.assign(r, spec); return { ...r }
  },
  deleteRule: async (id: string, ruleId: number): Promise<void> => {
    if (!SAMPLE) { await del(`/connectors/${id}/rules/${ruleId}`); return }
    await seed(); S.rules = S.rules.filter((r) => r.id !== ruleId)
  },
  previewRules: async (accountId: string): Promise<PreviewHit[]> => {
    if (!SAMPLE) return post<PreviewHit[]>('/connectors/rules/preview', { account_id: accountId })
    await seed()
    const findings = await get<FindingCatalogEntry[]>(
      endpoint(`/accounts/${accountId}/findings`, `account_${accountId}_findings.json`)).catch(() => [])
    // Ported from backend rule_matches (cnapp_connectors.py) so Preview doesn't
    // over-report. on_attack_path is not in the findings fixture, so a rule that
    // gates on it is treated as "any" here (the live backend applies it exactly).
    const hits: PreviewHit[] = []
    for (const f of findings) {
      for (const r of S.rules.filter((x) => x.enabled)) {
        const c = S.conns.find((x) => x.connector_id === r.connector_id)
        if (!c || !c.enabled) continue
        if (r.statuses.length && !r.statuses.includes(f.status)) continue
        if (r.severities.length) { if (!r.severities.includes(f.severity)) continue }
        else if ((RANK[f.severity] ?? 0) < (RANK[r.min_severity] ?? 0)) continue
        if (r.sections.length && !r.sections.includes(f.section)) continue
        if (r.check_globs.length && !r.check_globs.some((g) => glob(g, f.check_id))) continue
        if (r.not_check_globs.some((g) => glob(g, f.check_id))) continue
        if (r.account_globs.length && !r.account_globs.some((g) => glob(g, accountId))) continue
        if (r.frameworks.length && !r.frameworks.some((fw) => fw in (f.compliance ?? {}))) continue
        if (r.min_distinct && f.distinct < r.min_distinct) continue
        hits.push({ connector_id: r.connector_id, connector_name: c.name, rule_id: r.id,
          check_id: f.check_id, account: accountId, severity: f.severity })
      }
    }
    return hits
  },
  notifyAccount: async (accountId: string): Promise<{ sent: number; suppressed: number; resolved: number; failed: number; digested: number }> => {
    if (!SAMPLE) return post('/accounts/' + accountId + '/notify', {})
    const hits = await connectorApi.previewRules(accountId)
    const fresh = hits.filter((h) => !S.deliveries.some(
      (d) => d.connector_id === h.connector_id && d.account === h.account && d.check_id === h.check_id))
    for (const h of fresh) {
      S.deliveries.unshift({ id: S.deliveries.length + 1, connector_id: h.connector_id, dedup_key: randHex(8),
        rule_id: h.rule_id, account: h.account, check_id: h.check_id, state: 'open', kind: 'new',
        status: 'sent', http_status: 201, error: null, external_ref: 'SEC-' + (100 + S.deliveries.length),
        created_at: nowEpoch(), sent_at: nowEpoch() })
    }
    return { sent: fresh.length, suppressed: hits.length - fresh.length, resolved: 0, failed: 0, digested: 0 }
  },
  listDeliveries: async (id?: string): Promise<Delivery[]> => {
    if (!SAMPLE) return get<Delivery[]>(`${API_BASE}${id ? `/connectors/${id}/deliveries` : '/notifications'}`)
    await seed(); return S.deliveries.filter((d) => !id || d.connector_id === id).map((d) => ({ ...d }))
  },
}

// ── compliance breadth (crosswalk from the NIST spine) ─────────────────────────
let _cwCache: CrosswalkData | null = null
async function crosswalkData(): Promise<CrosswalkData> {
  if (!SAMPLE) return get<CrosswalkData>(`${API_BASE}/compliance/crosswalk?_full=1`)
  if (!_cwCache) _cwCache = await get<CrosswalkData>('/sample/crosswalk.json')
  return _cwCache
}

const complianceApi = {
  complianceFrameworks: async (): Promise<{ crosswalk_version: string; spine: string; frameworks: ComplianceFrameworkMeta[] }> => {
    if (!SAMPLE) return get(`${API_BASE}/compliance/frameworks`)
    const cw = await crosswalkData()
    return { crosswalk_version: cw.schema, spine: cw.spine, frameworks: cw.frameworks }
  },
  crosswalkEdges: async (framework?: string): Promise<CrosswalkEdge[]> => {
    if (!SAMPLE) return get(`${API_BASE}/compliance/crosswalk${framework ? `?framework=${framework}` : ''}`)
    const cw = await crosswalkData()
    const meta = new Map(cw.frameworks.map((f) => [f.id, f]))
    const rows: CrosswalkEdge[] = []
    for (const [nist, fwmap] of Object.entries(cw.crosswalk))
      for (const [fid, e] of Object.entries(fwmap))
        if (!framework || fid === framework)
          rows.push({ nist, framework: fid, targets: e.targets, confidence: e.confidence, note: e.note, sources: meta.get(fid)?.sources ?? [] })
    return rows.sort((a, b) => a.framework.localeCompare(b.framework) || a.nist.localeCompare(b.nist))
  },
  accountCompliance: async (id: string, opts?: { minConfidence?: string; frameworks?: string[] }): Promise<AccountCompliance> => {
    if (!SAMPLE) {
      const q = new URLSearchParams()
      if (opts?.minConfidence) q.set('min_confidence', opts.minConfidence)
      if (opts?.frameworks?.length) q.set('frameworks', opts.frameworks.join(','))
      return get(`${API_BASE}/accounts/${id}/compliance${q.toString() ? `?${q}` : ''}`)
    }
    const [summary, cw] = await Promise.all([
      get<AccountSummary>(`/sample/account_${id}_summary.json`), crosswalkData()])
    let derived = deriveCrosswalk(summary.compliance_scorecard, cw, opts?.minConfidence)
    if (opts?.frameworks?.length) {
      const keep = new Set(opts.frameworks)
      derived = Object.fromEntries(Object.entries(derived).filter(([k]) => keep.has(k)))
    }
    return { account: id, native: summary.compliance_scorecard, derived, crosswalk_version: cw.schema, min_confidence: opts?.minConfidence ?? null }
  },
}

// ── continuous scheduling + drift (CTEM) ───────────────────────────────────────
const _sched: Record<string, string> = {}       // sample-mode schedule overrides

function synthTrend(id: string, score: number): TrendRow[] {
  // a deterministic 6-point posture history converging to the account's current score
  const rows: TrendRow[] = []
  const base = 1_700_000_000
  for (let i = 5; i >= 0; i--) {
    const s = Math.max(0, Math.min(100, Math.round(score - i * 2 + (i % 2 ? 1 : 0))))
    const prev = rows.length ? rows[rows.length - 1].posture_score : null
    rows.push({
      scan_id: `${id}-s${5 - i}`, ts_epoch: base - i * 86400, ts_iso: new Date((base - i * 86400) * 1000).toISOString(),
      posture_score: s, grade: s >= 90 ? 'A' : s >= 80 ? 'B' : s >= 70 ? 'C' : s >= 60 ? 'D' : 'F',
      crit: 0, high: 0, med: 0, low: 0, total_open: Math.max(0, 40 - Math.round(s / 3)),
      new_count: i === 0 ? 3 : 1, resolved_count: i === 0 ? 1 : 0, reopened_count: 0, suppressed_count: 0,
      delta: prev === null ? null : Math.round((s - prev) * 10) / 10,
    })
  }
  return rows
}

const schedulingApi = {
  setSchedule: async (id: string, schedule: string): Promise<{ account_id: string; scan_schedule: string }> => {
    if (!SAMPLE) return put(`/accounts/${id}/schedule`, { schedule })   // backend route is PUT
    _sched[id] = schedule
    return { account_id: id, scan_schedule: schedule }
  },
  scheduleTick: async (): Promise<{ job_ids: string[] }> => {
    if (!SAMPLE) return post('/scans/schedule-tick', {})
    return { job_ids: [] }
  },
  getSchedule: (id: string): string => _sched[id] ?? 'off',
  trend: async (id: string): Promise<TrendRow[]> => {
    if (!SAMPLE) return get<TrendRow[]>(`${API_BASE}/accounts/${id}/trend`)
    const s = await get<AccountSummary>(`/sample/account_${id}_summary.json`).catch(() => null)
    return s ? synthTrend(id, s.posture_score) : []
  },
  drift: async (id: string): Promise<TrendRow | Record<string, never>> => {
    if (!SAMPLE) return get(`${API_BASE}/accounts/${id}/drift`)
    const t = await schedulingApi.trend(id)
    return t.length ? t[t.length - 1] : {}
  },
  digestPreview: async (id: string): Promise<DriftDigest | null> => {
    if (!SAMPLE) return post(`/accounts/${id}/digest/preview`, {})
    const [s, findings] = await Promise.all([
      get<AccountSummary>(`/sample/account_${id}_summary.json`).catch(() => null),
      get<FindingCatalogEntry[]>(`/sample/account_${id}_findings.json`).catch(() => [] as FindingCatalogEntry[])])
    if (!s) return null
    const t = await schedulingApi.trend(id)
    const cur = t[t.length - 1]
    const newly = findings.slice(0, 5).map((f) => ({ check_id: f.check_id, severity: f.severity, resource: f.affected[0] ?? '', on_attack_path: false }))
    return {
      account: id, scan_id: 'preview', ts_epoch: cur.ts_epoch, ts_iso: cur.ts_iso, window_id: 'preview',
      posture_score: cur.posture_score, posture_grade: cur.grade, posture_delta: cur.delta,
      counts: { new: 3, resolved: 1, reopened: 0, mutated: 0, still_open: findings.length, suppressed: 0 },
      sev_delta: {}, material_change: true, newly_exposed: newly, newly_on_path: newly.filter((_, i) => i === 0),
      resolved_wins: [], reopened: [], sla: { open_over_sla: 2, sla_days: 30 }, mttr_days_mean: 4.2,
      compliance_delta: null, headline: `Drift · acct ${id} · +3 new · -1 resolved`, link: `/accounts/${id}`,
    }
  },
  listDigests: async (connectorId?: string): Promise<DigestDelivery[]> => {
    if (!SAMPLE) return get<DigestDelivery[]>(`${API_BASE}${connectorId ? `/connectors/${connectorId}/digests` : '/digests'}`)
    return []       // sample: digests are produced by scans; none pre-seeded
  },
}

// ── external-vuln ingest plane (SARIF/CycloneDX/SPDX → reachability-ranked) ──
interface VulnQuery { min_band?: string; kev?: boolean; on_path?: boolean; source?: string; node?: string; include_suppressed?: boolean; sort?: string }
function vulnQS(q: VulnQuery = {}): string {
  const p = new URLSearchParams()
  if (q.min_band) p.set('min_band', q.min_band)
  if (q.kev !== undefined) p.set('kev', String(q.kev))
  if (q.on_path !== undefined) p.set('on_path', String(q.on_path))
  if (q.source) p.set('source', q.source)
  if (q.node) p.set('node', q.node)
  if (q.include_suppressed !== undefined) p.set('include_suppressed', String(q.include_suppressed))
  if (q.sort) p.set('sort', q.sort)
  const s = p.toString()
  return s ? `?${s}` : ''
}

const vulnApi = {
  // The whole sample vuln set is one account-tagged fixture; filter it per scope.
  _allVulns: () => get<IngestedVuln[]>('/sample/vulns.json').catch(() => [] as IngestedVuln[]),
  listVulns: async (id: string, q: VulnQuery = {}): Promise<IngestedVuln[]> => {
    if (!SAMPLE) return get<IngestedVuln[]>(`${API_BASE}/accounts/${id}/vulns${vulnQS(q)}`)
    let rows = (await vulnApi._allVulns()).filter((r) => r.account === id)
    if (q.include_suppressed === false) rows = rows.filter((r) => !r.suppressed)
    if (q.kev !== undefined) rows = rows.filter((r) => r.kev === q.kev)
    if (q.on_path !== undefined) rows = rows.filter((r) => r.on_attack_path === q.on_path)
    return rows.sort((a, b) => b.priority_score - a.priority_score)
  },
  orgVulns: async (q: VulnQuery = {}): Promise<IngestedVuln[]> => {
    if (!SAMPLE) return get<IngestedVuln[]>(`${API_BASE}/org/vulns${vulnQS(q)}`)
    return (await vulnApi._allVulns()).sort((a, b) => b.priority_score - a.priority_score)
  },
  getVuln: async (id: string, cve: string): Promise<IngestedVuln[]> => {
    if (!SAMPLE) return get<IngestedVuln[]>(`${API_BASE}/accounts/${id}/vulns/${cve}`)
    return (await vulnApi._allVulns()).filter((r) => r.account === id && r.cve === cve)
  },
  listIngestDocs: async (id: string): Promise<IngestDoc[]> => {
    if (!SAMPLE) return get<IngestDoc[]>(`${API_BASE}/accounts/${id}/ingest/docs`)
    return []
  },
  ingest: async (id: string, doc: unknown, target_resource?: string): Promise<IngestResult> => {
    if (!SAMPLE) return post<IngestResult>(`/accounts/${id}/ingest`, { doc, target_resource })
    // sample mode: accept + echo a plausible result (no persistence)
    return { doc_id: 'sha256:' + randHex(8), resolved_node: target_resource ?? 'ingest:image:demo',
             node_kind: 'ECRImage', mapping_status: target_resource ? 'resolved' : 'unmapped',
             lane: 'findings', finding_count: 0, notes: ['sample mode — not persisted'],
             newly_reachable_kev: [], top: [] }
  },
  refreshVulns: async (id: string): Promise<{ became_reachable: unknown[]; became_unreachable: unknown[] }> => {
    if (!SAMPLE) return post(`/accounts/${id}/vulns/refresh`, {})
    return { became_reachable: [], became_unreachable: [] }
  },
}

export const api = {
  ...connectorApi,
  ...complianceApi,
  ...schedulingApi,
  ...vulnApi,
  orgOverview: () => get<OrgOverview>(endpoint('/org/overview', 'org_overview.json')),
  listAccounts: () => get<Account[]>(endpoint('/accounts', 'accounts.json')),
  accountSummary: (id: string) =>
    get<AccountSummary>(endpoint(`/accounts/${id}/summary`, `account_${id}_summary.json`)),
  issues: (id: string) =>
    get<Finding[]>(endpoint(`/accounts/${id}/issues`, `account_${id}_issues.json`)),
  paths: (id: string) =>
    get<AttackPath[]>(endpoint(`/accounts/${id}/paths`, `account_${id}_paths.json`)),
  graph: (id: string) =>
    get<GraphFull>(endpoint(`/accounts/${id}/graph`, `account_${id}_graph.json`)),
  findings: (id: string) =>
    get<FindingCatalogEntry[]>(endpoint(`/accounts/${id}/findings`, `account_${id}_findings.json`)),
  orgFindings: () =>
    get<FindingCatalogEntry[]>(endpoint('/org/findings', 'org_findings.json')),

  // write flow (admin) — mocked in sample mode, real POSTs in live mode
  onboard: (req: OnboardRequest) =>
    SAMPLE ? Promise.resolve(mockOnboard(req)) : post<OnboardResult>('/accounts', req),
  validate: (id: string, orgMode = false) =>
    SAMPLE
      ? new Promise<ValidationResult>((res) => setTimeout(() => res(mockValidate(id, orgMode)), 1300))
      : post<ValidationResult>(`/accounts/${id}/validate?org_mode=${orgMode}`, {}),
  triggerScan: (ids: string[]) =>
    SAMPLE
      ? Promise.resolve({ job_ids: ids.map(() => 'job-' + randHex(8)) })
      : post<{ job_ids: string[] }>('/scans', { account_ids: ids }),
}

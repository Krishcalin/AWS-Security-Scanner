// Data layer with a build-time toggle between the bundled SAMPLE fixtures and the
// LIVE FastAPI hub. Same fetch shape either way, so screens are source-agnostic.
//   VITE_DATA_SOURCE = 'sample' (default) | 'live'
//   VITE_API_BASE    = '/api' (default; the Vite dev-proxy forwards to :8000)
import type {
  OrgOverview, Account, AccountSummary, Finding, AttackPath, FindingCatalogEntry,
  OnboardRequest, OnboardResult, ValidationResult, GraphFull,
  Connector, ConnectorRule, TestResult, Delivery, PreviewHit,
  CrosswalkData, CrosswalkEdge, AccountCompliance, ComplianceFrameworkMeta,
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

export const api = {
  ...connectorApi,
  ...complianceApi,
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

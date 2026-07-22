// Data layer with a build-time toggle between the bundled SAMPLE fixtures and the
// LIVE FastAPI hub. Same fetch shape either way, so screens are source-agnostic.
//   VITE_DATA_SOURCE = 'sample' (default) | 'live'
//   VITE_API_BASE    = '/api' (default; the Vite dev-proxy forwards to :8000)
import type {
  OrgOverview, Account, AccountSummary, Finding, AttackPath, FindingCatalogEntry,
  OnboardRequest, OnboardResult, ValidationResult, GraphFull,
} from './types'

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

async function post<T>(livePath: string, body: unknown): Promise<T> {
  const r = await fetch(`${API_BASE}${livePath}`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
  })
  if (!r.ok) throw new Error(`${r.status} ${r.statusText}`)
  return (await r.json()) as T
}

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

export const api = {
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

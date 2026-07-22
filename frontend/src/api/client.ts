// Data layer with a build-time toggle between the bundled SAMPLE fixtures and the
// LIVE FastAPI hub. Same fetch shape either way, so screens are source-agnostic.
//   VITE_DATA_SOURCE = 'sample' (default) | 'live'
//   VITE_API_BASE    = '/api' (default; the Vite dev-proxy forwards to :8000)
import type {
  OrgOverview, Account, AccountSummary, Finding, AttackPath, FindingCatalogEntry,
} from './types'

const MODE = (import.meta.env.VITE_DATA_SOURCE as string) ?? 'sample'
const API_BASE = (import.meta.env.VITE_API_BASE as string) ?? '/api'
export const DATA_MODE = MODE

function endpoint(livePath: string, sampleFile: string): string {
  return MODE === 'live' ? `${API_BASE}${livePath}` : `/sample/${sampleFile}`
}

async function get<T>(u: string): Promise<T> {
  const r = await fetch(u, { headers: { Accept: 'application/json' } })
  if (!r.ok) throw new Error(`${r.status} ${r.statusText}`)
  return (await r.json()) as T
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
  findings: (id: string) =>
    get<FindingCatalogEntry[]>(endpoint(`/accounts/${id}/findings`, `account_${id}_findings.json`)),
  orgFindings: () =>
    get<FindingCatalogEntry[]>(endpoint('/org/findings', 'org_findings.json')),
}

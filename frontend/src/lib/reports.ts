// Pure report-assembly helpers (no React/DOM) so the node-env vitest can exercise them.
// Everything here reads data the Reports page already fetched — no new endpoint, no scanning.
import type { FindingCatalogEntry, GraphFull, AccountSummary } from '../api/types'

// ── Cross-account network analysis ─────────────────────────────────────────────
// Trust-boundary-crossing findings already in the catalog: active peering (VPC-06),
// cross-account resource-policy grants, and flow-log-evidenced signals.
export const CROSS_ACCOUNT_CHECKS = new Set([
  'VPC-06', 'KMS-04', 'S3-10', 'SEC-05', 'DDB-05', 'BCK-03', 'CNT-03', 'AMI-01',
  'DSPM-03', 'EXTACCESS-02', 'FLOW-01', 'FLOW-02', 'FLOW-03',
])
export function crossAccountFindings(findings: FindingCatalogEntry[]): FindingCatalogEntry[] {
  return findings.filter((f) => CROSS_ACCOUNT_CHECKS.has((f.check_id || '').toUpperCase()))
}

// ── Network exposure (from the EXPOSED_TO edges on the account graph) ───────────
export interface ExposureRow { resource: string; exposed_via: string; ports: string; ip_kind: string; basis: string }
export function exposureReport(g: GraphFull | null): ExposureRow[] {
  if (!g || !Array.isArray(g.edges)) return []
  const s = (v: unknown) => (v == null ? '' : Array.isArray(v) ? v.join(',') : String(v))
  return g.edges
    .filter((e) => e.kind === 'EXPOSED_TO')
    .map((e) => ({
      resource: s(e.target),
      exposed_via: s(e.source),
      ports: s(e.ports ?? e.port),
      ip_kind: s(e.ip_kind),
      basis: s(e.basis),
    }))
}

// ── Executive HTML (a branded, self-contained artifact, no PDF dependency) ─────
const _esc = (v: unknown): string =>
  String(v ?? '').replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]!))

export function buildExecHtml(opts: {
  scope: string
  isOrg: boolean
  summary: Partial<AccountSummary> | null
  orgScore?: number | null
  findings: FindingCatalogEntry[]
}): string {
  const { scope, isOrg, summary, orgScore, findings } = opts
  const score = isOrg ? (orgScore ?? null) : (summary?.posture_score ?? null)
  const grade = isOrg ? '' : (summary?.posture_grade ?? '')
  // Severity counts come from the FINDINGS themselves — correct in BOTH org and account scope
  // (AccountSummary.severity_counts is absent under org, and summary.summary is a StatusCount,
  // not narrative prose — rendering it directly produced "[object Object]").
  const sev: Record<string, number> = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 }
  for (const f of findings) if (f.severity in sev) sev[f.severity]++
  const sevRow = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
    .map((s) => `<span class="pill ${s.toLowerCase()}">${sev[s]} ${s}</span>`).join(' ')
  const assessment = `${sev.CRITICAL} critical and ${sev.HIGH} high-severity finding(s) across `
    + `${isOrg ? 'the organization' : 'this account'}`
    + (score != null ? `; posture score ${score}${grade ? ` (grade ${grade})` : ''}.` : '.')
  const top = findings
    .filter((f) => f.severity === 'CRITICAL' || f.severity === 'HIGH')
    .slice(0, 25)
    .map((f) => `<tr><td class="mono">${_esc(f.check_id)}</td><td>${_esc(f.severity)}</td>`
      + `<td>${_esc(f.section)}</td><td>${_esc(f.risk)}</td>`
      + `<td class="mono">${_esc((f.affected || []).slice(0, 3).join(', '))}</td></tr>`).join('')
  return `<!doctype html><html><head><meta charset="utf-8">
<title>OverWatch Executive Report — ${_esc(isOrg ? 'Organization' : scope)}</title>
<style>
  body{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;color:#0f172a;margin:0;padding:40px;background:#fff}
  .head{display:flex;align-items:center;gap:12px;border-bottom:3px solid #38bdf8;padding-bottom:16px;margin-bottom:24px}
  .head h1{font-size:22px;margin:0}.head .sub{color:#64748b;font-size:13px;font-family:ui-monospace,monospace}
  .gauge{font-size:52px;font-weight:800;line-height:1}.grade{color:#64748b;font-size:14px}
  .pill{display:inline-block;border-radius:999px;padding:3px 10px;font-size:12px;font-weight:700;margin-right:4px}
  .pill.critical{background:#fee2e2;color:#b91c1c}.pill.high{background:#ffedd5;color:#c2410c}
  .pill.medium{background:#fef9c3;color:#a16207}.pill.low{background:#dcfce7;color:#15803d}
  h2{font-size:15px;margin:26px 0 10px;color:#334155}
  table{border-collapse:collapse;width:100%;font-size:12px}
  th{text-align:left;background:#f1f5f9;padding:7px 9px;border-bottom:2px solid #e2e8f0;color:#475569}
  td{padding:7px 9px;border-bottom:1px solid #eef2f6;vertical-align:top}
  .mono{font-family:ui-monospace,monospace;font-size:11px}
  .foot{margin-top:28px;color:#94a3b8;font-size:11px}
</style></head><body>
<div class="head">
  <div style="flex:1"><h1>OverWatch — Executive Security Report</h1>
  <div class="sub">${_esc(isOrg ? 'Organization' : 'Account ' + scope)} · ${findings.length} findings</div></div>
  <div style="text-align:right"><div class="gauge">${score == null ? '—' : _esc(score)}</div>
  <div class="grade">${grade ? 'grade ' + _esc(grade) : 'posture score'}</div></div>
</div>
<h2>Severity summary</h2><div>${sevRow}</div>
<h2>Assessment</h2><p style="font-size:13px;color:#334155">${_esc(assessment)}</p>
<h2>Top critical &amp; high findings</h2>
<table><thead><tr><th>Check</th><th>Severity</th><th>Section</th><th>Risk</th><th>Affected</th></tr></thead>
<tbody>${top || '<tr><td colspan="5">No critical or high findings.</td></tr>'}</tbody></table>
<div class="foot">Generated by the OverWatch console · self-hosted, agentless, zero-telemetry · this artifact never left your boundary.</div>
</body></html>`
}

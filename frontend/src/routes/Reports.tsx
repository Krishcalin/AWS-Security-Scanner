import { useState } from 'react'
import { FileText, Download, FileJson, FileSpreadsheet, Info } from 'lucide-react'
import { useScope } from '../state/scope'
import { useFetch } from '../lib/useFetch'
import { api } from '../api/client'
import { Card, Loader, ErrorNote } from '../components/ui'
import type { OrgOverview, AccountSummary, FindingCatalogEntry } from '../api/types'

const SECTIONS = [
  { k: 'summary', label: 'Executive summary' },
  { k: 'paths', label: 'Attack paths' },
  { k: 'findings', label: 'Findings detail' },
  { k: 'compliance', label: 'Compliance scorecard' },
  { k: 'remediation', label: 'Remediation plan' },
] as const

function download(name: string, text: string, type: string) {
  const blob = new Blob([text], { type })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url; a.download = name; a.click()
  URL.revokeObjectURL(url)
}
function toCsv(findings: FindingCatalogEntry[]): string {
  const esc = (v: string) => `"${String(v).replace(/"/g, '""')}"`
  const head = ['check_id', 'section', 'severity', 'distinct', 'frameworks', 'affected']
  const rows = findings.map((f) => [f.check_id, f.section, f.severity, String(f.distinct), Object.keys(f.compliance).join('|'), f.affected.join('|')])
  return [head, ...rows].map((r) => r.map(esc).join(',')).join('\n')
}

interface RepData { o: OrgOverview | null; s: AccountSummary | null; f: FindingCatalogEntry[] }

export function Reports() {
  const { scope } = useScope()
  const isOrg = scope === 'org'
  const { data, loading, error } = useFetch<RepData>(
    () => isOrg
      ? Promise.all([api.orgOverview(), api.orgFindings()]).then(([o, f]) => ({ o, s: null, f }))
      : Promise.all([api.accountSummary(scope), api.findings(scope)]).then(([s, f]) => ({ o: null, s, f })),
    [scope])
  const [sections, setSections] = useState<Set<string>>(new Set(SECTIONS.map((s) => s.k)))
  const [schedule, setSchedule] = useState('none')

  if (loading) return <Loader />
  if (error) return <ErrorNote msg={error} />
  if (!data) return null

  const toggle = (k: string) => setSections((s) => { const n = new Set(s); n.has(k) ? n.delete(k) : n.add(k); return n })
  const stamp = isOrg ? 'org' : scope

  const buildJson = () => {
    const rep: Record<string, unknown> = { scanner: 'OverWatch CNAPP', scope: stamp, generated_by: 'console (client-side export)' }
    if (sections.has('summary')) rep.summary = isOrg
      ? { org_posture_score: data.o?.org_posture_score, accounts_scanned: data.o?.accounts_scanned, critical_attack_paths: data.o?.critical_attack_paths, crown_jewels_at_risk: data.o?.crown_jewels_at_risk }
      : { posture_score: data.s?.posture_score, posture_grade: data.s?.posture_grade, summary: data.s?.summary, severity_counts: data.s?.severity_counts }
    if (sections.has('paths')) rep.attack_paths = isOrg ? data.o?.top_attack_paths : data.s?.attack_paths
    if (sections.has('compliance') && !isOrg) rep.compliance_scorecard = data.s?.compliance_scorecard
    if (sections.has('remediation')) rep.choke_points = isOrg ? data.o?.top_choke_points : data.s?.choke_points
    if (sections.has('findings')) rep.finding_catalog = data.f
    return JSON.stringify(rep, null, 2)
  }

  return (
    <div className="p-6 md:p-8 max-w-[1440px] mx-auto">
      <div className="mb-5">
        <h1 className="text-2xl font-extrabold tracking-tight text-ink flex items-center gap-2"><FileText size={22} className="text-accent" /> Reports</h1>
        <p className="text-ink2 text-sm mt-1">Scope: <b className="text-ink">{isOrg ? 'Organization' : `Account ${scope}`}</b> · build a scoped export</p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-[1fr_1.2fr] gap-4">
        <Card className="p-5">
          <div className="text-sm font-bold text-ink mb-3">Sections</div>
          <div className="flex flex-col gap-2 mb-5">
            {SECTIONS.map((s) => (
              <label key={s.k} className="flex items-center gap-2.5 text-sm text-ink2 cursor-pointer">
                <input type="checkbox" checked={sections.has(s.k)} onChange={() => toggle(s.k)} className="accent-[var(--accent)]" />
                {s.label}
              </label>
            ))}
          </div>
          <div className="text-sm font-bold text-ink mb-2">Schedule</div>
          <select value={schedule} onChange={(e) => setSchedule(e.target.value)} className="w-full rounded-lg border border-line bg-panel px-3 py-2 text-sm text-ink">
            <option value="none">On demand</option>
            <option value="daily">Daily</option>
            <option value="weekly">Weekly (Mon)</option>
            <option value="monthly">Monthly (1st)</option>
          </select>
          {schedule !== 'none' && <div className="text-[11px] text-ink3 mt-2">Recurring delivery is configured on the hub; the console previews the export here.</div>}
        </Card>

        <Card className="p-5">
          <div className="text-sm font-bold text-ink mb-1">Download</div>
          <div className="text-xs text-ink3 mb-4">{data.f.length} findings · {sections.size} section{sections.size === 1 ? '' : 's'} selected</div>
          <div className="flex flex-col gap-2">
            <button onClick={() => download(`overwatch-${stamp}.json`, buildJson(), 'application/json')} className="flex items-center gap-2 rounded-lg border border-line bg-panel px-4 py-2.5 text-sm font-semibold text-ink hover:border-accent/40">
              <FileJson size={16} className="text-accent" /> JSON report <Download size={14} className="ml-auto text-ink3" />
            </button>
            <button onClick={() => download(`overwatch-${stamp}-findings.csv`, toCsv(data.f), 'text/csv')} className="flex items-center gap-2 rounded-lg border border-line bg-panel px-4 py-2.5 text-sm font-semibold text-ink hover:border-accent/40">
              <FileSpreadsheet size={16} className="text-accent" /> Findings CSV <Download size={14} className="ml-auto text-ink3" />
            </button>
          </div>
          <div className="flex items-start gap-2 mt-4 rounded-lg px-3 py-2.5 text-xs text-ink2" style={{ background: 'var(--panel2)' }}>
            <Info size={14} className="mt-0.5 shrink-0 text-ink3" />
            <span><b>HTML · SARIF 2.1.0 · ASFF</b> are produced by the engine (`save_html` / `save_sarif` / `save_asff`) with the same light theme as this console — available from the hub in live mode.</span>
          </div>
        </Card>
      </div>
    </div>
  )
}

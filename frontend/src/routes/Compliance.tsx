import { useState } from 'react'
import { Link } from 'react-router-dom'
import { ShieldCheck, ChevronDown, ChevronRight } from 'lucide-react'
import { useScope } from '../state/scope'
import { useFetch } from '../lib/useFetch'
import { api } from '../api/client'
import { activeAccountIds } from '../lib/orgdata'
import { Card, Loader, ErrorNote } from '../components/ui'
import { StackBar } from '../components/ui'
import { scoreColor } from '../lib/format'
import type { AccountSummary, ComplianceScorecard, ComplianceFramework } from '../api/types'

function mergeScorecards(sums: AccountSummary[]): ComplianceScorecard {
  const out: Record<string, ComplianceFramework> = {}
  for (const s of sums) {
    for (const [fw, c] of Object.entries(s.compliance_scorecard)) {
      const cur = out[fw] ?? { controls_total: 0, controls_passed: 0, controls_failed: 0, pass_rate: 0, failed_controls: [] }
      cur.controls_total += c.controls_total
      cur.controls_passed += c.controls_passed
      cur.controls_failed += c.controls_failed
      cur.failed_controls = [...cur.failed_controls, ...c.failed_controls]
      out[fw] = cur
    }
  }
  for (const c of Object.values(out)) c.pass_rate = c.controls_total ? Math.round((c.controls_passed / c.controls_total) * 1000) / 10 : 100
  return out
}

export function Compliance() {
  const { scope } = useScope()
  const isOrg = scope === 'org'
  const { data, loading, error } = useFetch<ComplianceScorecard>(
    () => isOrg
      ? activeAccountIds().then((ids) => Promise.all(ids.map((id) => api.accountSummary(id)))).then(mergeScorecards)
      : api.accountSummary(scope).then((s) => s.compliance_scorecard), [scope])
  const [minConf, setMinConf] = useState(80)
  const [open, setOpen] = useState<string | null>(null)

  if (loading) return <Loader />
  if (error) return <ErrorNote msg={error} />
  if (!data) return null
  const frameworks = Object.entries(data)
  const passing = frameworks.filter(([, c]) => c.pass_rate >= minConf).length

  return (
    <div className="p-6 md:p-8 max-w-[1440px] mx-auto">
      <div className="flex items-start justify-between gap-4 mb-5 flex-wrap">
        <div>
          <h1 className="text-2xl font-extrabold tracking-tight text-ink flex items-center gap-2"><ShieldCheck size={22} className="text-accent" /> Compliance</h1>
          <p className="text-ink2 text-sm mt-1">{isOrg ? 'Organization' : `Account ${scope}`} · {passing}/{frameworks.length} frameworks at ≥ {minConf}%</p>
        </div>
        <label className="flex items-center gap-2 text-sm text-ink2">
          Min conformance
          <input type="number" min={0} max={100} value={minConf}
            onChange={(e) => setMinConf(Math.max(0, Math.min(100, Number(e.target.value) || 0)))}
            className="w-16 rounded-lg border border-line bg-panel px-2 py-1 text-sm text-ink text-right tabular-nums" /> %
        </label>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {frameworks.map(([fw, c]) => {
          const pass = c.pass_rate >= minConf
          const isOpen = open === fw
          const failed = [...new Set(c.failed_controls)]
          return (
            <Card key={fw} className="overflow-hidden">
              <div className="p-5">
                <div className="flex items-center justify-between mb-2">
                  <span className="font-bold text-ink">{fw}</span>
                  <span className="text-xs font-bold px-2 py-0.5 rounded-full" style={{ color: pass ? 'var(--low)' : 'var(--crit)', background: pass ? 'var(--lowbg)' : 'var(--critbg)' }}>{pass ? 'Pass' : 'Fail'}</span>
                </div>
                <div className="flex items-end gap-2 mb-2">
                  <span className="text-3xl font-extrabold tabular-nums leading-none" style={{ color: scoreColor(c.pass_rate) }}>{c.pass_rate.toFixed(0)}%</span>
                  <span className="text-xs text-ink3 mb-0.5">{c.controls_passed}/{c.controls_total} controls</span>
                </div>
                <StackBar parts={[{ value: c.controls_passed, color: scoreColor(c.pass_rate) }, { value: c.controls_failed, color: 'var(--line)' }]} />
                {failed.length > 0 && (
                  <button onClick={() => setOpen(isOpen ? null : fw)} className="flex items-center gap-1 text-xs font-semibold text-accent mt-3">
                    {isOpen ? <ChevronDown size={13} /> : <ChevronRight size={13} />} {failed.length} failing control{failed.length === 1 ? '' : 's'}
                  </button>
                )}
              </div>
              {isOpen && (
                <div className="px-5 pb-5 flex gap-1.5 flex-wrap border-t border-line2 pt-3">
                  {failed.map((ctrl, i) => (
                    <Link to="/findings" key={i} className="font-mono text-xs rounded-md px-2 py-1 hover:border-accent/40 border border-line" style={{ background: 'var(--panel2)', color: 'var(--ink2)' }}>{ctrl}</Link>
                  ))}
                </div>
              )}
            </Card>
          )
        })}
      </div>
    </div>
  )
}

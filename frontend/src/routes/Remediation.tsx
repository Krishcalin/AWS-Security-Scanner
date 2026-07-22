import { useState } from 'react'
import { Wrench, Scissors, Star } from 'lucide-react'
import { useScope } from '../state/scope'
import { useFetch } from '../lib/useFetch'
import { api } from '../api/client'
import { Card, Loader, ErrorNote, Empty, Chip, CopyField } from '../components/ui'
import { SeverityChip } from '../components/paths'
import { FindingDetail } from '../components/FindingDetail'
import type { ChokePoint, FindingCatalogEntry } from '../api/types'

const firstSentence = (s: string) => { const m = (s || '').match(/^.*?[.](?:\s|$)/); return m ? m[0].trim() : s }

function ChokeCard({ c }: { c: ChokePoint }) {
  return (
    <Card className="p-4">
      <div className="flex items-center gap-2.5">
        {c.is_true_choke
          ? <Star size={16} className="shrink-0" style={{ color: 'var(--gold)' }} fill="var(--gold)" />
          : <Scissors size={16} className="text-ink3 shrink-0" />}
        <div className="min-w-0 flex-1">
          <div className="text-sm font-bold text-ink truncate">{c.label}</div>
          <div className="text-xs text-ink3">{c.node_kind}{c.account ? ` · ${c.account}` : ''}</div>
        </div>
        <div className="text-right shrink-0">
          <div className="font-mono text-sm font-bold text-ink tabular-nums">{c.paths_severed}/{c.total_paths}</div>
          <div className="text-[10px] text-ink3">paths cut</div>
        </div>
      </div>
      {c.remediation_hint && <p className="text-xs text-ink2 mt-2.5 leading-relaxed">{c.remediation_hint}</p>}
      {c.targets_fully_blocked?.length > 0 && (
        <div className="text-[11px] mt-1.5" style={{ color: 'var(--gold)' }}>Fully protects {c.targets_fully_blocked.length} crown-jewel target{c.targets_fully_blocked.length === 1 ? '' : 's'}</div>
      )}
    </Card>
  )
}

interface RemData { chokes: ChokePoint[]; findings: FindingCatalogEntry[] }

export function Remediation() {
  const { scope } = useScope()
  const isOrg = scope === 'org'
  const { data, loading, error } = useFetch<RemData>(
    () => isOrg
      ? Promise.all([api.orgOverview(), api.orgFindings()]).then(([o, f]) => ({ chokes: o.top_choke_points, findings: f }))
      : Promise.all([api.accountSummary(scope), api.findings(scope)]).then(([s, f]) => ({ chokes: s.choke_points, findings: f })),
    [scope])
  const [open, setOpen] = useState<FindingCatalogEntry | null>(null)

  if (loading) return <Loader />
  if (error) return <ErrorNote msg={error} />
  if (!data) return null
  const { chokes, findings } = data
  const fixable = findings.filter((f) => f.remediation_cmd)
  const totalCut = chokes[0] ? chokes[0].paths_severed : 0
  const totalPaths = chokes[0] ? chokes[0].total_paths : 0

  return (
    <div className="p-6 md:p-8 max-w-[1440px] mx-auto">
      <div className="mb-5">
        <h1 className="text-2xl font-extrabold tracking-tight text-ink flex items-center gap-2"><Wrench size={22} className="text-accent" /> Remediation</h1>
        <p className="text-ink2 text-sm mt-1">{isOrg ? 'Organization' : `Account ${scope}`} · {chokes.length} choke point{chokes.length === 1 ? '' : 's'} · {fixable.length} fixable findings</p>
      </div>

      {chokes.length > 0 && (
        <div className="rounded-2xl px-5 py-4 mb-5" style={{ background: 'var(--accentdim)' }}>
          <div className="text-lg font-bold text-accent">Fix the top {Math.min(3, chokes.length)} choke point{Math.min(3, chokes.length) === 1 ? '' : 's'} first</div>
          <div className="text-sm text-ink2 mt-0.5">The single highest-leverage node severs {totalCut}/{totalPaths} of the critical attack paths — start there, not with the long findings list.</div>
        </div>
      )}

      <h2 className="text-sm font-bold text-ink mb-3 flex items-center gap-1.5"><Scissors size={15} /> Highest-leverage fixes (choke points)</h2>
      {chokes.length === 0 ? (
        <Card><Empty icon={<Scissors size={24} />}>No choke points — no critical attack paths to sever.</Empty></Card>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3 mb-8">
          {chokes.map((c, i) => <ChokeCard key={i} c={c} />)}
        </div>
      )}

      <h2 className="text-sm font-bold text-ink mb-3 flex items-center gap-1.5"><Wrench size={15} /> Fixes by finding</h2>
      {fixable.length === 0 ? (
        <Card><Empty>Nothing to remediate in this scope.</Empty></Card>
      ) : (
        <div className="flex flex-col gap-2">
          {fixable.map((e, i) => (
            <Card key={`${e.account ?? ''}${e.check_id}${i}`} className="p-4">
              <div className="flex items-center gap-2 mb-2.5">
                <SeverityChip sev={e.severity} />
                <span className="font-mono text-sm font-bold text-ink">{e.check_id}</span>
                <span className="hidden sm:inline"><Chip>{e.section}</Chip></span>
                <span className="text-xs text-ink3 flex-1 min-w-0 truncate hidden md:block">{firstSentence(e.risk)}</span>
                {e.account && <span className="font-mono text-[11px] text-ink3 hidden lg:block">{e.account}</span>}
                <button onClick={() => setOpen(e)} className="text-xs font-semibold text-accent shrink-0 ml-auto md:ml-0">Full remediation →</button>
              </div>
              <CopyField text={e.remediation_cmd} />
            </Card>
          ))}
        </div>
      )}

      {open && <FindingDetail e={open} onPath={false} onClose={() => setOpen(null)} />}
    </div>
  )
}

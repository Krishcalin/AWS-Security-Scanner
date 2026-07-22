import { useState, type ReactNode } from 'react'
import { Link } from 'react-router-dom'
import { X, Copy, Check, Ticket, ShieldOff, FileCode2, Waypoints } from 'lucide-react'
import { Chip } from './ui'
import { SeverityChip } from './paths'
import { sevColor } from '../lib/format'
import type { FindingCatalogEntry } from '../api/types'

const SLA: Record<string, string> = { CRITICAL: '7 days', HIGH: '30 days', MEDIUM: '90 days', LOW: '180 days' }

function Label({ children }: { children: ReactNode }) {
  return <div className="text-xs font-semibold uppercase tracking-wide text-ink3">{children}</div>
}
function Prose({ label, children }: { label: string; children: ReactNode }) {
  return <div><Label>{label}</Label><p className="text-sm text-ink2 leading-relaxed mt-1.5">{children}</p></div>
}
function ActionBtn({ icon, children }: { icon: ReactNode; children: ReactNode }) {
  return (
    <button className="flex items-center gap-1.5 rounded-lg border border-line bg-panel px-3 py-2 text-xs font-semibold text-ink2 hover:border-accent/40 hover:text-ink transition-colors">
      {icon}{children}
    </button>
  )
}

function CopyLine({ text }: { text: string }) {
  const [ok, setOk] = useState(false)
  const copy = () => navigator.clipboard?.writeText(text).then(() => { setOk(true); setTimeout(() => setOk(false), 1200) })
  return (
    <div className="flex items-center gap-2 rounded-lg border border-line px-3 py-2" style={{ background: 'var(--panel2)' }}>
      <code className="font-mono text-xs text-ink2 flex-1 overflow-x-auto whitespace-nowrap">{text}</code>
      <button onClick={copy} className="shrink-0 h-7 w-7 grid place-items-center rounded-md hover:bg-panel text-ink3 hover:text-ink">
        {ok ? <Check size={14} style={{ color: 'var(--low)' }} /> : <Copy size={14} />}
      </button>
    </div>
  )
}

export function FindingDetail({ e, onPath, onClose }: { e: FindingCatalogEntry; onPath: boolean; onClose: () => void }) {
  return (
    <div className="fixed inset-0 z-40">
      <div className="absolute inset-0 bg-black/30 backdrop-blur-sm" onClick={onClose} />
      <aside className="absolute right-0 top-0 bottom-0 w-full max-w-[720px] bg-canvas border-l border-line shadow-2xl overflow-y-auto">
        <div className="sticky top-0 z-10 bg-canvas/90 backdrop-blur border-b border-line px-6 py-4 flex items-center gap-3">
          <span className="h-2.5 w-2.5 rounded-full" style={{ background: sevColor(e.severity) }} />
          <span className="font-mono text-lg font-extrabold text-ink">{e.check_id}</span>
          <SeverityChip sev={e.severity} />
          <Chip>{e.section}</Chip>
          <span className="ml-auto flex items-center gap-3">
            <span className="text-xs text-ink3 whitespace-nowrap">SLA {SLA[e.severity] ?? '—'}</span>
            <button onClick={onClose} className="h-8 w-8 grid place-items-center rounded-lg border border-line text-ink3 hover:text-ink"><X size={16} /></button>
          </span>
        </div>

        <div className="p-6 flex flex-col gap-5">
          {onPath && (
            <Link to="/attack-paths" className="flex items-center gap-2 rounded-xl px-4 py-2.5 text-sm font-semibold" style={{ background: 'var(--critbg)', color: 'var(--crit)' }}>
              <Waypoints size={15} /> On a critical attack path — view the path
            </Link>
          )}

          {e.risk && <Prose label="Risk">{e.risk}</Prose>}
          {e.impact && <Prose label="Business impact">{e.impact}</Prose>}

          {e.steps.length > 0 && (
            <div>
              <Label>Remediation — step by step</Label>
              <ol className="flex flex-col gap-2 mt-2">
                {e.steps.map((s, i) => (
                  <li key={i} className="flex gap-3 text-sm text-ink2">
                    <span className="shrink-0 h-5 w-5 rounded-full grid place-items-center text-[11px] font-mono font-bold mt-0.5" style={{ background: 'var(--accentdim)', color: 'var(--accent)' }}>{i + 1}</span>
                    <span className="leading-relaxed">{s}</span>
                  </li>
                ))}
              </ol>
            </div>
          )}

          {e.remediation_cmd && (
            <div><Label>One-line CLI</Label><div className="mt-2"><CopyLine text={e.remediation_cmd} /></div></div>
          )}

          {Object.keys(e.compliance).length > 0 && (
            <div>
              <Label>Frameworks — one fix clears several</Label>
              <div className="flex gap-1.5 flex-wrap mt-2">
                {Object.entries(e.compliance).map(([fw, ctrl]) => (
                  <span key={fw} className="rounded-lg border border-line px-2.5 py-1 text-xs" style={{ background: 'var(--panel2)' }}>
                    <b className="text-ink">{fw}</b> <span className="font-mono text-ink3">{ctrl}</span>
                  </span>
                ))}
              </div>
            </div>
          )}

          <div>
            <Label>Affected resources · {e.distinct}</Label>
            <div className="flex gap-1.5 flex-wrap mt-2">
              {e.affected.map((r, i) => (
                <span key={i} className="font-mono text-xs rounded-md px-2 py-1" style={{ background: 'var(--panel2)', color: 'var(--ink2)' }}>{r}</span>
              ))}
              {e.distinct > e.affected.length && <span className="text-xs text-ink3 self-center">+{e.distinct - e.affected.length} more</span>}
            </div>
          </div>

          <div className="flex gap-2 flex-wrap border-t border-line pt-4">
            <ActionBtn icon={<Ticket size={14} />}>Raise ticket</ActionBtn>
            <ActionBtn icon={<ShieldOff size={14} />}>Waive</ActionBtn>
            <ActionBtn icon={<FileCode2 size={14} />}>View IaC source</ActionBtn>
          </div>
        </div>
      </aside>
    </div>
  )
}

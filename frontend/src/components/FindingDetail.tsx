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
function ActionBtn({ icon, children, onClick, active }: { icon: ReactNode; children: ReactNode; onClick?: () => void; active?: boolean }) {
  return (
    <button onClick={onClick} className="flex items-center gap-1.5 rounded-lg border px-3 py-2 text-xs font-semibold transition-colors"
      style={{ borderColor: active ? 'var(--accent)' : 'var(--line)', background: active ? 'var(--accentdim)' : 'var(--panel)', color: active ? 'var(--accent)' : 'var(--ink2)' }}>
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

export function FindingDetail({ e, onPath, onClose, onWaive }: { e: FindingCatalogEntry; onPath: boolean; onClose: () => void; onWaive?: (checkId: string) => void }) {
  const [panel, setPanel] = useState<'ticket' | 'waive' | 'iac' | null>(null)
  const [ticket, setTicket] = useState<string | null>(null)
  const [waived, setWaived] = useState<string | null>(null)
  const [reason, setReason] = useState('')
  const [expiry, setExpiry] = useState('30d')
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

          <div className="border-t border-line pt-4">
            <div className="flex gap-2 flex-wrap">
              <ActionBtn icon={<Ticket size={14} />} active={panel === 'ticket'} onClick={() => setPanel(panel === 'ticket' ? null : 'ticket')}>Raise ticket</ActionBtn>
              <ActionBtn icon={<ShieldOff size={14} />} active={panel === 'waive'} onClick={() => setPanel(panel === 'waive' ? null : 'waive')}>Waive</ActionBtn>
              <ActionBtn icon={<FileCode2 size={14} />} active={panel === 'iac'} onClick={() => setPanel(panel === 'iac' ? null : 'iac')}>View IaC source</ActionBtn>
            </div>

            {panel === 'ticket' && (
              <div className="mt-3 rounded-xl border border-line p-4">
                {ticket ? (
                  <div className="text-sm text-ink2 flex items-center gap-2"><Check size={15} style={{ color: 'var(--low)' }} /> Created <b className="text-ink font-mono">{ticket}</b> in Jira · SecOps.</div>
                ) : (
                  <>
                    <div className="text-xs font-semibold text-ink mb-1">Create a tracking ticket</div>
                    <div className="text-xs text-ink2 mb-3">Destination <b>Jira · SecOps</b> (project SEC) · priority mapped from <b>{e.severity}</b>.</div>
                    <button onClick={() => setTicket('SEC-' + Math.floor(1000 + Math.random() * 9000))} className="rounded-lg px-3 py-1.5 text-xs font-semibold text-white ow-grad">Create ticket</button>
                  </>
                )}
              </div>
            )}

            {panel === 'waive' && (
              <div className="mt-3 rounded-xl border border-line p-4">
                {waived ? (
                  <div className="text-sm text-ink2 flex items-center gap-2"><Check size={15} style={{ color: 'var(--low)' }} /> Waived {waived === 'never' ? 'with no expiry' : `for ${waived}`}. It stays scored and tracked.</div>
                ) : (
                  <div className="flex flex-col gap-2.5">
                    <div className="text-xs font-semibold text-ink">Waive this finding (approver: you)</div>
                    <input value={reason} onChange={(ev) => setReason(ev.target.value)} placeholder="Reason (required)" className="rounded-lg border border-line bg-panel px-3 py-1.5 text-sm text-ink placeholder:text-ink3 outline-none focus:border-accent/50" />
                    <div className="flex items-center gap-2">
                      <select value={expiry} onChange={(ev) => setExpiry(ev.target.value)} className="rounded-lg border border-line bg-panel px-2 py-1.5 text-sm text-ink">
                        <option value="30d">30 days</option><option value="90d">90 days</option><option value="never">No expiry</option>
                      </select>
                      <button disabled={!reason.trim()} onClick={() => { setWaived(expiry); onWaive?.(e.check_id) }} className="rounded-lg px-3 py-1.5 text-xs font-semibold text-white ow-grad disabled:opacity-50">Waive</button>
                    </div>
                  </div>
                )}
              </div>
            )}

            {panel === 'iac' && (
              <div className="mt-3 rounded-xl border border-line p-4 flex items-start gap-2 text-sm text-ink2">
                <FileCode2 size={15} className="mt-0.5 shrink-0 text-ink3" />
                <span>No IaC repository connected. Connect a Terraform / CloudFormation repo in <b className="text-ink">Settings → Integrations</b> to trace this finding to its source resource and get a diff. Until then, apply the remediation steps above.</span>
              </div>
            )}
          </div>
        </div>
      </aside>
    </div>
  )
}

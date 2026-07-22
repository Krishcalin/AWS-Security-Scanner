import { Scissors, Star } from 'lucide-react'
import { Chip } from './ui'
import { sevColor, sevBg } from '../lib/format'
import { shortLabel } from '../lib/nodes'
import type { AttackPath, ChokePoint } from '../api/types'

export function SeverityChip({ sev }: { sev: string }) {
  return <Chip mono fg={sevColor(sev)} bg={sevBg(sev)}>{sev}</Chip>
}

/** The path badge set — one visual language everywhere a path is shown. */
export function PathBadges({ p }: { p: AttackPath }) {
  return (
    <div className="flex items-center gap-1 flex-wrap">
      {p.kev && <Chip fg="var(--crit)" bg="var(--critbg)">KEV</Chip>}
      {p.active_threat && <Chip fg="var(--high)" bg="var(--highbg)">active threat</Chip>}
      {p.vuln_pivot && <Chip fg="var(--accent)" bg="var(--accentdim)">vuln pivot</Chip>}
      {p.terminal_kind === 'data'
        ? <Chip fg="var(--gold)" bg="var(--goldbg)">crown data</Chip>
        : <Chip fg="var(--crit)" bg="var(--critbg)">admin</Chip>}
      {p.conditioned && <Chip>conditioned</Chip>}
    </div>
  )
}

/** The internet→…→crown/admin chain, rendered with cyan→indigo arrows. */
export function PathChain({ nodes, terminalKind }: { nodes: string[]; terminalKind: string }) {
  return (
    <div className="flex items-center gap-1.5 flex-wrap text-[13px]">
      {nodes.map((n, i) => {
        const last = i === nodes.length - 1
        const crown = last && terminalKind === 'data'
        return (
          <span key={i} className="flex items-center gap-1.5">
            <span className={i === 0 ? 'text-ink3' : 'text-ink'} style={crown ? { color: 'var(--gold)', fontWeight: 600 } : undefined}>
              {shortLabel(n)}
            </span>
            {!last && <span className="ow-grad-text font-bold select-none">→</span>}
          </span>
        )
      })}
    </div>
  )
}

export function ChokeRow({ c, onClick }: { c: ChokePoint; onClick?: () => void }) {
  const Comp = onClick ? 'button' : 'div'
  return (
    <Comp
      onClick={onClick}
      className={`flex w-full items-center gap-3 rounded-xl border border-line2 bg-panel2/40 px-3.5 py-2.5 text-left ${onClick ? 'hover:border-accent/40 transition-colors' : ''}`}
    >
      {c.is_true_choke
        ? <Star size={15} className="shrink-0" style={{ color: 'var(--gold)' }} fill="var(--gold)" />
        : <Scissors size={15} className="text-ink3 shrink-0" />}
      <div className="min-w-0 flex-1">
        <div className="text-sm font-semibold text-ink truncate">{c.label}</div>
        <div className="text-xs text-ink3">{c.node_kind}{c.account ? ` · ${c.account}` : ''}</div>
      </div>
      <div className="text-right shrink-0">
        <div className="font-mono text-sm font-bold text-ink tabular-nums">{c.paths_severed}/{c.total_paths}</div>
        <div className="text-[11px] text-ink3">severed</div>
      </div>
    </Comp>
  )
}

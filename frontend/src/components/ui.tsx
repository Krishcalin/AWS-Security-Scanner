import type { ReactNode } from 'react'
import { Loader2, Inbox, TriangleAlert } from 'lucide-react'
import { sevColor, gradeColor } from '../lib/format'

export const CARD = 'rounded-2xl border border-line bg-panel shadow-sm'

export function Card({ className = '', children }: { className?: string; children: ReactNode }) {
  return <div className={`${CARD} ${className}`}>{children}</div>
}

export function SectionLabel({ n, children }: { n?: string; children: ReactNode }) {
  return (
    <div className="flex items-center gap-2.5 mb-3">
      <span className="h-[3px] w-6 rounded ow-grad" />
      {n && <span className="font-mono text-xs text-ink3 font-semibold">{n}</span>}
      <span className="text-ink2 text-sm">{children}</span>
    </div>
  )
}

export function SevDot({ sev, size = 8 }: { sev: string; size?: number }) {
  return (
    <span
      className="inline-block rounded-full shrink-0"
      style={{ width: size, height: size, background: sevColor(sev) }}
    />
  )
}

export function Chip({ children, fg, bg, mono }: { children: ReactNode; fg?: string; bg?: string; mono?: boolean }) {
  return (
    <span
      className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-semibold whitespace-nowrap ${mono ? 'font-mono' : ''}`}
      style={{ color: fg ?? 'var(--ink2)', background: bg ?? 'var(--panel2)' }}
    >
      {children}
    </span>
  )
}

export function Loader({ label = 'Loading…' }: { label?: string }) {
  return (
    <div className="flex items-center justify-center gap-2 py-16 text-ink3 text-sm">
      <Loader2 size={16} className="animate-spin" />
      {label}
    </div>
  )
}

export function ErrorNote({ msg }: { msg: string }) {
  return (
    <div className="flex items-start gap-2.5 rounded-xl border border-line px-4 py-3 text-sm" style={{ background: 'var(--critbg)', color: 'var(--crit)' }}>
      <TriangleAlert size={16} className="mt-0.5 shrink-0" />
      <div><b>Couldn’t load data.</b> {msg}</div>
    </div>
  )
}

export function Empty({ icon, children }: { icon?: ReactNode; children: ReactNode }) {
  return (
    <div className="flex flex-col items-center justify-center gap-2 py-14 text-ink3 text-sm text-center">
      <div className="text-ink3/70">{icon ?? <Inbox size={26} />}</div>
      {children}
    </div>
  )
}

/** Conic-gradient posture dial (0–100 → A–F), matching the exported report component. */
export function GradeDial({ score, grade, size = 128 }: { score: number; grade: string; size?: number }) {
  const color = gradeColor(grade)
  const deg = Math.max(0, Math.min(360, Math.round((score / 100) * 360)))
  const ring = Math.round(size * 0.09)
  return (
    <div className="relative shrink-0" style={{ width: size, height: size }}>
      <div className="rounded-full h-full w-full" style={{ background: `conic-gradient(${color} ${deg}deg, var(--line) ${deg}deg)` }} />
      <div className="absolute rounded-full bg-panel flex flex-col items-center justify-center" style={{ inset: ring }}>
        <div className="font-mono font-extrabold leading-none" style={{ fontSize: size * 0.34, color }}>{grade}</div>
        <div className="font-mono text-ink3 mt-1 tabular-nums" style={{ fontSize: size * 0.1 }}>{score.toFixed(0)}/100</div>
      </div>
    </div>
  )
}

/** A thin stacked proportion bar (e.g. severity histogram). */
export function StackBar({ parts, height = 9 }: { parts: { value: number; color: string }[]; height?: number }) {
  const total = parts.reduce((a, p) => a + p.value, 0) || 1
  return (
    <div className="flex w-full overflow-hidden rounded-full" style={{ height, background: 'var(--line)' }}>
      {parts.map((p, i) => (
        <span key={i} style={{ width: `${(p.value / total) * 100}%`, background: p.color }} />
      ))}
    </div>
  )
}

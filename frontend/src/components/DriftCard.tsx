import { TrendingUp, TrendingDown, Minus, Waypoints, Clock } from 'lucide-react'
import { useFetch } from '../lib/useFetch'
import { api } from '../api/client'
import { Card, Loader } from './ui'
import { sevColor, scoreColor } from '../lib/format'
import type { TrendRow } from '../api/types'

/** A posture-trend sparkline (SVG polyline over the last N scans, endpoint emphasized). */
function Sparkline({ rows }: { rows: TrendRow[] }) {
  if (rows.length < 2) return null
  const w = 200, h = 40, pad = 3
  const xs = rows.map((_, i) => pad + (i * (w - 2 * pad)) / (rows.length - 1))
  const ys = rows.map((r) => h - pad - (r.posture_score / 100) * (h - 2 * pad))
  const pts = xs.map((x, i) => `${x.toFixed(1)},${ys[i].toFixed(1)}`).join(' ')
  const last = rows[rows.length - 1]
  return (
    <svg width={w} height={h} className="overflow-visible">
      <polyline points={pts} fill="none" stroke={scoreColor(last.posture_score)} strokeWidth={1.8} strokeLinejoin="round" />
      <circle cx={xs[xs.length - 1]} cy={ys[ys.length - 1]} r={2.6} fill={scoreColor(last.posture_score)} />
    </svg>
  )
}

function DeltaTile({ label, value, tone }: { label: string; value: number; tone?: string }) {
  return (
    <div className="rounded-xl border border-line px-3 py-2.5 text-center" style={{ background: 'var(--panel2)' }}>
      <div className="text-xl font-extrabold tabular-nums leading-none" style={{ color: tone ?? 'var(--ink)' }}>{value}</div>
      <div className="text-[11px] text-ink3 mt-1">{label}</div>
    </div>
  )
}

/** "What changed since last scan" — drift counts + posture-delta + trend sparkline for one account. */
export function DriftCard({ account }: { account: string }) {
  const { data: trend, loading } = useFetch<TrendRow[]>(() => api.trend(account), [account])
  if (loading) return <Card className="p-5"><Loader label="Loading drift…" /></Card>
  if (!trend || trend.length === 0) return null
  const cur = trend[trend.length - 1]
  const delta = cur.delta ?? 0
  const DeltaIcon = delta > 0 ? TrendingUp : delta < 0 ? TrendingDown : Minus
  const deltaColor = delta > 0 ? 'var(--low)' : delta < 0 ? 'var(--crit)' : 'var(--ink3)'
  return (
    <Card className="p-5">
      <div className="flex items-center justify-between mb-3">
        <div className="text-sm font-bold text-ink">What changed since last scan</div>
        <div className="flex items-center gap-1.5 text-sm font-bold" style={{ color: deltaColor }}>
          <DeltaIcon size={16} /> {delta > 0 ? '+' : ''}{delta} posture
        </div>
      </div>
      <div className="grid grid-cols-3 gap-2 mb-4">
        <DeltaTile label="new" value={cur.new_count} tone={cur.new_count ? sevColor('HIGH') : undefined} />
        <DeltaTile label="resolved" value={cur.resolved_count} tone={cur.resolved_count ? 'var(--low)' : undefined} />
        <DeltaTile label="reopened" value={cur.reopened_count} tone={cur.reopened_count ? sevColor('CRITICAL') : undefined} />
      </div>
      <div className="flex items-end justify-between">
        <div>
          <div className="text-[11px] text-ink3 mb-1">Posture trend · last {trend.length} scans</div>
          <Sparkline rows={trend} />
        </div>
        <div className="text-right">
          <div className="text-3xl font-extrabold tabular-nums leading-none" style={{ color: scoreColor(cur.posture_score) }}>{cur.posture_score}</div>
          <div className="text-[11px] text-ink3 mt-1">grade {cur.grade} · {cur.total_open} open</div>
        </div>
      </div>
      <div className="flex items-center gap-3 mt-3 text-[11px] text-ink3">
        <span className="flex items-center gap-1"><Waypoints size={11} /> tracked across scans</span>
        <span className="flex items-center gap-1"><Clock size={11} /> continuous cadence</span>
      </div>
    </Card>
  )
}

import { Link } from 'react-router'
import { Radar, ShieldAlert, ShieldCheck, Globe, Gem, AlertTriangle, ArrowRight } from 'lucide-react'
import { useScope, isOrgScope } from '../state/scope'
import { useFetch } from '../lib/useFetch'
import { api } from '../api/client'
import { Card, Loader, ErrorNote, Empty, SevDot } from '../components/ui'
import { nodeMeta } from '../lib/nodes'
import { sevColor } from '../lib/format'
import type { EdrCoverage, OrgEdrCoverage, RuntimeIncident, CoverageGap } from '../api/types'

// exposure rank -> label + severity tone (mirrors aws_edr.compute_coverage: 3 exposed&crown, etc.)
const EXPOSURE = [
  { label: 'Isolated', sev: 'LOW', icon: ShieldCheck },
  { label: 'Internet-reachable', sev: 'MEDIUM', icon: Globe },
  { label: 'Reaches crown data', sev: 'HIGH', icon: Gem },
  { label: 'Exposed & crown-bound', sev: 'CRITICAL', icon: AlertTriangle },
]

function pct(c: { pct: number | null }): string {
  return c.pct === null ? '—' : `${c.pct}%`
}
function covTone(p: number | null): string {
  if (p === null) return 'var(--ink3)'
  return p >= 90 ? 'var(--ok)' : p >= 60 ? 'var(--gold)' : 'var(--crit)'
}

function CoverageRing({ monitored, total, p }: { monitored: number; total: number; p: number | null }) {
  const frac = p === null ? 0 : p / 100
  const R = 34, C = 2 * Math.PI * R
  return (
    <div className="relative h-24 w-24 shrink-0">
      <svg viewBox="0 0 80 80" className="h-24 w-24 -rotate-90">
        <circle cx="40" cy="40" r={R} fill="none" stroke="var(--panel2)" strokeWidth="8" />
        <circle cx="40" cy="40" r={R} fill="none" stroke={covTone(p)} strokeWidth="8" strokeLinecap="round"
          strokeDasharray={`${frac * C} ${C}`} />
      </svg>
      <div className="absolute inset-0 grid place-items-center">
        <div className="text-center leading-none">
          <div className="text-xl font-extrabold tabular-nums" style={{ color: covTone(p) }}>{p === null ? '—' : `${Math.round(p)}%`}</div>
          <div className="text-[10px] text-ink3 mt-0.5 tabular-nums">{monitored}/{total}</div>
        </div>
      </div>
    </div>
  )
}

function GapRow({ g }: { g: CoverageGap }) {
  const M = nodeMeta(g.kind)
  const Icon = M.icon
  const ex = EXPOSURE[Math.max(0, Math.min(3, g.exposure_rank))]
  return (
    <div className="flex items-center gap-3 px-3 py-2 rounded-lg hover:bg-panel2 transition-colors">
      <span className="h-7 w-7 rounded-lg grid place-items-center shrink-0" style={{ background: 'var(--panel2)', color: M.tone }}><Icon size={14} /></span>
      <div className="min-w-0 flex-1">
        <div className="text-sm font-semibold text-ink truncate">{g.label}</div>
        <div className="font-mono text-[11px] text-ink3 truncate">{g.node_id}</div>
      </div>
      <span className="text-xs font-semibold px-2 py-0.5 rounded-full inline-flex items-center gap-1.5 shrink-0"
        style={{ color: sevColor(ex.sev), background: 'var(--panel2)' }}>
        <ex.icon size={12} /> {ex.label}
      </span>
    </div>
  )
}

function IncidentRow({ i }: { i: RuntimeIncident }) {
  const band = (i.priority_band || i.band || 'LOW').toUpperCase()
  return (
    <div className="flex items-center gap-3 px-3 py-2 rounded-lg hover:bg-panel2 transition-colors">
      <SevDot sev={band} />
      <div className="min-w-0 flex-1">
        <div className="text-sm font-semibold text-ink truncate">{i.title || i.type}</div>
        <div className="font-mono text-[11px] text-ink3 truncate">{i.source} · {String(i.node_id ?? i.mapping_status).split('/').pop()}</div>
      </div>
      {i.reachable_from_internet && <Globe size={13} style={{ color: 'var(--gold)' }} aria-label="internet-reachable" />}
      {i.reaches_crown && <Gem size={13} style={{ color: 'var(--crit)' }} aria-label="reaches crown" />}
      <span className="text-xs font-mono tabular-nums font-bold w-8 text-right" style={{ color: sevColor(band) }}>{i.priority_score}</span>
    </div>
  )
}

function Stat({ label, value, tone }: { label: string; value: string; tone?: string }) {
  return (
    <Card className="p-4">
      <div className="text-2xl font-extrabold tabular-nums leading-none" style={{ color: tone ?? 'var(--ink)' }}>{value}</div>
      <div className="text-xs font-semibold uppercase tracking-wide mt-2 text-ink3">{label}</div>
    </Card>
  )
}

// ── org roll-up ───────────────────────────────────────────────────────────────
function OrgRuntime({ data }: { data: OrgEdrCoverage }) {
  const o = data.overall
  return (
    <div className="flex flex-col gap-4">
      <Card className="p-5 flex items-center gap-5">
        <CoverageRing monitored={o.monitored} total={o.total} p={o.pct} />
        <div>
          <div className="text-lg font-bold text-ink">Fleet runtime coverage</div>
          <p className="text-sm text-ink2 mt-1 max-w-lg">{o.monitored} of {o.total} workloads across the org report to a runtime sensor. The rest are runtime blind spots — an attacker's actions there are invisible.</p>
        </div>
      </Card>
      <Card className="p-2">
        <div className="grid grid-cols-[1fr_auto_auto_auto] gap-x-4 px-3 py-2 text-[11px] font-bold uppercase tracking-wide text-ink3">
          <span>Account</span><span className="text-right">Monitored</span><span className="text-right">Coverage</span><span className="text-right">Gaps</span>
        </div>
        {data.accounts.map((a) => (
          <Link key={a.account} to={`/runtime?scope=${a.account}`}
            className="grid grid-cols-[1fr_auto_auto_auto] gap-x-4 items-center px-3 py-2 rounded-lg hover:bg-panel2 transition-colors">
            <span className="font-mono text-sm text-ink truncate">{a.account}</span>
            <span className="text-sm tabular-nums text-ink2 text-right">{a.monitored}/{a.total}</span>
            <span className="text-sm font-bold tabular-nums text-right" style={{ color: covTone(a.pct) }}>{pct(a)}</span>
            <span className="text-sm tabular-nums text-right" style={{ color: a.gap_count ? 'var(--crit)' : 'var(--ink3)' }}>{a.gap_count}</span>
          </Link>
        ))}
      </Card>
    </div>
  )
}

// ── per-account ───────────────────────────────────────────────────────────────
function AccountRuntime({ cov, incidents }: { cov: EdrCoverage; incidents: RuntimeIncident[] }) {
  const o = cov.overall
  const kinds = Object.entries(cov.per_kind).filter(([, v]) => v.total > 0)
  return (
    <div className="flex flex-col gap-4">
      <div className="grid grid-cols-1 lg:grid-cols-[auto_1fr] gap-4">
        <Card className="p-5 flex items-center gap-5">
          <CoverageRing monitored={o.monitored} total={o.total} p={o.pct} />
          <div>
            <div className="text-lg font-bold text-ink">Runtime coverage</div>
            <div className="text-sm text-ink2 mt-1">{o.monitored} of {o.total} workloads sensored · <span style={{ color: cov.gaps.length ? 'var(--crit)' : 'var(--ok)' }}>{cov.gaps.length} gap{cov.gaps.length === 1 ? '' : 's'}</span></div>
          </div>
        </Card>
        <div className="grid grid-cols-3 gap-3">
          {kinds.length === 0
            ? <Card className="p-4 col-span-3"><Empty icon={<Radar size={22} />}>No runtime-hostable workloads in this account.</Empty></Card>
            : kinds.map(([k, v]) => (
              <Stat key={k} label={nodeMeta(k).label} value={pct(v)} tone={covTone(v.pct)} />
            ))}
        </div>
      </div>

      <Card className="p-4">
        <div className="text-xs font-bold uppercase tracking-wide text-ink3 mb-2 flex items-center gap-1.5"><ShieldAlert size={13} /> Coverage gaps — unmonitored workloads (ranked by exposure)</div>
        {cov.gaps.length === 0
          ? <Empty icon={<ShieldCheck size={22} />}>Every runtime-hostable workload reports to a sensor.</Empty>
          : <div className="flex flex-col divide-y divide-line/60">{cov.gaps.map((g) => <GapRow key={g.node_id} g={g} />)}</div>}
      </Card>

      <Card className="p-4">
        <div className="text-xs font-bold uppercase tracking-wide text-ink3 mb-2 flex items-center gap-1.5"><Radar size={13} /> Runtime detections on attack-path workloads</div>
        {incidents.length === 0
          ? <Empty icon={<Radar size={22} />}>No runtime incidents on reachable workloads.</Empty>
          : <div className="flex flex-col divide-y divide-line/60">{incidents.map((i) => <IncidentRow key={i.detection_id} i={i} />)}</div>}
      </Card>
    </div>
  )
}

interface RtData { org: OrgEdrCoverage | null; cov: EdrCoverage | null; inc: RuntimeIncident[] }

export function Runtime() {
  const { scope } = useScope()
  const org = isOrgScope(scope)
  const { data, loading, error } = useFetch<RtData>(
    (): Promise<RtData> => org
      ? api.orgEdrCoverage().then((d) => ({ org: d, cov: null, inc: [] }))
      : Promise.all([api.edrCoverage(scope), api.runtimeIncidents(scope)]).then(([cov, inc]) => ({ org: null, cov, inc })),
    [scope])

  if (loading) return <Loader />
  if (error) return <ErrorNote msg={error} />
  if (!data) return null

  return (
    <div className="p-6 md:p-8 max-w-[1440px] mx-auto">
      <div className="mb-5">
        <h1 className="text-2xl font-extrabold tracking-tight text-ink flex items-center gap-2">
          <Radar size={22} className="text-accent" /> Runtime
        </h1>
        <p className="text-ink2 text-sm mt-1 max-w-3xl">Your existing runtime sensor (CrowdStrike / Falco / GuardDuty-Runtime / OCSF), correlated onto the attack-path graph — which workloads it watches, which it's blind to, and any live detection on a reachable host. OverWatch ingests your sensor; it never runs one. <Link to="/query" className="text-accent font-semibold inline-flex items-center gap-0.5">Query the gaps <ArrowRight size={12} /></Link></p>
      </div>
      {data.org
        ? <OrgRuntime data={data.org} />
        : data.cov && <AccountRuntime cov={data.cov} incidents={data.inc} />}
    </div>
  )
}

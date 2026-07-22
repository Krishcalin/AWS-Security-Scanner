import { useState, type ReactNode } from 'react'
import { Link } from 'react-router-dom'
import { X, ArrowRight, Waypoints, Scissors, Zap, ShieldCheck } from 'lucide-react'
import { useScope } from '../state/scope'
import { useFetch } from '../lib/useFetch'
import { api } from '../api/client'
import { Card, Loader, ErrorNote, Empty } from '../components/ui'
import { SeverityChip, PathBadges, PathChain, ChokeRow } from '../components/paths'
import { PathGraph } from '../components/PathGraph'
import { sevColor } from '../lib/format'
import { shortLabel } from '../lib/nodes'
import type { OrgOverview, AccountSummary, AttackPath, ChokePoint } from '../api/types'

// ── filter pill ───────────────────────────────────────────────────────────────
function Toggle({ active, onClick, children, tone }: { active: boolean; onClick: () => void; children: ReactNode; tone?: string }) {
  return (
    <button
      onClick={onClick}
      className="rounded-lg px-2.5 py-1 text-xs font-semibold border transition-colors"
      style={{
        borderColor: active ? (tone ?? 'var(--accent)') : 'var(--line)',
        background: active ? (tone ? `color-mix(in srgb, ${tone} 12%, transparent)` : 'var(--accentdim)') : 'var(--panel)',
        color: active ? (tone ?? 'var(--accent)') : 'var(--ink2)',
      }}
    >
      {children}
    </button>
  )
}

// ── worklist row ──────────────────────────────────────────────────────────────
function PathCard({ p, onOpen }: { p: AttackPath; onOpen: () => void }) {
  return (
    <button onClick={onOpen} className="w-full text-left rounded-xl border border-line bg-panel p-4 hover:border-accent/50 hover:shadow-sm transition-all">
      <div className="flex items-center gap-2 mb-2">
        <SeverityChip sev={p.severity} />
        <span className="font-mono text-lg font-extrabold tabular-nums leading-none" style={{ color: sevColor(p.severity) }}>{Math.round(p.score)}</span>
        <div className="ml-1"><PathBadges p={p} /></div>
        {p.account && <span className="ml-auto font-mono text-[11px] text-ink3">{p.account}</span>}
      </div>
      <PathChain nodes={p.nodes} terminalKind={p.terminal_kind} />
      <div className="text-xs text-ink3 mt-2 line-clamp-2">{p.rationale}</div>
      <div className="flex items-center justify-between mt-2.5">
        {p.driving_findings?.length > 0 ? (
          <div className="flex items-center gap-1.5 flex-wrap">
            {p.driving_findings.slice(0, 4).map((f, i) => (
              <span key={i} className="font-mono text-[10px] rounded px-1.5 py-0.5" style={{ background: 'var(--panel2)', color: 'var(--ink2)' }}>{f}</span>
            ))}
          </div>
        ) : <span />}
        <span className="flex items-center gap-1 text-accent text-xs font-semibold shrink-0">Explore <ArrowRight size={12} /></span>
      </div>
    </button>
  )
}

// ── score breakdown ───────────────────────────────────────────────────────────
const FACTOR_ROWS: { key: string; label: string; hint: string }[] = [
  { key: 'exposure', label: 'Exposure', hint: 'internet reachability' },
  { key: 'exploitability', label: 'Exploitability', hint: 'CVE / KEV on the path' },
  { key: 'privilege', label: 'Privilege', hint: 'escalation to admin' },
  { key: 'impact', label: 'Impact', hint: 'crown-jewel data reached' },
  { key: 'reach', label: 'Reach', hint: 'network + service reachability' },
  { key: 'boost', label: 'Boost', hint: 'active-threat / KEV multiplier' },
]

function FactorBar({ label, hint, value }: { label: string; hint: string; value: number }) {
  const pct = Math.min(100, (value / 2) * 100)
  return (
    <div>
      <div className="flex items-center justify-between text-xs mb-1">
        <span className="font-semibold text-ink">{label} <span className="font-normal text-ink3">· {hint}</span></span>
        <span className="font-mono tabular-nums text-ink2">{value.toFixed(2)}×</span>
      </div>
      <div className="h-1.5 w-full rounded-full overflow-hidden" style={{ background: 'var(--line)' }}>
        <span className="block h-full rounded-full" style={{ width: `${pct}%`, background: value >= 1 ? 'var(--accent)' : 'var(--med)' }} />
      </div>
    </div>
  )
}

// ── detail slide-over ─────────────────────────────────────────────────────────
function PathDetail({ p, chokes, onClose }: { p: AttackPath; chokes: ChokePoint[]; onClose: () => void }) {
  const onPath = chokes.filter((c) => p.nodes.includes(c.node_id))
  return (
    <div className="fixed inset-0 z-40">
      <div className="absolute inset-0 bg-black/30 backdrop-blur-sm" onClick={onClose} />
      <aside className="absolute right-0 top-0 bottom-0 w-full max-w-[780px] bg-canvas border-l border-line shadow-2xl overflow-y-auto">
        {/* header */}
        <div className="sticky top-0 z-10 bg-canvas/90 backdrop-blur border-b border-line px-6 py-4 flex items-center gap-3">
          <SeverityChip sev={p.severity} />
          <span className="font-mono text-2xl font-extrabold tabular-nums" style={{ color: sevColor(p.severity) }}>{Math.round(p.score)}</span>
          <div className="leading-tight">
            <div className="text-sm font-bold text-ink">Attack path</div>
            <div className="text-xs text-ink3">to {shortLabel(p.terminal)} · {p.terminal_kind === 'data' ? 'crown-jewel data' : 'admin'}</div>
          </div>
          <button onClick={onClose} className="ml-auto h-8 w-8 grid place-items-center rounded-lg border border-line text-ink3 hover:text-ink">
            <X size={16} />
          </button>
        </div>

        <div className="p-6 flex flex-col gap-5">
          <div><PathBadges p={p} /></div>

          <div>
            <div className="text-xs font-semibold uppercase tracking-wide text-ink3 mb-2">Blast path</div>
            <PathGraph path={p} height={280} />
            <div className="mt-2"><PathChain nodes={p.nodes} terminalKind={p.terminal_kind} /></div>
          </div>

          <Card className="p-5">
            <div className="flex items-center justify-between mb-3">
              <div className="text-sm font-bold text-ink">Why this score</div>
              <span className="font-mono text-sm font-extrabold tabular-nums" style={{ color: sevColor(p.severity) }}>{Math.round(p.score)}/100</span>
            </div>
            <div className="text-[11px] font-mono text-ink3 mb-4 rounded-lg px-3 py-2" style={{ background: 'var(--panel2)' }}>
              score = exposure × exploitability × max(privilege, impact) × reach × boost, clamped 0–100
            </div>
            <div className="flex flex-col gap-3">
              {FACTOR_ROWS.map((f) => <FactorBar key={f.key} label={f.label} hint={f.hint} value={Number(p.factors?.[f.key] ?? 0)} />)}
            </div>
            <div className="flex gap-2 flex-wrap mt-4">
              {p.hard_floor_applied && <span className="text-[11px] rounded px-2 py-1 font-semibold" style={{ background: 'var(--critbg)', color: 'var(--crit)' }}>KEV + data hard floor applied</span>}
              {p.conditioned && <span className="text-[11px] rounded px-2 py-1 font-semibold" style={{ background: 'var(--medbg)', color: 'var(--med)' }}>conditioned — score capped</span>}
              {p.vuln_pivot && <span className="text-[11px] rounded px-2 py-1 font-semibold" style={{ background: 'var(--accentdim)', color: 'var(--accent)' }}>vulnerability pivot gate</span>}
            </div>
            <p className="text-sm text-ink2 mt-4 leading-relaxed">{p.rationale}</p>
          </Card>

          {p.driving_findings?.length > 0 && (
            <div>
              <div className="text-xs font-semibold uppercase tracking-wide text-ink3 mb-2">Driving findings</div>
              <div className="flex gap-1.5 flex-wrap">
                {p.driving_findings.map((f, i) => (
                  <Link key={i} to="/findings" className="font-mono text-xs rounded-lg px-2 py-1 hover:border-accent/40 border border-line" style={{ background: 'var(--panel)', color: 'var(--ink2)' }}>{f}</Link>
                ))}
              </div>
            </div>
          )}

          <div>
            <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wide text-ink3 mb-2">
              <Scissors size={13} /> Sever this path
            </div>
            {onPath.length === 0 ? (
              <div className="text-sm text-ink3 rounded-xl border border-line2 px-4 py-3">No single choke point on this path.</div>
            ) : (
              <div className="flex flex-col gap-2">
                {onPath.map((c, i) => <ChokeRow key={i} c={c} />)}
                <Link to="/remediation" className="flex items-center gap-1.5 text-sm font-semibold text-accent hover:underline mt-1">
                  Open remediation plan <ArrowRight size={14} />
                </Link>
              </div>
            )}
          </div>
        </div>
      </aside>
    </div>
  )
}

// ── page ──────────────────────────────────────────────────────────────────────
export function AttackPaths() {
  const { scope } = useScope()
  const isOrg = scope === 'org'
  const { data, loading, error } = useFetch<OrgOverview | AccountSummary>(
    () => (isOrg ? api.orgOverview() : api.accountSummary(scope)), [scope])

  const [sev, setSev] = useState<Set<string>>(new Set())
  const [kevOnly, setKevOnly] = useState(false)
  const [threatOnly, setThreatOnly] = useState(false)
  const [dataOnly, setDataOnly] = useState(false)
  const [uncondOnly, setUncondOnly] = useState(false)
  const [open, setOpen] = useState<AttackPath | null>(null)

  if (loading) return <Loader />
  if (error) return <ErrorNote msg={error} />
  if (!data) return null

  const paths: AttackPath[] = isOrg ? (data as OrgOverview).top_attack_paths : (data as AccountSummary).attack_paths
  const chokes: ChokePoint[] = isOrg ? (data as OrgOverview).top_choke_points : (data as AccountSummary).choke_points

  const toggleSev = (s: string) => setSev((cur) => { const n = new Set(cur); n.has(s) ? n.delete(s) : n.add(s); return n })
  const filtered = paths.filter((p) => {
    if (sev.size && !sev.has(p.severity)) return false
    if (kevOnly && !p.kev) return false
    if (threatOnly && !p.active_threat) return false
    if (dataOnly && p.terminal_kind !== 'data') return false
    if (uncondOnly && p.conditioned) return false
    return true
  })
  const nCrit = paths.filter((p) => p.severity === 'CRITICAL').length
  const topChoke = chokes[0]

  return (
    <div className="p-6 md:p-8 max-w-[1440px] mx-auto">
      <div className="mb-5">
        <h1 className="text-2xl font-extrabold tracking-tight text-ink flex items-center gap-2">
          <Waypoints size={22} className="text-accent" /> Attack Paths
        </h1>
        <p className="text-ink2 text-sm mt-1">
          {isOrg ? 'Organization' : `Account ${scope}`} · {filtered.length} of {paths.length} ranked toxic-combination path{paths.length === 1 ? '' : 's'} · {nCrit} critical
        </p>
      </div>

      {/* filters */}
      <div className="flex items-center gap-2 flex-wrap mb-5">
        {(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const).map((s) => (
          <Toggle key={s} active={sev.has(s)} onClick={() => toggleSev(s)} tone={sevColor(s)}>{s}</Toggle>
        ))}
        <span className="w-px h-5 mx-1" style={{ background: 'var(--line)' }} />
        <Toggle active={kevOnly} onClick={() => setKevOnly((v) => !v)} tone="var(--crit)">KEV only</Toggle>
        <Toggle active={threatOnly} onClick={() => setThreatOnly((v) => !v)} tone="var(--high)"><Zap size={11} className="inline -mt-0.5" /> active threat</Toggle>
        <Toggle active={dataOnly} onClick={() => setDataOnly((v) => !v)} tone="var(--gold)">to crown data</Toggle>
        <Toggle active={uncondOnly} onClick={() => setUncondOnly((v) => !v)}>unconditioned</Toggle>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-[1.7fr_1fr] gap-4">
        {/* worklist */}
        <div className="flex flex-col gap-3">
          {filtered.length === 0 ? (
            <Card><Empty icon={<Waypoints size={28} />}>{paths.length === 0 ? 'No attack paths — clean across this scope.' : 'No paths match the current filters.'}</Empty></Card>
          ) : (
            filtered.map((p, i) => <PathCard key={i} p={p} onOpen={() => setOpen(p)} />)
          )}
        </div>

        {/* choke rail */}
        <div className="flex flex-col gap-3">
          <Card className="p-0">
            <div className="px-5 pt-4 pb-3 flex items-center justify-between">
              <h2 className="text-[15px] font-bold text-ink flex items-center gap-1.5"><Scissors size={15} /> Choke points</h2>
              <Link to="/remediation" className="text-xs font-semibold text-accent hover:underline">Remediate</Link>
            </div>
            <div className="px-5 pb-5 flex flex-col gap-2.5">
              {topChoke && (
                <div className="rounded-xl px-4 py-3" style={{ background: 'var(--accentdim)' }}>
                  <div className="text-sm font-bold text-accent">Fix {Math.min(3, chokes.length)} to cut the most paths</div>
                  <div className="text-xs text-ink2 mt-0.5">Top choke severs {topChoke.paths_severed}/{topChoke.total_paths} paths</div>
                </div>
              )}
              {chokes.length === 0 ? <Empty icon={<Scissors size={24} />}>No choke points.</Empty>
                : chokes.slice(0, 6).map((c, i) => <ChokeRow key={i} c={c} />)}
            </div>
          </Card>

          <Card className="p-5">
            <div className="flex items-center gap-2 text-sm font-bold text-ink mb-2"><ShieldCheck size={15} className="text-accent" /> How paths are scored</div>
            <p className="text-xs text-ink2 leading-relaxed">
              Every path is ranked by a <b className="text-ink">gated-multiplicative</b> score — internet exposure × exploitability × privilege/impact × reachability × threat boost. Any missing factor collapses the path, so a high-CVSS-but-unreachable finding never floats to the top. Open a path to see its factor breakdown.
            </p>
          </Card>
        </div>
      </div>

      {open && <PathDetail p={open} chokes={chokes} onClose={() => setOpen(null)} />}
    </div>
  )
}

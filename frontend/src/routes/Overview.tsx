import type { ReactNode } from 'react'
import { Link } from 'react-router-dom'
import { Waypoints, Gem, ShieldCheck, CircleAlert, Cloud, ArrowRight, Scissors, ShieldAlert, Flame } from 'lucide-react'
import { useScope } from '../state/scope'
import { useFetch } from '../lib/useFetch'
import { api } from '../api/client'
import { Card, GradeDial, Loader, ErrorNote, Empty, SevDot, StackBar } from '../components/ui'
import { SeverityChip, PathBadges, PathChain, ChokeRow } from '../components/paths'
import { DriftCard } from '../components/DriftCard'
import { SEVERITIES, sevColor, scoreColor, gradeColor } from '../lib/format'
import type { OrgOverview as TOrg, AccountSummary, AttackPath, IngestedVuln } from '../api/types'

/** External-CVE reachability roll-up — renders only when the account has ingested
 *  scanner output, so it never adds noise to accounts with no external scans. */
function VulnRollup({ id }: { id: string }) {
  const { data } = useFetch<IngestedVuln[]>(() => api.listVulns(id).catch(() => []), [id])
  const rows = data ?? []
  if (rows.length === 0) return null
  const reachable = rows.filter((v) => v.on_attack_path && !v.suppressed).length
  const kevReach = rows.filter((v) => v.kev && v.on_attack_path && !v.suppressed).length
  return (
    <Link to="/vulnerabilities" className="group block">
      <Card className="p-4 flex items-center gap-4 hover:border-accent/40 transition-colors">
        <span className="h-10 w-10 rounded-xl grid place-items-center shrink-0" style={{ background: 'var(--panel2)', color: 'var(--crit)' }}><ShieldAlert size={20} /></span>
        <div className="flex-1 min-w-0">
          <div className="text-sm font-bold text-ink">External vulnerabilities · reachability-ranked</div>
          <div className="text-xs text-ink3 mt-0.5">{rows.length} CVE{rows.length === 1 ? '' : 's'} owned from SARIF/CycloneDX/SPDX uploads</div>
        </div>
        <div className="flex items-center gap-5">
          <div className="text-center"><div className="text-2xl font-extrabold tabular-nums" style={{ color: 'var(--high)' }}>{reachable}</div><div className="text-[10px] text-ink3 flex items-center gap-1"><Waypoints size={10} /> reachable</div></div>
          <div className="text-center"><div className="text-2xl font-extrabold tabular-nums" style={{ color: 'var(--crit)' }}>{kevReach}</div><div className="text-[10px] text-ink3 flex items-center gap-1"><Flame size={10} /> reachable KEV</div></div>
          <ArrowRight size={16} className="text-ink3 opacity-0 group-hover:opacity-100 transition-opacity" />
        </div>
      </Card>
    </Link>
  )
}

const scoreToGrade = (s: number) => (s >= 90 ? 'A' : s >= 80 ? 'B' : s >= 70 ? 'C' : s >= 60 ? 'D' : 'F')

function Page({ title, sub, children }: { title: string; sub: string; children: ReactNode }) {
  return (
    <div className="p-6 md:p-8 max-w-[1440px] mx-auto">
      <div className="mb-6">
        <h1 className="text-2xl font-extrabold tracking-tight text-ink">{title}</h1>
        <p className="text-ink2 text-sm mt-1">{sub}</p>
      </div>
      {children}
    </div>
  )
}

/** A deep-linking Top-N tile — click-through to its pre-filtered screen. */
function Tile({ to, icon, label, value, sub, tone = 'var(--accent)' }: {
  to: string; icon: ReactNode; label: string; value: ReactNode; sub?: string; tone?: string
}) {
  return (
    <Link to={to} className={`${'group'} rounded-2xl border border-line bg-panel shadow-sm p-4 flex flex-col gap-2 hover:border-accent/40 transition-colors`}>
      <div className="flex items-center justify-between">
        <span className="h-8 w-8 rounded-lg grid place-items-center" style={{ background: 'var(--panel2)', color: tone }}>{icon}</span>
        <ArrowRight size={15} className="text-ink3 opacity-0 group-hover:opacity-100 transition-opacity" />
      </div>
      <div className="text-3xl font-extrabold tabular-nums leading-none" style={{ color: tone }}>{value}</div>
      <div>
        <div className="text-sm font-semibold text-ink">{label}</div>
        {sub && <div className="text-xs text-ink3 mt-0.5">{sub}</div>}
      </div>
    </Link>
  )
}

function PathRow({ p }: { p: AttackPath }) {
  return (
    <Link to="/attack-paths" className="block rounded-xl border border-line2 hover:border-accent/40 bg-panel2/40 px-3.5 py-3 transition-colors">
      <div className="flex items-center gap-2 mb-1.5">
        <SeverityChip sev={p.severity} />
        <span className="font-mono text-sm font-bold tabular-nums" style={{ color: sevColor(p.severity) }}>{Math.round(p.score)}</span>
        <div className="ml-1"><PathBadges p={p} /></div>
        {p.account && <span className="ml-auto font-mono text-[11px] text-ink3">{p.account}</span>}
      </div>
      <PathChain nodes={p.nodes} terminalKind={p.terminal_kind} />
      <div className="text-xs text-ink3 mt-1.5 line-clamp-1">{p.rationale}</div>
    </Link>
  )
}

function PanelHead({ title, to, cta }: { title: string; to?: string; cta?: string }) {
  return (
    <div className="flex items-center justify-between px-5 pt-4 pb-3">
      <h2 className="text-[15px] font-bold text-ink">{title}</h2>
      {to && <Link to={to} className="text-xs font-semibold text-accent hover:underline flex items-center gap-1">{cta ?? 'View all'} <ArrowRight size={12} /></Link>}
    </div>
  )
}

// ── ORG SCOPE ────────────────────────────────────────────────────────────────
function OrgView() {
  const { data, loading, error } = useFetch(() => api.orgOverview(), [])
  if (loading) return <Loader />
  if (error) return <ErrorNote msg={error} />
  if (!data) return null
  const o: TOrg = data
  const grade = scoreToGrade(o.org_posture_score)
  const topChoke = o.top_choke_points[0]
  const cutPct = topChoke && topChoke.total_paths ? Math.round((topChoke.paths_severed / topChoke.total_paths) * 100) : 0

  return (
    <Page title="Security Overview" sub={`Organization · ${o.accounts_scanned} account${o.accounts_scanned === 1 ? '' : 's'} scanned`}>
      {/* hero */}
      <div className="grid grid-cols-1 lg:grid-cols-[auto_1fr] gap-4 mb-4">
        <Card className="p-5 flex items-center gap-5">
          <GradeDial score={o.org_posture_score} grade={grade} />
          <div>
            <div className="text-xs font-semibold uppercase tracking-wide text-ink3">Org posture</div>
            <div className="text-4xl font-extrabold tabular-nums" style={{ color: scoreColor(o.org_posture_score) }}>{o.org_posture_score.toFixed(1)}</div>
            <div className="flex gap-3 mt-2 text-xs">
              <span><b className="text-ink">{o.summary.FAIL}</b> <span className="text-ink3">fail</span></span>
              <span><b className="text-ink">{o.summary.WARN}</b> <span className="text-ink3">warn</span></span>
              <span><b className="text-ink">{o.summary.PASS}</b> <span className="text-ink3">pass</span></span>
            </div>
          </div>
        </Card>
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
          <Tile to="/attack-paths" icon={<Waypoints size={17} />} tone="var(--crit)" value={o.critical_attack_paths} label="Critical attack paths" sub="ranked toxic combinations" />
          <Tile to="/inventory" icon={<Gem size={17} />} tone="var(--gold)" value={o.crown_jewels_at_risk} label="Crown jewels at risk" sub="reachable sensitive data" />
          <Tile to="/remediation" icon={<Scissors size={17} />} tone="var(--accent)" value={topChoke ? `${cutPct}%` : '—'} label="Top choke leverage" sub={topChoke ? `fix 1 → cut ${cutPct}% of paths` : 'no choke points'} />
          <Tile to="/accounts" icon={<Cloud size={17} />} tone="var(--info)" value={o.accounts_scanned} label="Accounts" sub="onboarded & scanning" />
        </div>
      </div>

      {/* paths + chokes */}
      <div className="grid grid-cols-1 lg:grid-cols-[1.6fr_1fr] gap-4 mb-4">
        <Card>
          <PanelHead title="Top attack paths" to="/attack-paths" />
          <div className="px-5 pb-5 flex flex-col gap-2.5">
            {o.top_attack_paths.length === 0 ? <Empty icon={<Waypoints size={26} />}>No attack paths — clean across the org.</Empty>
              : o.top_attack_paths.slice(0, 5).map((p, i) => <PathRow key={i} p={p} />)}
          </div>
        </Card>
        <Card>
          <PanelHead title="Choke points" to="/remediation" cta="Remediate" />
          <div className="px-5 pb-5 flex flex-col gap-2.5">
            {topChoke && (
              <div className="rounded-xl px-4 py-3 mb-1" style={{ background: 'var(--accentdim)' }}>
                <div className="text-sm font-bold text-accent">Fix {Math.min(3, o.top_choke_points.length)} to cut the most paths</div>
                <div className="text-xs text-ink2 mt-0.5">Top choke severs {topChoke.paths_severed}/{topChoke.total_paths} critical paths</div>
              </div>
            )}
            {o.top_choke_points.length === 0 ? <Empty icon={<Scissors size={24} />}>No choke points.</Empty>
              : o.top_choke_points.slice(0, 4).map((c, i) => <ChokeRow key={i} c={c} />)}
          </div>
        </Card>
      </div>

      {/* accounts by posture */}
      <Card>
        <PanelHead title="Accounts by posture" to="/accounts" cta="Manage" />
        <div className="px-3 pb-3">
          {o.accounts.map((a) => (
            <div key={a.account} className="flex items-center gap-3 px-2.5 py-2.5 rounded-lg hover:bg-panel2 transition-colors">
              <span className="h-2.5 w-2.5 rounded-full shrink-0" style={{ background: scoreColor(a.posture_score ?? 100) }} />
              <span className="font-mono text-sm text-ink w-32">{a.account}</span>
              <span className="text-xs text-ink3 w-24">{a.region}</span>
              <div className="flex-1 max-w-xs"><StackBar parts={[{ value: a.posture_score ?? 0, color: scoreColor(a.posture_score ?? 100) }, { value: 100 - (a.posture_score ?? 0), color: 'var(--line)' }]} /></div>
              <span className="font-mono text-sm font-bold tabular-nums w-12 text-right" style={{ color: scoreColor(a.posture_score ?? 100) }}>{(a.posture_score ?? 0).toFixed(0)}</span>
              <span className="text-xs text-ink3 w-24 text-right">{a.critical_paths} crit path{a.critical_paths === 1 ? '' : 's'}</span>
            </div>
          ))}
        </div>
      </Card>
    </Page>
  )
}

// ── ACCOUNT SCOPE ────────────────────────────────────────────────────────────
function AccountView({ id }: { id: string }) {
  const { data, loading, error } = useFetch(() => api.accountSummary(id), [id])
  if (loading) return <Loader />
  if (error) return <ErrorNote msg={error} />
  if (!data) return null
  const s: AccountSummary = data
  const totalFindings = SEVERITIES.reduce((a, sv) => a + (s.severity_counts[sv] || 0), 0)
  const topChoke = s.choke_points[0]

  return (
    <Page title="Security Overview" sub={`Account ${s.account} · ${s.region}`}>
      <div className="grid grid-cols-1 lg:grid-cols-[auto_1fr_1.1fr] gap-4 mb-4">
        <Card className="p-5 flex items-center gap-5">
          <GradeDial score={s.posture_score} grade={s.posture_grade} />
          <div>
            <div className="text-xs font-semibold uppercase tracking-wide text-ink3">Posture</div>
            <div className="text-4xl font-extrabold tabular-nums" style={{ color: gradeColor(s.posture_grade) }}>{s.posture_score.toFixed(0)}</div>
            <div className="text-xs text-ink3 mt-1">{s.summary.FAIL} fail · {s.summary.WARN} warn · {s.summary.PASS} pass</div>
          </div>
        </Card>

        <Card className="p-5">
          <div className="flex items-center justify-between mb-3">
            <div className="text-sm font-bold text-ink">Findings by severity</div>
            <Link to="/findings" className="text-xs font-semibold text-accent hover:underline">{totalFindings} open</Link>
          </div>
          <StackBar height={10} parts={SEVERITIES.map((sv) => ({ value: s.severity_counts[sv] || 0, color: sevColor(sv) }))} />
          <div className="grid grid-cols-4 gap-2 mt-4">
            {SEVERITIES.map((sv) => (
              <Link to="/findings" key={sv} className="rounded-lg px-2.5 py-2 hover:bg-panel2 transition-colors" style={{ background: 'var(--panel2)' }}>
                <div className="flex items-center gap-1.5"><SevDot sev={sv} /><span className="text-[11px] font-semibold text-ink2 capitalize">{sv.toLowerCase()}</span></div>
                <div className="text-xl font-extrabold tabular-nums mt-0.5" style={{ color: sevColor(sv) }}>{s.severity_counts[sv] || 0}</div>
              </Link>
            ))}
          </div>
        </Card>

        <Card className="p-5">
          <div className="flex items-center justify-between mb-3">
            <div className="text-sm font-bold text-ink">Attack surface</div>
            <Link to="/attack-paths" className="text-xs font-semibold text-accent hover:underline">Explore</Link>
          </div>
          <div className="grid grid-cols-2 gap-3">
            <Link to="/attack-paths" className="rounded-lg px-3 py-3 hover:bg-panel2 transition-colors" style={{ background: 'var(--critbg)' }}>
              <div className="text-2xl font-extrabold tabular-nums" style={{ color: 'var(--crit)' }}>{s.attack_paths.length}</div>
              <div className="text-xs font-semibold text-ink2">attack paths</div>
            </Link>
            <Link to="/remediation" className="rounded-lg px-3 py-3 hover:bg-panel2 transition-colors" style={{ background: 'var(--accentdim)' }}>
              <div className="text-2xl font-extrabold tabular-nums text-accent">{s.choke_points.length}</div>
              <div className="text-xs font-semibold text-ink2">choke points</div>
            </Link>
            <div className="rounded-lg px-3 py-3" style={{ background: 'var(--panel2)' }}>
              <div className="text-2xl font-extrabold tabular-nums text-ink">{s.graph?.nodes ?? 0}</div>
              <div className="text-xs font-semibold text-ink3">graph nodes</div>
            </div>
            <div className="rounded-lg px-3 py-3" style={{ background: 'var(--panel2)' }}>
              <div className="text-2xl font-extrabold tabular-nums text-ink">{s.graph?.edges ?? 0}</div>
              <div className="text-xs font-semibold text-ink3">relationships</div>
            </div>
          </div>
        </Card>
      </div>

      <div className="mb-4"><VulnRollup id={id} /></div>
      <div className="mb-4"><DriftCard account={id} /></div>

      <div className="grid grid-cols-1 lg:grid-cols-[1.6fr_1fr] gap-4">
        <Card>
          <PanelHead title="Top attack paths" to="/attack-paths" />
          <div className="px-5 pb-5 flex flex-col gap-2.5">
            {s.attack_paths.length === 0 ? <Empty icon={<Waypoints size={26} />}>No attack paths for this account.</Empty>
              : s.attack_paths.slice(0, 5).map((p, i) => <PathRow key={i} p={p} />)}
          </div>
        </Card>

        <Card>
          <PanelHead title="Compliance" to="/compliance" />
          <div className="px-5 pb-5 flex flex-col gap-3">
            {Object.entries(s.compliance_scorecard).map(([fw, c]) => (
              <Link to="/compliance" key={fw} className="block group">
                <div className="flex items-center justify-between mb-1">
                  <span className="text-sm font-semibold text-ink flex items-center gap-1.5"><ShieldCheck size={13} className="text-ink3" />{fw}</span>
                  <span className="font-mono text-xs tabular-nums" style={{ color: scoreColor(c.pass_rate) }}>{c.pass_rate.toFixed(0)}%</span>
                </div>
                <StackBar parts={[{ value: c.controls_passed, color: scoreColor(c.pass_rate) }, { value: c.controls_failed, color: 'var(--line)' }]} />
                <div className="text-[11px] text-ink3 mt-1">{c.controls_passed}/{c.controls_total} controls · {c.controls_failed} failing</div>
              </Link>
            ))}
            {topChoke && (
              <div className="rounded-xl px-4 py-3 mt-1" style={{ background: 'var(--accentdim)' }}>
                <div className="text-xs font-bold text-accent flex items-center gap-1.5"><CircleAlert size={13} />Fastest win</div>
                <div className="text-xs text-ink2 mt-0.5">Fix <b className="text-ink">{topChoke.label}</b> → severs {topChoke.paths_severed}/{topChoke.total_paths} paths</div>
              </div>
            )}
          </div>
        </Card>
      </div>
    </Page>
  )
}

export function Overview() {
  const { scope } = useScope()
  return scope === 'org' ? <OrgView /> : <AccountView id={scope} />
}

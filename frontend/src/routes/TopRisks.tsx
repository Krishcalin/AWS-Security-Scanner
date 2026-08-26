/**
 * TopRisks — the category grid: the worst ten in each risk domain, on one screen.
 *
 * The reference dashboard this answers puts a single 0–10 number on every row. We do
 * not have one and do not invent one: see lib/toprisks.ts. A row shows a REAL number
 * when a real number exists (an attack-path score, or a published CVSS) and its
 * severity band when it does not, with the basis stated on the badge.
 */
import { useMemo, useState } from 'react'
import { Link } from 'react-router'
import { ArrowRight, Info, LayoutGrid, ScanLine } from 'lucide-react'
import { useScope } from '../state/scope'
import { useFetch } from '../lib/useFetch'
import { api } from '../api/client'
import { Card, Loader, ErrorNote, Empty, Chip } from '../components/ui'
import { FindingDetail } from '../components/FindingDetail'
import { sevColor, sevBg } from '../lib/format'
import { shortLabel } from '../lib/nodes'
import { useDeepLinkPanel } from '../lib/deeplink'
import { topRisks, type CategoryResult, type TopRiskRow } from '../lib/toprisks'
import type {
  FindingCatalogEntry, AttackPath, IngestedVuln, OrgOverview, AccountSummary,
} from '../api/types'

// ── the score badge ─────────────────────────────────────────────────────────
// Three states, and the third is the point: no number, because there is no number.
function ScoreBadge({ row }: { row: TopRiskRow }) {
  const c = sevColor(row.severity)
  const bg = sevBg(row.severity)
  if (row.score === null) {
    return (
      <div className="w-[52px] shrink-0 rounded-lg px-1.5 py-1 text-center leading-none"
        style={{ background: bg }}>
        <div className="font-mono text-[10px] font-extrabold tracking-tight" style={{ color: c }}>
          {row.severity.slice(0, 4)}
        </div>
        <div className="text-[8px] font-semibold mt-0.5" style={{ color: 'var(--ink3)' }}>band</div>
      </div>
    )
  }
  const shown = row.basis === 'path' ? Math.round(row.score) : row.score.toFixed(1)
  return (
    <div className="w-[52px] shrink-0 rounded-lg px-1.5 py-1 text-center leading-none"
      style={{ background: bg }}
      title={row.basis === 'path'
        ? 'Attack-path score (0–100) — exposure × exploitability × privilege/impact × reach'
        : 'Published CVSS base score for the worst CVE on an affected resource'}>
      <div className="font-mono text-[15px] font-extrabold tabular-nums" style={{ color: c }}>{shown}</div>
      <div className="text-[8px] font-bold uppercase tracking-wide mt-0.5" style={{ color: c, opacity: 0.8 }}>
        {row.basis === 'path' ? 'path' : 'cvss'}
      </div>
    </div>
  )
}

// ── one row ─────────────────────────────────────────────────────────────────
function Row({ row, onOpen }: { row: TopRiskRow; onOpen: () => void }) {
  const open = (row.status || '').toUpperCase() !== 'PASS'
  return (
    <button
      onClick={onOpen}
      className="w-full flex items-center gap-2.5 px-3 py-2 text-left border-l-2 hover:bg-panel2/60 transition-colors"
      style={{ borderColor: sevColor(row.severity) }}
    >
      <ScoreBadge row={row} />
      <div className="min-w-0 flex-1">
        <div className="font-mono text-[11px] font-bold text-ink truncate">{row.check_id}</div>
        <div className="text-[10px] text-ink3 truncate">{row.section || '—'}</div>
      </div>
      <div className="min-w-0 w-[38%] hidden sm:block">
        <div className="text-[11px] text-ink2 truncate" title={row.asset}>
          {row.asset ? shortLabel(row.asset) : <span className="text-ink3 italic">account-scoped</span>}
        </div>
        <div className="text-[10px] text-ink3 truncate">
          {row.assetCount > 1 ? `${row.assetCount} resources` : row.asset ? '1 resource' : '—'}
        </div>
      </div>
      <div className="shrink-0 text-right">
        <div className="text-[11px] font-semibold" style={{ color: open ? sevColor(row.severity) : 'var(--low)' }}>
          {open ? 'Open' : 'Pass'}
        </div>
        {row.account && <div className="font-mono text-[9px] text-ink3">{row.account}</div>}
      </div>
    </button>
  )
}

// ── one category card ───────────────────────────────────────────────────────
function CategoryCard({ r, onOpenRow }: { r: CategoryResult; onOpenRow: (key: string) => void }) {
  const Icon = r.cat.icon
  return (
    <Card className="flex flex-col overflow-hidden">
      <header className="flex items-center gap-2 px-4 py-3 border-b border-line2">
        <Icon size={15} className="text-accent shrink-0" />
        <h2 className="text-[13px] font-bold text-ink truncate">Top 10 {r.cat.title}</h2>
        <span className="font-mono text-[10px] text-ink3 tabular-nums">
          {r.total > r.rows.length ? `${r.rows.length}/${r.total}` : r.total}
        </span>
        {r.cat.seeAll && (
          <Link to={r.cat.seeAll}
            className="ml-auto flex items-center gap-1 text-[11px] font-semibold text-accent hover:underline shrink-0">
            See all <ArrowRight size={11} />
          </Link>
        )}
      </header>

      {r.rows.length === 0 ? (
        <div className="px-4 py-6 text-center">
          <p className="text-xs text-ink3 leading-relaxed">
            No findings in this category for this scope.
            <br />
            <span className="text-[11px]">That is an absence of findings, not a proof of safety —
            checks that were denied or skipped appear under Coverage.</span>
          </p>
        </div>
      ) : (
        <div className="divide-y" style={{ borderColor: 'var(--line2)' }}>
          {r.rows.map((row) => <Row key={row.key} row={row} onOpen={() => onOpenRow(row.key)} />)}
        </div>
      )}
    </Card>
  )
}

// ── the page ────────────────────────────────────────────────────────────────
export function TopRisks() {
  const { scope } = useScope()
  const isOrg = scope === 'org'
  const [showRule, setShowRule] = useState(false)
  const [openId, setOpenId] = useDeepLinkPanel('detail')

  const { data, loading, error } = useFetch<{
    catalog: FindingCatalogEntry[]; paths: AttackPath[]; vulns: IngestedVuln[]
  }>(async () => {
    const [catalog, paths, vulns] = await Promise.all([
      isOrg ? api.orgFindings() : api.findings(scope),
      (isOrg
        ? api.orgOverview().then((o: OrgOverview) => o.top_attack_paths)
        : api.accountSummary(scope).then((s: AccountSummary) => s.attack_paths)
      ).catch(() => [] as AttackPath[]),
      (isOrg ? api.orgVulns() : api.listVulns(scope)).catch(() => [] as IngestedVuln[]),
    ])
    return { catalog, paths: paths ?? [], vulns: vulns ?? [] }
  }, [scope])

  const results = useMemo(
    () => (data ? topRisks(data.catalog, data.paths, data.vulns) : []), [data])

  const keyOf = (e: FindingCatalogEntry) => `${e.account ?? ''}::${e.check_id}`
  const open = openId && data ? (data.catalog.find((e) => keyOf(e) === openId) ?? null) : null
  const onPathIds = useMemo(() => {
    const s = new Set<string>()
    for (const p of data?.paths ?? []) for (const d of p.driving_findings ?? []) s.add(d.split(':')[0])
    return s
  }, [data])

  if (loading) return <Loader />
  if (error) return <ErrorNote msg={error} />
  if (!data) return null

  const totalShown = results.reduce((n, r) => n + r.rows.length, 0)

  return (
    <div className="p-6 md:p-8 max-w-[1600px] mx-auto">
      <div className="flex flex-wrap items-start gap-3 mb-5">
        <div>
          <h1 className="text-2xl font-extrabold tracking-tight text-ink flex items-center gap-2">
            <LayoutGrid size={22} className="text-accent" /> Top Risks by Category
          </h1>
          <p className="text-ink2 text-sm mt-1 max-w-3xl">
            The worst ten in each risk domain, ranked by what OverWatch actually measured.
          </p>
          <p className="text-ink3 text-xs mt-1">
            {isOrg ? 'Organization' : `Account ${scope}`} · {data.catalog.length} finding
            {data.catalog.length === 1 ? '' : 's'} across {results.length} categories · {totalShown} shown
          </p>
        </div>
        <button
          onClick={() => setShowRule((v) => !v)}
          className="ml-auto flex items-center gap-1.5 rounded-lg border border-line px-3 py-1.5 text-xs font-semibold text-ink2 hover:text-ink hover:border-accent/40 transition-colors"
        >
          <Info size={13} /> How rows are ranked
        </button>
      </div>

      {showRule && (
        <Card className="p-5 mb-5">
          <h2 className="text-sm font-bold text-ink mb-2">There is no single risk number, so none is shown</h2>
          <p className="text-sm text-ink2 leading-relaxed mb-3">
            A finding carries a severity band, the resources it affects, and nothing numeric.
            Printing a 0–10 next to it would be inventing a precision the scan never produced,
            so a row shows a number only when a real one exists, and says which kind:
          </p>
          <div className="flex flex-col gap-2">
            <div className="flex items-start gap-3">
              <Chip mono fg="var(--crit)" bg="var(--critbg)">path</Chip>
              <p className="text-xs text-ink2 leading-relaxed flex-1">
                <b className="text-ink">0–100.</b> The score of the attack path this finding drives —
                exposure × exploitability × max(privilege, impact) × reach × threat boost. The only
                whole-risk number the product computes, and the one that outranks everything else,
                because it is the only one that accounts for whether anything can reach the flaw.
              </p>
            </div>
            <div className="flex items-start gap-3">
              <Chip mono fg="var(--high)" bg="var(--highbg)">cvss</Chip>
              <p className="text-xs text-ink2 leading-relaxed flex-1">
                <b className="text-ink">0–10, as published.</b> The base score of the worst CVE on an
                affected resource. Ingested, not derived — and deliberately ranked below a path
                score, since CVSS describes a component in isolation and says nothing about
                reachability.
              </p>
            </div>
            <div className="flex items-start gap-3">
              <Chip mono>band</Chip>
              <p className="text-xs text-ink2 leading-relaxed flex-1">
                <b className="text-ink">No number.</b> The severity band is what is known. These rows
                fall below the scored ones and are ordered by severity, then by how many resources
                they touch.
              </p>
            </div>
          </div>
        </Card>
      )}

      {data.catalog.length === 0 ? (
        <Card><Empty icon={<ScanLine size={26} />}>No findings in this scope yet — run a scan.</Empty></Card>
      ) : (
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
          {results.map((r) => <CategoryCard key={r.cat.slug} r={r} onOpenRow={setOpenId} />)}
        </div>
      )}

      {open && (
        <FindingDetail e={open} onPath={onPathIds.has(open.check_id)} onClose={() => setOpenId(null)} />
      )}
    </div>
  )
}

import { useScope } from '../state/scope'
import { useFetch } from '../lib/useFetch'
import { api } from '../api/client'
import { Card, Loader, ErrorNote, Empty } from '../components/ui'
import { FindingDetail } from '../components/FindingDetail'
import { FindingRow } from './Findings'
import { sevColor } from '../lib/format'
import { useDeepLinkPanel } from '../lib/deeplink'
import { findingInDashboard, type DashboardSpec } from '../lib/dashboards'
import type { FindingCatalogEntry, OrgOverview, AccountSummary } from '../api/types'

const SEVS = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const

// A named roll-up over the finding_catalog for one risk domain. Same data as /findings,
// scoped to the dashboard's check-id prefixes — a dedicated, deep-linkable surface.
export function CategoryDashboard({ spec }: { spec: DashboardSpec }) {
  const { scope } = useScope()
  const isOrg = scope === 'org'
  const Icon = spec.icon
  const { data, loading, error } = useFetch<FindingCatalogEntry[]>(
    () => (isOrg ? api.orgFindings() : api.findings(scope)), [scope, spec.slug])
  const paths = useFetch<string[]>(
    () => (isOrg ? api.orgOverview().then((o: OrgOverview) => o.top_attack_paths)
      : api.accountSummary(scope).then((s: AccountSummary) => s.attack_paths))
      .then((ps) => {
        const set = new Set<string>()
        ps.forEach((p) => p.driving_findings.forEach((df) => set.add(df.split(':')[0])))
        return [...set]
      }), [scope])
  const [openId, setOpenId] = useDeepLinkPanel('detail')

  if (loading) return <Loader />
  if (error) return <ErrorNote msg={error} />
  if (!data) return null

  // In ORG scope the same check_id appears once per account, so key the open detail on
  // account+check_id — else clicking account B's row opens account A's (sorted-first) finding.
  const keyOf = (e: FindingCatalogEntry) => (e.account ? `${e.account}::${e.check_id}` : e.check_id)
  const rows = data.filter((e) => findingInDashboard(e, spec))
  const onPathSet = new Set(paths.data ?? [])
  const open = openId ? (data.find((e) => keyOf(e) === openId) ?? null) : null
  const counts = SEVS.map((s) => ({ sev: s, n: rows.filter((r) => r.severity === s).length }))

  return (
    <div className="p-6 md:p-8 max-w-[1440px] mx-auto">
      <div className="mb-5">
        <h1 className="text-2xl font-extrabold tracking-tight text-ink flex items-center gap-2">
          <Icon size={22} className="text-accent" /> {spec.title}
        </h1>
        <p className="text-ink2 text-sm mt-1 max-w-3xl">{spec.blurb}</p>
        <p className="text-ink3 text-xs mt-1">{isOrg ? 'Organization' : `Account ${scope}`} · {rows.length} finding{rows.length === 1 ? '' : 's'}</p>
      </div>

      {/* severity roll-up tiles */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-5">
        {counts.map(({ sev, n }) => (
          <Card key={sev} className="p-4">
            <div className="text-3xl font-extrabold tabular-nums leading-none" style={{ color: n ? sevColor(sev) : 'var(--ink3)' }}>{n}</div>
            <div className="text-xs font-semibold uppercase tracking-wide mt-2" style={{ color: 'var(--ink3)' }}>{sev}</div>
          </Card>
        ))}
      </div>

      {rows.length === 0 ? (
        <Card><Empty icon={<Icon size={26} />}>{data.length === 0 ? 'No findings — clean across this scope.' : `No ${spec.title.toLowerCase()} findings in this scope.`}</Empty></Card>
      ) : (
        <div className="flex flex-col gap-2">
          {rows.map((e, i) => (
            <FindingRow key={`${e.account ?? ''}${e.check_id}${i}`} e={e}
              onPath={onPathSet.has(e.check_id)} onOpen={() => setOpenId(keyOf(e))} />
          ))}
        </div>
      )}

      {open && <FindingDetail e={open} onPath={onPathSet.has(open.check_id)} onClose={() => setOpenId(null)} />}
    </div>
  )
}

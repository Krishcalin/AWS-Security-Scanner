import { useState, type ReactNode } from 'react'
import { ChevronRight, ChevronDown, Search, Waypoints, CircleAlert } from 'lucide-react'
import { useScope } from '../state/scope'
import { useFetch } from '../lib/useFetch'
import { api } from '../api/client'
import { Card, Loader, ErrorNote, Empty, SevDot, Chip } from '../components/ui'
import { FindingDetail } from '../components/FindingDetail'
import { sevColor } from '../lib/format'
import { useDeepLinkPanel } from '../lib/deeplink'
import { capNote } from '../lib/cap'
import { Link } from 'react-router'
import { pathLinks } from '../lib/deeplink'
import type { PathLink } from '../lib/deeplink'
import type { FindingCatalogEntry, OrgOverview, AccountSummary } from '../api/types'

type Source = 'all' | 'misconfig' | 'vuln' | 'data'

function sourceOf(e: FindingCatalogEntry): Exclude<Source, 'all'> {
  const s = (e.section || '').toUpperCase()
  const c = (e.check_id || '').toUpperCase()
  if (['VULN', 'WINVULN', 'CWPP', 'THREAT'].includes(s) || /^(VULN|CWPP|WINVULN|CNT-02)/.test(c)) return 'vuln'
  if (s === 'DATA' || /^(DSPM|EXTACCESS)/.test(c)) return 'data'
  return 'misconfig'
}

const TABS: { key: Source; label: string }[] = [
  { key: 'all', label: 'All' },
  { key: 'misconfig', label: 'Misconfigurations' },
  { key: 'vuln', label: 'Vulnerabilities' },
  { key: 'data', label: 'Data' },
]

const firstSentence = (s: string) => { const m = (s || '').match(/^.*?[.](?:\s|$)/); return m ? m[0].trim() : s }

function Pill({ active, onClick, children, tone }: { active: boolean; onClick: () => void; children: ReactNode; tone?: string }) {
  return (
    <button onClick={onClick} className="rounded-lg px-2.5 py-1 text-xs font-semibold border transition-colors"
      style={{
        borderColor: active ? (tone ?? 'var(--accent)') : 'var(--line)',
        background: active ? (tone ? `color-mix(in srgb, ${tone} 12%, transparent)` : 'var(--accentdim)') : 'var(--panel)',
        color: active ? (tone ?? 'var(--accent)') : 'var(--ink2)',
      }}>
      {children}
    </button>
  )
}

export function FindingRow({ e, onPath, onOpen, dataTour }: { e: FindingCatalogEntry; onPath: PathLink | null; onOpen: () => void; dataTour?: string }) {
  const [exp, setExp] = useState(false)
  return (
    <div data-tour={dataTour} className="rounded-xl border border-line bg-panel hover:border-accent/40 transition-colors">
      <div className="flex items-center gap-3 px-4 py-3 cursor-pointer" onClick={onOpen}>
        <SevDot sev={e.severity} />
        <span className="font-mono text-sm font-bold text-ink w-24 shrink-0">{e.check_id}</span>
        <span className="hidden sm:inline"><Chip>{e.section}</Chip></span>
        <span className="text-sm text-ink2 flex-1 min-w-0 truncate">{firstSentence(e.risk)}</span>
        {onPath && (
          // The marker used to be inert: it sat inside the row's onClick, so
          // clicking it opened the finding detail and never the graph. Reaching
          // the path cost a context switch at exactly the moment of triage.
          <Link
            to={`/attack-paths?path=${encodeURIComponent(onPath.id)}`}
            onClick={(ev: React.MouseEvent) => ev.stopPropagation()}
            title={onPath.count > 1
              ? `On ${onPath.count} attack paths — open the highest-ranked`
              : 'On an attack path — open it'}
            aria-label={onPath.count > 1
              ? `On ${onPath.count} attack paths, open the highest-ranked`
              : 'On an attack path, open it'}
            className="shrink-0 rounded p-0.5 hover:bg-panel2 focus:outline-none focus:ring-1 focus:ring-accent"
          >
            <Waypoints size={14} style={{ color: 'var(--crit)' }} />
          </Link>
        )}
        <div className="hidden md:flex gap-1 items-center">
          {Object.keys(e.compliance).slice(0, 3).map((fw) => (
            <span key={fw} className="text-[10px] font-semibold text-ink3 rounded px-1.5 py-0.5" style={{ background: 'var(--panel2)' }}>{fw}</span>
          ))}
          {capNote(3, Object.keys(e.compliance).length) && (
            <span className="text-[10px] text-ink3" title={Object.keys(e.compliance).join(', ')}>
              {capNote(3, Object.keys(e.compliance).length)}
            </span>
          )}
        </div>
        {e.account && <span className="font-mono text-[11px] text-ink3 w-28 hidden lg:block truncate">{e.account}</span>}
        <span className="text-xs text-ink3 w-16 text-right shrink-0 tabular-nums">{e.distinct} res</span>
        <button onClick={(ev) => { ev.stopPropagation(); setExp((v) => !v) }} className="h-6 w-6 grid place-items-center text-ink3 hover:text-ink shrink-0">
          {exp ? <ChevronDown size={16} /> : <ChevronRight size={16} />}
        </button>
      </div>
      {exp && (
        <div className="px-4 pb-3 flex gap-1.5 flex-wrap border-t border-line2 pt-2.5">
          <span className="text-xs text-ink3 mr-1 self-center">Affected:</span>
          {e.affected.map((r, i) => (
            <span key={i} className="font-mono text-xs rounded-md px-2 py-1" style={{ background: 'var(--panel2)', color: 'var(--ink2)' }}>{r}</span>
          ))}
          {e.distinct > e.affected.length && <span className="text-xs text-ink3 self-center">+{e.distinct - e.affected.length} more</span>}
        </div>
      )}
    </div>
  )
}

export function Findings() {
  const { scope } = useScope()
  const isOrg = scope === 'org'
  const { data, loading, error } = useFetch<FindingCatalogEntry[]>(
    () => (isOrg ? api.orgFindings() : api.findings(scope)), [scope])
  // check_id -> the highest-ranked path it drives, plus how many it drives in all.
  // Paths arrive ranked, so the FIRST path to claim a check is the one worth
  // opening; later ones only increment the count. Keeping the count is what lets
  // the marker avoid implying the linked path is the only one.
  const paths = useFetch<Record<string, PathLink>>(
    () => (isOrg ? api.orgOverview().then((o: OrgOverview) => o.top_attack_paths)
      : api.accountSummary(scope).then((s: AccountSummary) => s.attack_paths))
      .then(pathLinks), [scope])

  const [tab, setTab] = useState<Source>('all')
  const [q, setQ] = useState('')
  const [sev, setSev] = useState<Set<string>>(new Set())
  const [onPathOnly, setOnPathOnly] = useState(false)
  const [group, setGroup] = useState<'none' | 'section' | 'severity'>('none')
  // open finding lives in the URL (?detail=<check_id>) — shareable + tour-drivable.
  const [openId, setOpenId] = useDeepLinkPanel('detail')
  const [waived, setWaived] = useState<Set<string>>(new Set())

  if (loading) return <Loader />
  if (error) return <ErrorNote msg={error} />
  if (!data) return null

  // resolve from the FULL catalog, not the filtered rows, so a deep link opens a
  // finding even when the active tab/severity/on-path filters would hide it.
  const open = openId ? (data.find((e) => e.check_id === openId) ?? null) : null

  const pathBy = paths.data ?? {}
  const linkFor = (e: FindingCatalogEntry): PathLink | null => pathBy[e.check_id] ?? null
  const isOnPath = (e: FindingCatalogEntry) => linkFor(e) !== null
  const counts: Record<Source, number> = { all: data.length, misconfig: 0, vuln: 0, data: 0 }
  data.forEach((e) => { counts[sourceOf(e)]++ })

  const ql = q.trim().toLowerCase()
  const filtered = data.filter((e) => {
    if (waived.has(e.check_id)) return false
    if (tab !== 'all' && sourceOf(e) !== tab) return false
    if (sev.size && !sev.has(e.severity)) return false
    if (onPathOnly && !isOnPath(e)) return false
    if (ql && !(`${e.check_id} ${e.section} ${e.risk} ${e.affected.join(' ')}`.toLowerCase().includes(ql))) return false
    return true
  })

  const toggleSev = (s: string) => setSev((c) => { const n = new Set(c); n.has(s) ? n.delete(s) : n.add(s); return n })

  // grouping
  const groups: { key: string; items: FindingCatalogEntry[] }[] = (() => {
    if (group === 'none') return [{ key: '', items: filtered }]
    const m = new Map<string, FindingCatalogEntry[]>()
    for (const e of filtered) {
      const k = group === 'section' ? e.section : e.severity
      if (!m.has(k)) m.set(k, [])
      m.get(k)!.push(e)
    }
    const order = group === 'severity' ? ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] : [...m.keys()].sort()
    return order.filter((k) => m.has(k)).map((k) => ({ key: k, items: m.get(k)! }))
  })()

  return (
    <div className="p-6 md:p-8 max-w-[1440px] mx-auto">
      <div className="mb-4">
        <h1 className="text-2xl font-extrabold tracking-tight text-ink flex items-center gap-2">
          <CircleAlert size={22} className="text-accent" /> Findings
        </h1>
        <p className="text-ink2 text-sm mt-1">{isOrg ? 'Organization' : `Account ${scope}`} · {filtered.length} of {data.length} findings</p>
      </div>

      {/* source sub-tabs */}
      <div data-tour="findings-tabs" className="flex items-center gap-1 border-b border-line mb-4">
        {TABS.map((t) => (
          <button key={t.key} onClick={() => setTab(t.key)}
            className="relative px-3.5 py-2 text-sm font-semibold transition-colors"
            style={{ color: tab === t.key ? 'var(--accent)' : 'var(--ink2)' }}>
            {t.label} <span className="text-xs text-ink3 font-normal">{counts[t.key]}</span>
            {tab === t.key && <span className="absolute left-2 right-2 -bottom-px h-[2px] rounded ow-grad" />}
          </button>
        ))}
      </div>

      {/* toolbar */}
      <div className="flex items-center gap-2 flex-wrap mb-4">
        <div data-tour="findings-search" className="relative">
          <Search size={14} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-ink3" />
          <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search check, section, resource…"
            className="rounded-lg border border-line bg-panel pl-8 pr-3 py-1.5 text-sm text-ink placeholder:text-ink3 outline-none focus:border-accent/50 w-64" />
        </div>
        {(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const).map((s) => (
          <Pill key={s} active={sev.has(s)} onClick={() => toggleSev(s)} tone={sevColor(s)}>{s}</Pill>
        ))}
        <Pill active={onPathOnly} onClick={() => setOnPathOnly((v) => !v)} tone="var(--crit)"><Waypoints size={11} className="inline -mt-0.5" /> on attack path</Pill>
        <span className="w-px h-5 mx-1" style={{ background: 'var(--line)' }} />
        <span className="text-xs text-ink3">Group</span>
        {(['none', 'section', 'severity'] as const).map((g) => (
          <Pill key={g} active={group === g} onClick={() => setGroup(g)}>{g === 'none' ? 'flat' : g}</Pill>
        ))}
      </div>

      {/* list */}
      {filtered.length === 0 ? (
        <Card><Empty icon={<CircleAlert size={26} />}>{data.length === 0 ? 'No findings — clean across this scope.' : 'No findings match the current filters.'}</Empty></Card>
      ) : (
        <div className="flex flex-col gap-4">
          {groups.map((grp, gi) => (
            <div key={grp.key} className="flex flex-col gap-2">
              {grp.key && (
                <div className="flex items-center gap-2 px-1">
                  {group === 'severity' && <SevDot sev={grp.key} />}
                  <span className="text-sm font-bold text-ink">{grp.key}</span>
                  <span className="text-xs text-ink3">{grp.items.length}</span>
                </div>
              )}
              {grp.items.map((e, i) => (
                <FindingRow key={`${e.account ?? ''}${e.check_id}${i}`} e={e} onPath={linkFor(e)}
                  dataTour={gi === 0 && i === 0 ? 'finding-row-0' : undefined} onOpen={() => setOpenId(e.check_id)} />
              ))}
            </div>
          ))}
        </div>
      )}

      {open && <FindingDetail e={open} onPath={isOnPath(open)} onClose={() => setOpenId(null)} onWaive={(cid) => { setWaived((s) => new Set(s).add(cid)); setOpenId(null) }} />}
    </div>
  )
}

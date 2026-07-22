import { useState, type ReactNode } from 'react'
import { ChevronRight, ChevronDown, Search, Waypoints, CircleAlert } from 'lucide-react'
import { useScope } from '../state/scope'
import { useFetch } from '../lib/useFetch'
import { api } from '../api/client'
import { Card, Loader, ErrorNote, Empty, SevDot, Chip } from '../components/ui'
import { FindingDetail } from '../components/FindingDetail'
import { sevColor } from '../lib/format'
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

function FindingRow({ e, onPath, onOpen }: { e: FindingCatalogEntry; onPath: boolean; onOpen: () => void }) {
  const [exp, setExp] = useState(false)
  return (
    <div className="rounded-xl border border-line bg-panel hover:border-accent/40 transition-colors">
      <div className="flex items-center gap-3 px-4 py-3 cursor-pointer" onClick={onOpen}>
        <SevDot sev={e.severity} />
        <span className="font-mono text-sm font-bold text-ink w-24 shrink-0">{e.check_id}</span>
        <span className="hidden sm:inline"><Chip>{e.section}</Chip></span>
        <span className="text-sm text-ink2 flex-1 min-w-0 truncate">{firstSentence(e.risk)}</span>
        {onPath && <Waypoints size={14} style={{ color: 'var(--crit)' }} aria-label="On attack path" />}
        <div className="hidden md:flex gap-1">
          {Object.keys(e.compliance).slice(0, 3).map((fw) => (
            <span key={fw} className="text-[10px] font-semibold text-ink3 rounded px-1.5 py-0.5" style={{ background: 'var(--panel2)' }}>{fw}</span>
          ))}
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
  const paths = useFetch<string[]>(
    () => (isOrg ? api.orgOverview().then((o: OrgOverview) => o.top_attack_paths)
      : api.accountSummary(scope).then((s: AccountSummary) => s.attack_paths))
      .then((ps) => {
        const set = new Set<string>()
        ps.forEach((p) => p.driving_findings.forEach((df) => set.add(df.split(':')[0])))
        return [...set]
      }), [scope])

  const [tab, setTab] = useState<Source>('all')
  const [q, setQ] = useState('')
  const [sev, setSev] = useState<Set<string>>(new Set())
  const [onPathOnly, setOnPathOnly] = useState(false)
  const [group, setGroup] = useState<'none' | 'section' | 'severity'>('none')
  const [open, setOpen] = useState<FindingCatalogEntry | null>(null)
  const [waived, setWaived] = useState<Set<string>>(new Set())

  if (loading) return <Loader />
  if (error) return <ErrorNote msg={error} />
  if (!data) return null

  const onPathSet = new Set(paths.data ?? [])
  const isOnPath = (e: FindingCatalogEntry) => onPathSet.has(e.check_id)
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
      <div className="flex items-center gap-1 border-b border-line mb-4">
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
        <div className="relative">
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
          {groups.map((grp) => (
            <div key={grp.key} className="flex flex-col gap-2">
              {grp.key && (
                <div className="flex items-center gap-2 px-1">
                  {group === 'severity' && <SevDot sev={grp.key} />}
                  <span className="text-sm font-bold text-ink">{grp.key}</span>
                  <span className="text-xs text-ink3">{grp.items.length}</span>
                </div>
              )}
              {grp.items.map((e, i) => (
                <FindingRow key={`${e.account ?? ''}${e.check_id}${i}`} e={e} onPath={isOnPath(e)} onOpen={() => setOpen(e)} />
              ))}
            </div>
          ))}
        </div>
      )}

      {open && <FindingDetail e={open} onPath={isOnPath(open)} onClose={() => setOpen(null)} onWaive={(cid) => { setWaived((s) => new Set(s).add(cid)); setOpen(null) }} />}
    </div>
  )
}

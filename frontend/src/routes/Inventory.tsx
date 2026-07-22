import { useState } from 'react'
import { Boxes, List, Network, Gem, ChevronRight, ChevronDown, Search } from 'lucide-react'
import { useScope } from '../state/scope'
import { useFetch } from '../lib/useFetch'
import { api } from '../api/client'
import { loadGraph } from '../lib/orgdata'
import { Card, Loader, ErrorNote, Empty, SevDot } from '../components/ui'
import { nodeMeta, shortLabel } from '../lib/nodes'
import { sevColor } from '../lib/format'
import type { GNode, FindingCatalogEntry } from '../api/types'

const EXCLUDE = new Set(['InternetSource', 'AdminCapability', 'Vulnerability', 'ThreatFinding', 'InstanceProfile'])
const RANK: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 }

interface Res { id: string; kind: string; name: string; region: string; account: string; crown: boolean; count: number; worst: string }

function parseRegion(id: string): string {
  const s = id.startsWith('lb/') ? id.slice(3) : id
  const p = s.split(':')
  return p[0] === 'arn' && p.length >= 4 && p[3] ? p[3] : 'global'
}

function ResRow({ r }: { r: Res }) {
  const M = nodeMeta(r.kind)
  const Icon = M.icon
  return (
    <div className="flex items-center gap-3 px-3 py-2 rounded-lg hover:bg-panel2 transition-colors">
      <span className="h-7 w-7 rounded-lg grid place-items-center shrink-0" style={{ background: 'var(--panel2)', color: M.tone }}><Icon size={14} /></span>
      <div className="min-w-0 flex-1">
        <div className="text-sm font-semibold text-ink truncate flex items-center gap-1.5">{r.name}{r.crown && <Gem size={12} style={{ color: 'var(--gold)' }} aria-label="crown jewel" />}</div>
        <div className="font-mono text-[11px] text-ink3 truncate">{r.id}</div>
      </div>
      <span className="text-xs text-ink3 w-24 hidden md:block">{r.region}</span>
      {r.count > 0
        ? <span className="text-xs font-semibold px-2 py-0.5 rounded-full flex items-center gap-1.5" style={{ color: sevColor(r.worst), background: 'var(--panel2)' }}><SevDot sev={r.worst} />{r.count}</span>
        : <span className="text-xs text-ink3 w-8 text-right">—</span>}
    </div>
  )
}

export function Inventory() {
  const { scope } = useScope()
  const isOrg = scope === 'org'
  const { data, loading, error } = useFetch(
    () => Promise.all([loadGraph(scope), isOrg ? api.orgFindings() : api.findings(scope)])
      .then(([g, f]) => ({ g, f: f as FindingCatalogEntry[] })), [scope])
  const [view, setView] = useState<'list' | 'tree'>('list')
  const [q, setQ] = useState('')
  const [openKeys, setOpenKeys] = useState<Set<string>>(new Set())

  if (loading) return <Loader />
  if (error) return <ErrorNote msg={error} />
  if (!data) return null

  const fmap = new Map<string, { count: number; sevs: string[] }>()
  for (const e of data.f) for (const r of e.affected) {
    const cur = fmap.get(r) ?? { count: 0, sevs: [] }; cur.count++; cur.sevs.push(e.severity); fmap.set(r, cur)
  }
  const worst = (sevs: string[]) => [...sevs].sort((a, b) => (RANK[a] ?? 9) - (RANK[b] ?? 9))[0] ?? ''

  let resources: Res[] = (data.g.nodes as (GNode & { account?: unknown })[]).filter((n) => !EXCLUDE.has(n.kind)).map((n) => {
    const name = typeof n.name === 'string' ? n.name : shortLabel(n.id)
    const fm = fmap.get(name)
    return { id: n.id, kind: n.kind, name, region: parseRegion(n.id), account: String(n.account ?? ''), crown: !!n.crown_jewel, count: fm?.count ?? 0, worst: fm ? worst(fm.sevs) : '' }
  })
  const ql = q.trim().toLowerCase()
  if (ql) resources = resources.filter((r) => `${r.name} ${r.id} ${r.kind}`.toLowerCase().includes(ql))
  resources.sort((a, b) => (RANK[a.worst] ?? 9) - (RANK[b.worst] ?? 9) || a.name.localeCompare(b.name))

  const toggle = (k: string) => setOpenKeys((s) => { const n = new Set(s); n.has(k) ? n.delete(k) : n.add(k); return n })

  // list mode → grouped by kind
  const byKind = new Map<string, Res[]>()
  for (const r of resources) { if (!byKind.has(r.kind)) byKind.set(r.kind, []); byKind.get(r.kind)!.push(r) }

  // tree mode → account → region → kind
  const tree = new Map<string, Map<string, Map<string, Res[]>>>()
  for (const r of resources) {
    const a = r.account || 'account', rg = r.region
    if (!tree.has(a)) tree.set(a, new Map())
    const byReg = tree.get(a)!; if (!byReg.has(rg)) byReg.set(rg, new Map())
    const byK = byReg.get(rg)!; if (!byK.has(r.kind)) byK.set(r.kind, []); byK.get(r.kind)!.push(r)
  }

  return (
    <div className="p-6 md:p-8 max-w-[1440px] mx-auto">
      <div className="flex items-start justify-between gap-4 mb-5 flex-wrap">
        <div>
          <h1 className="text-2xl font-extrabold tracking-tight text-ink flex items-center gap-2"><Boxes size={22} className="text-accent" /> Cloud Assets</h1>
          <p className="text-ink2 text-sm mt-1">{isOrg ? 'Organization' : `Account ${scope}`} · {resources.length} resources</p>
        </div>
        <div className="flex items-center gap-2">
          <div className="relative">
            <Search size={14} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-ink3" />
            <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search resources…" className="rounded-lg border border-line bg-panel pl-8 pr-3 py-1.5 text-sm text-ink placeholder:text-ink3 outline-none focus:border-accent/50 w-52" />
          </div>
          <div className="flex rounded-lg border border-line overflow-hidden">
            <button onClick={() => setView('list')} className="px-3 py-1.5 text-xs font-semibold flex items-center gap-1.5" style={{ background: view === 'list' ? 'var(--accent)' : 'var(--panel)', color: view === 'list' ? '#fff' : 'var(--ink2)' }}><List size={13} /> List</button>
            <button onClick={() => setView('tree')} className="px-3 py-1.5 text-xs font-semibold flex items-center gap-1.5" style={{ background: view === 'tree' ? 'var(--accent)' : 'var(--panel)', color: view === 'tree' ? '#fff' : 'var(--ink2)' }}><Network size={13} /> Hierarchy</button>
          </div>
        </div>
      </div>

      {resources.length === 0 ? (
        <Card><Empty icon={<Boxes size={26} />}>No resources in this scope.</Empty></Card>
      ) : view === 'list' ? (
        <div className="flex flex-col gap-3">
          {[...byKind.entries()].map(([kind, list]) => (
            <Card key={kind} className="p-2">
              <div className="flex items-center gap-2 px-3 py-2">
                <span className="text-sm font-bold text-ink">{nodeMeta(kind).label}</span>
                <span className="text-xs text-ink3">{list.length}</span>
              </div>
              {list.map((r) => <ResRow key={r.id} r={r} />)}
            </Card>
          ))}
        </div>
      ) : (
        <Card className="p-2">
          {[...tree.entries()].map(([acct, byReg]) => (
            <div key={acct}>
              <button onClick={() => toggle(acct)} className="flex items-center gap-2 px-3 py-2 w-full text-left font-mono text-sm font-bold text-ink">
                {openKeys.has(acct) ? <ChevronDown size={15} /> : <ChevronRight size={15} />} {acct}
              </button>
              {openKeys.has(acct) && [...byReg.entries()].map(([rg, byK]) => (
                <div key={rg} className="ml-4">
                  <button onClick={() => toggle(`${acct}/${rg}`)} className="flex items-center gap-2 px-3 py-1.5 w-full text-left text-sm font-semibold text-ink2">
                    {openKeys.has(`${acct}/${rg}`) ? <ChevronDown size={14} /> : <ChevronRight size={14} />} {rg}
                  </button>
                  {openKeys.has(`${acct}/${rg}`) && [...byK.entries()].map(([kind, list]) => (
                    <div key={kind} className="ml-5">
                      <div className="text-xs font-semibold text-ink3 px-3 py-1">{nodeMeta(kind).label} · {list.length}</div>
                      {list.map((r) => <ResRow key={r.id} r={r} />)}
                    </div>
                  ))}
                </div>
              ))}
            </div>
          ))}
        </Card>
      )}
    </div>
  )
}

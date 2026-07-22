import { useState } from 'react'
import { Link } from 'react-router-dom'
import { KeyRound, ShieldAlert, Gem, Globe, ChevronDown, ChevronRight } from 'lucide-react'
import { useScope } from '../state/scope'
import { useFetch } from '../lib/useFetch'
import { loadGraph } from '../lib/orgdata'
import { Card, Loader, ErrorNote, Empty, Chip } from '../components/ui'
import { nodeMeta, shortLabel, prettyRel } from '../lib/nodes'
import type { GNode } from '../api/types'

type Pack = 'all' | 'privesc' | 'crown' | 'exposed'
interface Rel { rel: string; target: string; dir: 'out' | 'in' }
interface Principal {
  id: string; kind: string; name: string; account: string
  privesc: boolean; crown: boolean; exposed: boolean; rels: Rel[]
}
const risk = (p: Principal) => Number(p.privesc) + Number(p.crown) + Number(p.exposed)

function PrincipalCard({ p, open, onToggle }: { p: Principal; open: boolean; onToggle: () => void }) {
  const M = nodeMeta(p.kind)
  const Icon = M.icon
  return (
    <Card>
      <div className="flex items-center gap-3 px-4 py-3">
        <span className="h-8 w-8 rounded-lg grid place-items-center shrink-0" style={{ background: 'var(--panel2)', color: M.tone }}><Icon size={15} /></span>
        <div className="min-w-0 flex-1">
          <div className="text-sm font-semibold text-ink truncate">{p.name}</div>
          <div className="font-mono text-[11px] text-ink3 truncate">{p.kind}{p.account ? ` · ${p.account}` : ''}</div>
        </div>
        <div className="flex gap-1 flex-wrap justify-end">
          {p.exposed && <Chip fg="var(--crit)" bg="var(--critbg)"><Globe size={10} className="inline -mt-0.5 mr-0.5" />exposed</Chip>}
          {p.privesc && <Chip fg="var(--high)" bg="var(--highbg)"><ShieldAlert size={10} className="inline -mt-0.5 mr-0.5" />can escalate</Chip>}
          {p.crown && <Chip fg="var(--gold)" bg="var(--goldbg)"><Gem size={10} className="inline -mt-0.5 mr-0.5" />reads crown</Chip>}
        </div>
        <button onClick={onToggle} className="h-6 w-6 grid place-items-center text-ink3 hover:text-ink shrink-0">{open ? <ChevronDown size={16} /> : <ChevronRight size={16} />}</button>
      </div>
      {open && (
        <div className="px-4 pb-3 border-t border-line2 pt-2.5 flex flex-col gap-1.5">
          {p.rels.length === 0 ? <span className="text-xs text-ink3">No mapped relationships.</span> : p.rels.map((r, i) => (
            <div key={i} className="flex items-center gap-2 text-xs">
              <span className="font-mono text-ink3 truncate max-w-[160px]">{p.name}</span>
              <span className="ow-grad-text font-bold">{r.dir === 'out' ? '→' : '←'}</span>
              <Chip>{prettyRel(r.rel)}</Chip>
              <span className="font-mono text-ink truncate">{shortLabel(r.target)}</span>
            </div>
          ))}
          <Link to="/attack-paths" className="text-xs font-semibold text-accent mt-1">See attack paths through this principal →</Link>
        </div>
      )}
    </Card>
  )
}

export function Identity() {
  const { scope } = useScope()
  const isOrg = scope === 'org'
  const { data, loading, error } = useFetch(() => loadGraph(scope), [scope])
  const [pack, setPack] = useState<Pack>('all')
  const [open, setOpen] = useState<string | null>(null)

  if (loading) return <Loader />
  if (error) return <ErrorNote msg={error} />
  if (!data) return null

  const crownSet = new Set(data.nodes.filter((n) => n.crown_jewel).map((n) => n.id))
  const isPrincipal = (k: string) => k === 'IAMRole' || k === 'IAMUser'

  const principals: Principal[] = (data.nodes as (GNode & { account?: unknown })[]).filter((n) => isPrincipal(n.kind)).map((n) => {
    const out = data.edges.filter((e) => e.source === n.id)
    const inc = data.edges.filter((e) => e.target === n.id)
    const rels: Rel[] = [
      ...out.map((e) => ({ rel: e.kind, target: e.target, dir: 'out' as const })),
      ...inc.filter((e) => e.kind === 'EXPOSED_TO' || e.kind === 'HAS_ROLE').map((e) => ({ rel: e.kind, target: e.source, dir: 'in' as const })),
    ]
    return {
      id: n.id, kind: n.kind, name: typeof n.name === 'string' ? n.name : shortLabel(n.id), account: String(n.account ?? ''),
      privesc: out.some((e) => e.kind === 'CAN_PRIVESC_TO' || e.kind === 'CAN_ASSUME'),
      crown: out.some((e) => e.kind === 'CAN_READ_DATA' && crownSet.has(e.target)),
      exposed: inc.some((e) => e.kind === 'EXPOSED_TO'),
      rels,
    }
  })

  const packs: { k: Pack; label: string; n: number }[] = [
    { k: 'all', label: 'All principals', n: principals.length },
    { k: 'privesc', label: 'Can escalate to admin', n: principals.filter((p) => p.privesc).length },
    { k: 'crown', label: 'Can read crown data', n: principals.filter((p) => p.crown).length },
    { k: 'exposed', label: 'Internet-exposed', n: principals.filter((p) => p.exposed).length },
  ]
  const shown = principals
    .filter((p) => pack === 'all' || (pack === 'privesc' && p.privesc) || (pack === 'crown' && p.crown) || (pack === 'exposed' && p.exposed))
    .sort((a, b) => risk(b) - risk(a) || a.name.localeCompare(b.name))

  return (
    <div className="p-6 md:p-8 max-w-[1440px] mx-auto">
      <div className="mb-5">
        <h1 className="text-2xl font-extrabold tracking-tight text-ink flex items-center gap-2"><KeyRound size={22} className="text-accent" /> Identity &amp; Access</h1>
        <p className="text-ink2 text-sm mt-1">{isOrg ? 'Organization' : `Account ${scope}`} · {principals.length} principals · effective permissions over the graph</p>
      </div>

      <div className="flex gap-2 flex-wrap mb-5">
        {packs.map((p) => (
          <button key={p.k} onClick={() => setPack(p.k)} className="rounded-lg px-3 py-1.5 text-xs font-semibold border transition-colors"
            style={{ borderColor: pack === p.k ? 'var(--accent)' : 'var(--line)', background: pack === p.k ? 'var(--accentdim)' : 'var(--panel)', color: pack === p.k ? 'var(--accent)' : 'var(--ink2)' }}>
            {p.label} <span className="text-ink3">{p.n}</span>
          </button>
        ))}
      </div>

      {shown.length === 0 ? (
        <Card><Empty icon={<KeyRound size={26} />}>No principals match this query pack.</Empty></Card>
      ) : (
        <div className="flex flex-col gap-2">
          {shown.map((p) => <PrincipalCard key={p.id} p={p} open={open === p.id} onToggle={() => setOpen(open === p.id ? null : p.id)} />)}
        </div>
      )}
    </div>
  )
}

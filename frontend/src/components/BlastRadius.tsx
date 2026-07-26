import { ReactFlow, Background, MarkerType, Handle, Position } from '@xyflow/react'
import type { Node, Edge, NodeProps } from '@xyflow/react'
import '@xyflow/react/dist/style.css'
import { X, Radar, Globe, Crown, ShieldAlert, ArrowRight, ArrowLeft } from 'lucide-react'
import { useFetch } from '../lib/useFetch'
import { api } from '../api/client'
import { Loader, ErrorNote, Empty, Chip } from './ui'
import { nodeMeta } from '../lib/nodes'
import type { BlastRow } from '../api/types'

const VIZ_CAP = 6 // nodes drawn per side; the lists below show every row

function BNode({ data }: NodeProps) {
  const d = data as { label: string; kind: string; role: 'center' | 'source' | 'data' | 'admin' }
  const M = nodeMeta(d.kind)
  const Icon = M.icon
  const border =
    d.role === 'center' ? 'var(--accent)' : d.role === 'data' ? 'var(--gold)' : d.role === 'admin' ? 'var(--crit)' : 'var(--line)'
  return (
    <div className="rounded-xl border-2 bg-panel px-2.5 py-1.5 shadow-sm flex items-center gap-2" style={{ borderColor: border }}>
      <Handle type="target" position={Position.Left} style={{ opacity: 0 }} />
      <span className="h-6 w-6 rounded-lg grid place-items-center shrink-0" style={{ background: 'var(--panel2)', color: M.tone }}><Icon size={13} /></span>
      <div className="min-w-0">
        <div className="text-[11px] font-bold text-ink whitespace-nowrap max-w-[130px] truncate">{d.label}</div>
        <div className="text-[9px] text-ink3">{M.label}</div>
      </div>
      <Handle type="source" position={Position.Right} style={{ opacity: 0 }} />
    </div>
  )
}
const nodeTypes = { b: BNode }

function RowItem({ r, dir }: { r: BlastRow; dir: 'to' | 'from' }) {
  const M = nodeMeta(r.kind)
  const Icon = M.icon
  return (
    <div className="flex items-center gap-2.5 rounded-lg border border-line px-3 py-2" style={{ background: 'var(--panel)' }}>
      <span className="h-6 w-6 rounded-lg grid place-items-center shrink-0" style={{ background: 'var(--panel2)', color: M.tone }}><Icon size={13} /></span>
      <div className="min-w-0 flex-1">
        <div className="text-xs font-semibold text-ink truncate">{r.label}</div>
        <div className="text-[10px] text-ink3">{M.label} · {r.path.length - 1} hop{r.path.length - 1 === 1 ? '' : 's'} {dir === 'to' ? 'away' : 'to here'}</div>
      </div>
      {r.terminal === 'data' && <Chip fg="var(--gold)" bg="var(--panel2)">crown data</Chip>}
      {r.terminal === 'admin' && <Chip fg="var(--crit)" bg="var(--panel2)">admin</Chip>}
    </div>
  )
}

export function BlastRadius({ account, node, onClose }: { account: string; node: string; onClose: () => void }) {
  const { data, loading, error } = useFetch(() => api.blastRadius(account, node), [account, node])

  const nodes: Node[] = []
  const edges: Edge[] = []
  if (data?.exists) {
    nodes.push({ id: data.node, type: 'b', position: { x: 0, y: 0 }, data: { label: data.label, kind: data.kind ?? 'Resource', role: 'center' } })
    const src = data.reached_by.slice(0, VIZ_CAP)
    const tgt = data.reaches.slice(0, VIZ_CAP)
    const col = (n: number, i: number) => (i - (n - 1) / 2) * 66
    src.forEach((r, i) => {
      nodes.push({ id: `s:${r.id}`, type: 'b', position: { x: -300, y: col(src.length, i) }, data: { label: r.label, kind: r.kind, role: 'source' } })
      edges.push({ id: `es${i}`, source: `s:${r.id}`, target: data.node, animated: true, style: { stroke: 'var(--ink3)', strokeWidth: 1.5 }, markerEnd: { type: MarkerType.ArrowClosed, color: 'var(--ink3)', width: 14, height: 14 } })
    })
    tgt.forEach((r, i) => {
      const tone = r.terminal === 'admin' ? 'var(--crit)' : 'var(--gold)'
      nodes.push({ id: `t:${r.id}`, type: 'b', position: { x: 300, y: col(tgt.length, i) }, data: { label: r.label, kind: r.kind, role: r.terminal ?? 'data' } })
      edges.push({ id: `et${i}`, source: data.node, target: `t:${r.id}`, animated: true, style: { stroke: tone, strokeWidth: 1.6 }, markerEnd: { type: MarkerType.ArrowClosed, color: tone, width: 14, height: 14 } })
    })
  }

  return (
    <div className="fixed inset-0 z-50">
      <div className="absolute inset-0 bg-black/40 backdrop-blur-sm" onClick={onClose} />
      <aside className="absolute right-0 top-0 bottom-0 w-full max-w-[820px] bg-canvas border-l border-line shadow-2xl overflow-y-auto">
        <div className="sticky top-0 z-10 bg-canvas/90 backdrop-blur border-b border-line px-6 py-4 flex items-center gap-3">
          <span className="h-8 w-8 grid place-items-center rounded-lg text-white ow-grad"><Radar size={16} /></span>
          <div className="leading-tight min-w-0">
            <div className="text-sm font-bold text-ink">Blast radius</div>
            <div className="text-xs text-ink3 truncate font-mono">{data?.label ?? node}</div>
          </div>
          <button onClick={onClose} className="ml-auto h-8 w-8 grid place-items-center rounded-lg border border-line text-ink3 hover:text-ink"><X size={16} /></button>
        </div>

        <div className="p-6 flex flex-col gap-5">
          {loading && <Loader label="Tracing reachability…" />}
          {error && <ErrorNote msg={error} />}
          {data && !data.exists && <Empty icon={<Radar size={26} />}>This node isn’t in the current scan graph.</Empty>}

          {data?.exists && (
            <>
              <div className="flex flex-wrap items-center gap-2">
                {data.internet_reachable && (
                  <span className="inline-flex items-center gap-1.5 rounded-lg px-2.5 py-1 text-xs font-semibold" style={{ background: 'var(--critbg)', color: 'var(--crit)' }}>
                    <Globe size={12} /> Internet-reachable
                  </span>
                )}
                <span className="inline-flex items-center gap-1.5 rounded-lg px-2.5 py-1 text-xs font-semibold" style={{ background: 'var(--panel2)', color: 'var(--gold)' }}>
                  <Crown size={12} /> reaches {data.counts.crowns} crown-jewel{data.counts.crowns === 1 ? '' : 's'}
                </span>
                <span className="inline-flex items-center gap-1.5 rounded-lg px-2.5 py-1 text-xs font-semibold" style={{ background: 'var(--panel2)', color: 'var(--crit)' }}>
                  <ShieldAlert size={12} /> {data.counts.admins} admin path{data.counts.admins === 1 ? '' : 's'}
                </span>
                <span className="rounded-lg px-2.5 py-1 text-xs font-semibold" style={{ background: 'var(--panel2)', color: 'var(--ink2)' }}>
                  {data.counts.sources} node{data.counts.sources === 1 ? '' : 's'} can reach it
                </span>
              </div>

              <div style={{ height: 320 }} className="rounded-xl border border-line overflow-hidden">
                <ReactFlow nodes={nodes} edges={edges} nodeTypes={nodeTypes} fitView fitViewOptions={{ padding: 0.25 }} nodesConnectable={false} edgesFocusable={false} minZoom={0.3} maxZoom={1.5}>
                  <Background gap={16} size={1} color="var(--line)" />
                </ReactFlow>
              </div>
              <p className="text-xs text-ink3 -mt-2">
                Reachability over attack edges only (exposure, trust, privilege-escalation, data access) — the same edge universe that scores attack paths. Vulnerability, image and threat annotations are excluded.
              </p>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
                <div>
                  <div className="flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wide text-ink3 mb-2"><ArrowRight size={13} /> Can reach ({data.reaches.length})</div>
                  {data.reaches.length === 0 ? <div className="text-sm text-ink3 rounded-xl border border-line2 px-4 py-3">Reaches no crown-jewel data or admin.</div>
                    : <div className="flex flex-col gap-2">{data.reaches.map((r) => <RowItem key={r.id} r={r} dir="to" />)}</div>}
                </div>
                <div>
                  <div className="flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wide text-ink3 mb-2"><ArrowLeft size={13} /> Can be reached by ({data.reached_by.length})</div>
                  {data.reached_by.length === 0 ? <div className="text-sm text-ink3 rounded-xl border border-line2 px-4 py-3">Nothing in the graph reaches this node.</div>
                    : <div className="flex flex-col gap-2">{data.reached_by.map((r) => <RowItem key={r.id} r={r} dir="from" />)}</div>}
                </div>
              </div>
            </>
          )}
        </div>
      </aside>
    </div>
  )
}

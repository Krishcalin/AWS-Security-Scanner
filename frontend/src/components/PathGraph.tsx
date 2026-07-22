import { ReactFlow, Background, Controls, MarkerType, Handle, Position } from '@xyflow/react'
import type { Node, Edge, NodeProps } from '@xyflow/react'
import '@xyflow/react/dist/style.css'
import { nodeMeta, shortLabel, nodeKindOf, prettyRel } from '../lib/nodes'
import type { AttackPath } from '../api/types'

interface KindData {
  label: string
  kind: string
  terminal: boolean
  entry: boolean
  [key: string]: unknown
}

function KindNode({ data }: NodeProps) {
  const d = data as KindData
  const M = nodeMeta(d.kind)
  const Icon = M.icon
  const border = d.terminal ? 'var(--gold)' : d.entry ? 'var(--ink3)' : 'var(--line)'
  return (
    <div className="rounded-xl border-2 bg-panel px-3 py-2 shadow-sm flex items-center gap-2" style={{ borderColor: border }}>
      <Handle type="target" position={Position.Left} style={{ opacity: 0 }} />
      <span className="h-7 w-7 rounded-lg grid place-items-center shrink-0" style={{ background: 'var(--panel2)', color: M.tone }}>
        <Icon size={15} />
      </span>
      <div className="min-w-0">
        <div className="text-xs font-bold text-ink whitespace-nowrap max-w-[150px] truncate">{d.label}</div>
        <div className="text-[10px] text-ink3">{M.label}</div>
      </div>
      <Handle type="source" position={Position.Right} style={{ opacity: 0 }} />
    </div>
  )
}

const nodeTypes = { kind: KindNode }

export function PathGraph({ path, height = 300 }: { path: AttackPath; height?: number }) {
  const nodes: Node[] = path.nodes.map((nid, i) => ({
    id: nid,
    type: 'kind',
    position: { x: i * 210, y: 0 },
    data: {
      label: shortLabel(nid),
      kind: nodeKindOf(nid),
      terminal: i === path.nodes.length - 1 && path.terminal_kind === 'data',
      entry: i === 0,
    } satisfies KindData,
  }))

  const edges: Edge[] = path.edges.map(([s, d, rel], i) => ({
    id: `e${i}`,
    source: s,
    target: d,
    label: prettyRel(rel ?? ''),
    animated: true,
    style: { stroke: 'var(--accent)', strokeWidth: 1.6, strokeDasharray: path.conditioned ? '6 4' : undefined },
    labelStyle: { fill: 'var(--ink2)', fontSize: 10, fontWeight: 600 },
    labelBgStyle: { fill: 'var(--panel)' },
    labelBgPadding: [4, 2],
    labelBgBorderRadius: 4,
    markerEnd: { type: MarkerType.ArrowClosed, color: 'var(--accent)', width: 16, height: 16 },
  }))

  return (
    <div style={{ height }} className="rounded-xl border border-line overflow-hidden">
      <ReactFlow
        nodes={nodes}
        edges={edges}
        nodeTypes={nodeTypes}
        fitView
        fitViewOptions={{ padding: 0.2 }}
        nodesConnectable={false}
        edgesFocusable={false}
        minZoom={0.3}
        maxZoom={1.5}
      >
        <Background gap={16} size={1} color="var(--line)" />
        <Controls showInteractive={false} />
      </ReactFlow>
    </div>
  )
}

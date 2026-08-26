/**
 * AttackPathCanvas — the full-screen attack path view.
 *
 * WHAT THIS SHOWS THAT A CHAIN OF ARROWS DOES NOT
 * ------------------------------------------------
 * The previous renderer drew `path.nodes` as boxes and `path.edges` as arrows and
 * looked nothing up, so it could tell you the SHAPE of a path and nothing about the
 * mechanism. Three things are added here, and each answers a question a responder
 * actually asks:
 *
 *   1. THE BASIS OF EVERY HOP. The graph records *why* each edge exists —
 *      "0.0.0.0/0 security group", "instance profile", "iam:PassRole +
 *      sts:AssumeRole", "s3:GetObject". That string is the difference between
 *      "these two things are connected" and "here is the thing to revoke".
 *   2. THE EVIDENCE UNDER EACH HOP. Findings whose `affected` list names the node,
 *      and the CVE the path pivoted through, hung beneath the node they belong to.
 *   3. WHY THE SCORE IS THE SCORE. The factor decomposition, rather than a number
 *      presented as a verdict.
 *
 * EMPTY IS NOT CLEAN
 * ------------------
 * Every lookup here can miss: a path node absent from the graph, a resource with no
 * catalog entry, an edge whose basis the scanner did not record. A view that renders
 * nothing in those cases reads as "nothing to see", which is the phantom-pass
 * failure this codebase exists to avoid. So each one states what it could not
 * resolve — see `UnresolvedNote` and the `evidence.unknown` branch.
 */
import { useCallback, useEffect, useMemo, useState } from 'react'
import {
  ReactFlow, ReactFlowProvider, Background, BackgroundVariant, Handle, Position,
  BaseEdge, EdgeLabelRenderer, getSmoothStepPath, useReactFlow,
} from '@xyflow/react'
import type { Node, Edge, NodeProps, EdgeProps } from '@xyflow/react'
import '@xyflow/react/dist/style.css'
import {
  X, ZoomIn, ZoomOut, Maximize2, ChevronLeft, ChevronRight, Bug,
  ShieldAlert, Crown, Globe2, Lock, LockOpen, Info, Radar,
} from 'lucide-react'
import { nodeMeta, shortLabel, nodeKindOf, prettyRel, hopTactic } from '../lib/nodes'
import { buildPathModel, sentenceFor } from '../lib/pathmodel'
import type { PathModel, EvidenceItem } from '../lib/pathmodel'
import { sevColor, sevBg } from '../lib/format'
import { SeverityChip, PathBadges } from './paths'
import type { AttackPath, GraphFull, FindingCatalogEntry } from '../api/types'

// ── geometry ────────────────────────────────────────────────────────────────
const COL = 300          // horizontal gap between spine nodes
const SPINE_Y = 0
const EV_Y = 170         // evidence sits below the spine, as in a hop's "why"
const EV_STEP = 74

/** Thin memo over the pure join in lib/pathmodel — see that file for the invariant. */
function useModel(path: AttackPath, graph: GraphFull | null, catalog: FindingCatalogEntry[]): PathModel {
  return useMemo(() => buildPathModel(path, graph, catalog), [path, graph, catalog])
}

// ── spine node ──────────────────────────────────────────────────────────────
interface SpineData {
  label: string; kind: string; nid: string
  entry: boolean; terminal: boolean; terminalKind: string
  props: Record<string, unknown>
  resolved: boolean
  onFocus?: (nid: string) => void
  [k: string]: unknown
}

function PropBadge({ tone, bg, icon, children }: { tone: string; bg: string; icon: React.ReactNode; children: React.ReactNode }) {
  return (
    <span className="inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[10px] font-bold leading-none"
      style={{ color: tone, background: bg }}>
      {icon}{children}
    </span>
  )
}

function SpineNode({ data }: NodeProps) {
  const d = data as SpineData
  const M = nodeMeta(d.kind)
  const Icon = M.icon
  const accent = d.terminal
    ? (d.terminalKind === 'data' ? 'var(--gold)' : 'var(--crit)')
    : d.entry ? 'var(--ink3)' : 'var(--accent)'
  return (
    <div
      onClick={() => d.onFocus?.(d.nid)}
      className={`rounded-2xl border-2 bg-panel shadow-sm w-[210px] ${d.onFocus ? 'cursor-pointer hover:shadow-md' : ''} transition-shadow`}
      style={{ borderColor: accent }}
    >
      <Handle type="target" position={Position.Left} style={{ opacity: 0 }} />
      <div className="flex items-center gap-2.5 px-3 py-2.5">
        <span className="h-9 w-9 rounded-xl grid place-items-center shrink-0"
          style={{ background: 'var(--panel2)', color: M.tone }}>
          <Icon size={18} />
        </span>
        <div className="min-w-0">
          <div className="text-[13px] font-bold text-ink truncate" title={d.nid}>{d.label}</div>
          <div className="text-[10px] text-ink3 truncate">{M.label}</div>
        </div>
      </div>
      {(d.props.crown_jewel || d.props.public || d.props.admin || d.props.encrypted === false || !d.resolved) && (
        <div className="flex flex-wrap gap-1 px-3 pb-2.5">
          {d.props.crown_jewel === true &&
            <PropBadge tone="var(--gold)" bg="var(--goldbg)" icon={<Crown size={9} />}>crown jewel</PropBadge>}
          {d.props.admin === true &&
            <PropBadge tone="var(--crit)" bg="var(--critbg)" icon={<ShieldAlert size={9} />}>admin</PropBadge>}
          {d.props.public === true &&
            <PropBadge tone="var(--crit)" bg="var(--critbg)" icon={<Globe2 size={9} />}>public</PropBadge>}
          {d.props.encrypted === false &&
            <PropBadge tone="var(--high)" bg="var(--highbg)" icon={<LockOpen size={9} />}>unencrypted</PropBadge>}
          {d.props.encrypted === true &&
            <PropBadge tone="var(--ink3)" bg="var(--panel2)" icon={<Lock size={9} />}>encrypted</PropBadge>}
          {!d.resolved &&
            <PropBadge tone="var(--ink3)" bg="var(--panel2)" icon={<Info size={9} />}>not in graph</PropBadge>}
        </div>
      )}
      <Handle type="source" position={Position.Right} style={{ opacity: 0 }} />
      <Handle type="source" position={Position.Bottom} id="ev" style={{ opacity: 0 }} />
    </div>
  )
}

// ── evidence node ───────────────────────────────────────────────────────────
interface EvData { item: EvidenceItem; [k: string]: unknown }

function EvidenceNode({ data }: NodeProps) {
  const { item } = data as unknown as EvData
  const c = sevColor(item.severity)
  return (
    <div className="rounded-xl border bg-panel shadow-sm w-[190px] flex items-center gap-2 px-2.5 py-2"
      style={{ borderColor: 'var(--line)' }}>
      <Handle type="target" position={Position.Top} style={{ opacity: 0 }} />
      <span className="h-7 w-7 rounded-lg grid place-items-center shrink-0 font-mono text-[10px] font-extrabold"
        style={{ background: sevBg(item.severity), color: c }}>
        {item.kind === 'cve' ? <Bug size={13} /> : item.severity.slice(0, 1)}
      </span>
      <div className="min-w-0">
        <div className="font-mono text-[11px] font-bold truncate" style={{ color: c }}>{item.label}</div>
        <div className="text-[10px] text-ink3 truncate">{item.sub}</div>
      </div>
    </div>
  )
}

function MoreNode({ data }: NodeProps) {
  const d = data as { count: number; [k: string]: unknown }
  return (
    <div className="rounded-xl border border-dashed bg-panel2/50 w-[190px] px-2.5 py-2 text-center"
      style={{ borderColor: 'var(--line)' }}>
      <Handle type="target" position={Position.Top} style={{ opacity: 0 }} />
      <span className="text-[11px] font-semibold text-ink3">+{d.count} more finding{d.count === 1 ? '' : 's'}</span>
    </div>
  )
}

// ── hop edge: the relationship AND the basis ────────────────────────────────
interface HopEdgeData { rel: string; basis: string; ports: string; known: boolean; [k: string]: unknown }

function HopEdge({ id, sourceX, sourceY, targetX, targetY, sourcePosition, targetPosition, data }: EdgeProps) {
  const d = (data ?? {}) as HopEdgeData
  const [path, lx, ly] = getSmoothStepPath({
    sourceX, sourceY, targetX, targetY, sourcePosition, targetPosition, borderRadius: 8,
  })
  const tactic = hopTactic(d.rel)
  return (
    <>
      <BaseEdge id={id} path={path} markerEnd={`url(#ow-arrow)`}
        style={{ stroke: 'var(--accent)', strokeWidth: 2, strokeDasharray: d.known ? undefined : '5 4' }} />
      <EdgeLabelRenderer>
        <div
          className="nodrag nopan absolute rounded-lg border px-2 py-1 text-center shadow-sm"
          style={{
            transform: `translate(-50%,-50%) translate(${lx}px,${ly}px)`,
            background: 'var(--panel)', borderColor: 'var(--line)', maxWidth: 190,
          }}
        >
          <div className="text-[10px] font-extrabold uppercase tracking-wide" style={{ color: 'var(--accent)' }}>
            {prettyRel(d.rel)}
          </div>
          {d.basis
            ? <div className="font-mono text-[10px] text-ink2 leading-tight mt-0.5 break-words">{d.basis}</div>
            : <div className="text-[10px] text-ink3 italic mt-0.5">basis not recorded</div>}
          {d.ports && <div className="font-mono text-[10px] text-ink3 mt-0.5">ports {d.ports}</div>}
          {tactic && (
            <div className="text-[9px] font-semibold mt-1 rounded px-1 py-0.5 inline-block"
              style={{ background: 'var(--accentdim)', color: 'var(--accent)' }}>
              {tactic}
            </div>
          )}
        </div>
      </EdgeLabelRenderer>
    </>
  )
}

const nodeTypes = { spine: SpineNode, evidence: EvidenceNode, more: MoreNode }
const edgeTypes = { hop: HopEdge }

// ── canvas ──────────────────────────────────────────────────────────────────
const MAX_EVIDENCE = 3

function Canvas({
  path, model, step, onStep, onFocusNode,
}: {
  path: AttackPath
  model: PathModel
  step: number
  onStep: (i: number) => void
  onFocusNode?: (nid: string) => void
}) {
  const rf = useReactFlow()
  const { nodes, edges } = useMemo(() => {
    const ns: Node[] = []
    const es: Edge[] = []
    path.nodes.forEach((nid, i) => {
      const g = model.byId.get(nid)
      ns.push({
        id: nid, type: 'spine', position: { x: i * COL, y: SPINE_Y },
        data: {
          nid, label: shortLabel(nid),
          kind: g?.kind ?? nodeKindOf(nid),
          entry: i === 0,
          terminal: i === path.nodes.length - 1,
          terminalKind: path.terminal_kind,
          props: (g ?? {}) as Record<string, unknown>,
          resolved: !model.hasGraph || model.byId.has(nid),
          onFocus: onFocusNode,
        } satisfies SpineData,
      })
      const items = model.evidence.get(nid) ?? []
      items.slice(0, MAX_EVIDENCE).forEach((item, k) => {
        const eid = `ev:${item.id}`
        ns.push({
          id: eid, type: 'evidence',
          position: { x: i * COL + 10, y: EV_Y + k * EV_STEP },
          data: { item } as unknown as Record<string, unknown>,
        })
        es.push({
          id: `eve:${eid}`, source: nid, target: eid, sourceHandle: 'ev',
          style: { stroke: 'var(--line)', strokeWidth: 1.5, strokeDasharray: '3 3' },
        })
      })
      if (items.length > MAX_EVIDENCE) {
        const mid = `more:${nid}`
        ns.push({
          id: mid, type: 'more',
          position: { x: i * COL + 10, y: EV_Y + MAX_EVIDENCE * EV_STEP },
          data: { count: items.length - MAX_EVIDENCE },
        })
        es.push({
          id: `eve:${mid}`, source: nid, target: mid, sourceHandle: 'ev',
          style: { stroke: 'var(--line)', strokeWidth: 1.5, strokeDasharray: '3 3' },
        })
      }
    })
    model.hops.forEach((h, i) => {
      es.push({
        id: `hop:${i}`, source: h.from, target: h.to, type: 'hop',
        data: { rel: h.rel, basis: h.basis, ports: h.ports, known: h.known } satisfies HopEdgeData,
        animated: i === step,
        style: { opacity: step < 0 || i === step ? 1 : 0.45 },
      })
    })
    return { nodes: ns, edges: es }
  }, [path, model, step, onFocusNode])

  // Keep the active hop in view as the reader steps through the narrative.
  useEffect(() => {
    const h = model.hops[step]
    if (!h) return
    const ns = [h.from, h.to].map((id) => ({ id }))
    rf.fitView({ nodes: ns, duration: 400, padding: 0.45, maxZoom: 1.1 })
  }, [step, model.hops, rf])

  return (
    <ReactFlow
      nodes={nodes}
      edges={edges}
      nodeTypes={nodeTypes}
      edgeTypes={edgeTypes}
      fitView
      fitViewOptions={{ padding: 0.2 }}
      minZoom={0.25}
      maxZoom={2}
      proOptions={{ hideAttribution: true }}
      nodesDraggable={false}
      onEdgeClick={(_, e) => { if (e.id.startsWith('hop:')) onStep(Number(e.id.slice(4))) }}
    >
      {/* one shared arrowhead so every hop edge points the same way */}
      <svg style={{ position: 'absolute', width: 0, height: 0 }}>
        <defs>
          <marker id="ow-arrow" markerWidth="12" markerHeight="12" refX="10" refY="5"
            orient="auto" markerUnits="strokeWidth">
            <path d="M0,0 L10,5 L0,10 z" fill="var(--accent)" />
          </marker>
        </defs>
      </svg>
      <Background variant={BackgroundVariant.Dots} gap={22} size={1} color="var(--line)" />
    </ReactFlow>
  )
}

// ── zoom toolbar ────────────────────────────────────────────────────────────
function Toolbar() {
  const rf = useReactFlow()
  const btn = 'h-8 w-8 grid place-items-center rounded-lg border border-line bg-panel text-ink2 hover:text-ink hover:border-accent/40 transition-colors'
  return (
    <div className="absolute right-4 top-4 z-10 flex items-center gap-1.5">
      <button className={btn} onClick={() => rf.zoomOut({ duration: 200 })} title="Zoom out"><ZoomOut size={15} /></button>
      <button className={btn} onClick={() => rf.zoomIn({ duration: 200 })} title="Zoom in"><ZoomIn size={15} /></button>
      <button className={btn} onClick={() => rf.fitView({ duration: 300, padding: 0.2 })} title="Fit to view"><Maximize2 size={15} /></button>
    </div>
  )
}

// ── narrative ───────────────────────────────────────────────────────────────
function Narrative({ hops, step, onStep }: { hops: PathModel['hops']; step: number; onStep: (i: number) => void }) {
  const h = hops[step]
  if (!h) return null
  const tactic = hopTactic(h.rel)
  return (
    <div className="border-t border-line bg-panel px-5 py-3 flex items-start gap-4">
      <div className="flex items-center gap-1 shrink-0 pt-0.5">
        <button
          onClick={() => onStep(Math.max(0, step - 1))}
          disabled={step === 0}
          className="h-7 w-7 grid place-items-center rounded-lg border border-line text-ink2 disabled:opacity-35 hover:border-accent/40"
        ><ChevronLeft size={14} /></button>
        <span className="font-mono text-xs font-bold text-ink2 tabular-nums w-10 text-center">
          {step + 1}/{hops.length}
        </span>
        <button
          onClick={() => onStep(Math.min(hops.length - 1, step + 1))}
          disabled={step === hops.length - 1}
          className="h-7 w-7 grid place-items-center rounded-lg border border-line text-ink2 disabled:opacity-35 hover:border-accent/40"
        ><ChevronRight size={14} /></button>
      </div>
      <p className="text-sm text-ink leading-relaxed flex-1 min-w-0">
        {sentenceFor(h, step === 0)}
        {!h.known && (
          <span className="ml-2 text-[11px] text-ink3 italic">
            (this hop is not an edge the stored graph declares)
          </span>
        )}
      </p>
      {tactic && (
        <span className="shrink-0 text-[11px] font-semibold rounded-lg px-2 py-1"
          style={{ background: 'var(--accentdim)', color: 'var(--accent)' }}>
          ATT&amp;CK · {tactic}
        </span>
      )}
    </div>
  )
}

// ── score rail ──────────────────────────────────────────────────────────────
const FACTORS = [
  { key: 'exposure', label: 'Exposure', hint: 'how reachable the entry point is' },
  { key: 'exploitability', label: 'Exploitability', hint: 'whether a usable flaw sits on the path' },
  { key: 'privilege', label: 'Privilege', hint: 'what the identity on the path holds' },
  { key: 'impact', label: 'Impact', hint: 'what the terminal is worth' },
  { key: 'reach', label: 'Reach', hint: 'how much of the estate this opens' },
]

function Bar({ label, hint, v }: { label: string; hint: string; v: number }) {
  const pct = Math.max(0, Math.min(1, v)) * 100
  return (
    <div>
      <div className="flex items-baseline justify-between mb-1">
        <span className="text-xs font-semibold text-ink">{label}</span>
        <span className="font-mono text-xs font-bold text-ink2 tabular-nums">{v.toFixed(2)}</span>
      </div>
      <div className="h-1.5 rounded-full overflow-hidden" style={{ background: 'var(--line2)' }}>
        <div className="h-full rounded-full" style={{ width: `${pct}%`, background: 'var(--accent)' }} />
      </div>
      <div className="text-[10px] text-ink3 mt-1">{hint}</div>
    </div>
  )
}

function UnresolvedNote({ model, catalogLoaded }: { model: PathModel; catalogLoaded: boolean }) {
  const lines: string[] = []
  if (!model.hasGraph) lines.push('The stored graph could not be loaded, so node properties and hop bases are unavailable.')
  if (model.missingNodes.length) lines.push(`${model.missingNodes.length} of this path's nodes are not in the stored graph: ${model.missingNodes.map(shortLabel).join(', ')}.`)
  if (model.missingHops) lines.push(`${model.missingHops} hop(s) are not edges the graph declares, and are drawn dashed.`)
  if (!catalogLoaded) lines.push('The finding catalog could not be loaded, so no evidence is attached to any node.')
  if (!lines.length) return null
  return (
    <div className="rounded-xl border px-3 py-2.5" style={{ borderColor: 'var(--line)', background: 'var(--medbg)' }}>
      <div className="flex items-center gap-1.5 mb-1">
        <Info size={12} style={{ color: 'var(--med)' }} />
        <span className="text-[11px] font-bold" style={{ color: 'var(--med)' }}>Not everything resolved</span>
      </div>
      {lines.map((l, i) => <p key={i} className="text-[11px] text-ink2 leading-snug">{l}</p>)}
    </div>
  )
}

// ── the view ────────────────────────────────────────────────────────────────
export function AttackPathCanvas({
  path, graph, catalog, catalogLoaded = true, onClose, onFocusNode,
}: {
  path: AttackPath
  graph: GraphFull | null
  catalog: FindingCatalogEntry[]
  catalogLoaded?: boolean
  onClose: () => void
  onFocusNode?: (nid: string) => void
}) {
  const model = useModel(path, graph, catalog)
  const [step, setStep] = useState(0)

  // Esc closes; ← / → walk the narrative, which is how this gets read.
  const onKey = useCallback((e: KeyboardEvent) => {
    if (e.key === 'Escape') onClose()
    if (e.key === 'ArrowRight') setStep((s) => Math.min(model.hops.length - 1, s + 1))
    if (e.key === 'ArrowLeft') setStep((s) => Math.max(0, s - 1))
  }, [onClose, model.hops.length])
  useEffect(() => {
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [onKey])

  return (
    <div className="fixed inset-0 z-50 bg-canvas flex flex-col" role="dialog" aria-modal="true"
      aria-label={`Attack path to ${shortLabel(path.terminal)}`}>
      {/* header */}
      <header className="flex items-center gap-3 border-b border-line bg-panel px-5 py-3 shrink-0">
        <span className="font-mono text-2xl font-extrabold tabular-nums leading-none rounded-lg px-2.5 py-1.5"
          style={{ color: sevColor(path.severity), background: sevBg(path.severity) }}>
          {Math.round(path.score)}
        </span>
        <div className="min-w-0">
          <h2 className="text-sm font-bold text-ink truncate">
            Attack path to {shortLabel(path.terminal)}
          </h2>
          <div className="text-xs text-ink3">
            {path.terminal_kind === 'data' ? 'crown-jewel data' : 'administrative control'}
            {' · '}{path.nodes.length - 1} hop{path.nodes.length === 2 ? '' : 's'}
            {path.account ? ` · ${path.account}` : ''}
          </div>
        </div>
        <div className="ml-2 hidden md:block"><PathBadges p={path} /></div>
        <button onClick={onClose} aria-label="Close"
          className="ml-auto h-8 w-8 grid place-items-center rounded-lg border border-line text-ink3 hover:text-ink hover:border-accent/40">
          <X size={16} />
        </button>
      </header>

      {/* body */}
      <div className="flex-1 flex min-h-0">
        <div className="flex-1 relative min-w-0">
          <ReactFlowProvider>
            <Canvas path={path} model={model} step={step} onStep={setStep} onFocusNode={onFocusNode} />
            <Toolbar />
          </ReactFlowProvider>
        </div>

        {/* rail */}
        <aside className="w-[320px] shrink-0 border-l border-line bg-panel overflow-y-auto p-4 flex flex-col gap-4">
          <div>
            <div className="flex items-baseline justify-between mb-3">
              <h3 className="text-sm font-bold text-ink">Why this score</h3>
              <SeverityChip sev={path.severity} />
            </div>
            <div className="text-[10px] font-mono text-ink3 rounded-lg px-2.5 py-2 mb-3" style={{ background: 'var(--panel2)' }}>
              exposure × exploitability × max(privilege, impact) × reach × boost
            </div>
            <div className="flex flex-col gap-3">
              {FACTORS.map((f) => (
                <Bar key={f.key} label={f.label} hint={f.hint} v={Number(path.factors?.[f.key] ?? 0)} />
              ))}
            </div>
            <p className="font-mono text-[11px] text-ink3 mt-3 leading-relaxed">{path.rationale}</p>
          </div>

          <div className="border-t border-line pt-3">
            <h3 className="text-sm font-bold text-ink mb-2">Evidence on this path</h3>
            {model.evidenceTotal > 0 ? (
              <p className="text-xs text-ink2 leading-relaxed">
                {model.evidenceTotal} finding{model.evidenceTotal === 1 ? '' : 's'} name a resource on this
                path. They are drawn beneath the node they belong to.
              </p>
            ) : (
              <p className="text-xs text-ink3 leading-relaxed">
                No catalog finding names any resource on this path by id. That does not mean these
                resources are clean — account-scoped checks name the account rather than the
                resource, and would not match here.
              </p>
            )}
          </div>

          {onFocusNode && (
            <div className="border-t border-line pt-3 flex items-start gap-2">
              <Radar size={13} className="text-ink3 shrink-0 mt-0.5" />
              <p className="text-[11px] text-ink3 leading-snug">Click any node on the spine for its blast radius.</p>
            </div>
          )}

          <UnresolvedNote model={model} catalogLoaded={catalogLoaded} />
        </aside>
      </div>

      <Narrative hops={model.hops} step={step} onStep={setStep} />
    </div>
  )
}

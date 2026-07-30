import { useEffect, useMemo, useState } from 'react'
import { Terminal, Play, BookOpen, ShieldCheck, AlertTriangle, CheckCircle2, FileCheck2 } from 'lucide-react'
import { useScope } from '../state/scope'
import { useFetch } from '../lib/useFetch'
import { api } from '../api/client'
import { activeAccountIds } from '../lib/orgdata'
import { Card, Loader, ErrorNote, Empty, SevDot } from '../components/ui'
import { nodeMeta } from '../lib/nodes'
import { sevColor } from '../lib/format'
import {
  QUERY_KINDS, QUICK_PREDS, QUERY_EXAMPLES, composeQuery, prettyQuery,
} from '../lib/querybuilder'
import type { WqlResult, WqlRow } from '../lib/wql'
import type { ControlRow, PolicyRow } from '../api/types'

const errString = (e: unknown): string => (e instanceof Error ? e.message : String(e))

// A compact preview of a row's props (booleans render as a bare flag / =false, else key=value).
function PropChips({ props }: { props: Record<string, unknown> }) {
  const ORDER = ['crown_jewel', 'public', 'encrypted', 'severity', 'sensitivity', 'kev', 'region', 'account']
  const keys = Object.keys(props)
    .filter((k) => k !== 'name' && props[k] !== null && typeof props[k] !== 'object')
    .sort((a, b) => (ORDER.indexOf(a) + 1 || 99) - (ORDER.indexOf(b) + 1 || 99))
    .slice(0, 5)
  if (!keys.length) return <span className="text-ink3 text-xs">—</span>
  return (
    <div className="flex flex-wrap gap-1">
      {keys.map((k) => {
        const v = props[k]
        const label = typeof v === 'boolean' ? (v ? k : `${k}=false`) : `${k}=${String(v)}`
        return (
          <span key={k} className="rounded px-1.5 py-0.5 text-[11px] font-mono"
            style={{ color: 'var(--ink2)', background: 'var(--panel2)' }}>{label}</span>
        )
      })}
    </div>
  )
}

function ResultRow({ r }: { r: WqlRow }) {
  const M = nodeMeta(r.kind)
  const Icon = M.icon
  return (
    <div className="flex items-start gap-3 px-3 py-2 rounded-lg hover:bg-panel2 transition-colors">
      <span className="h-7 w-7 rounded-lg grid place-items-center shrink-0 mt-0.5" style={{ background: 'var(--panel2)', color: M.tone }}><Icon size={14} /></span>
      <div className="min-w-0 flex-1">
        <div className="text-sm font-semibold text-ink truncate">{r.label}</div>
        <div className="font-mono text-[11px] text-ink3 truncate">{r.id}</div>
      </div>
      <div className="hidden md:block w-28 text-xs text-ink3 shrink-0">{M.label}</div>
      <div className="w-[46%] max-w-[420px] shrink-0"><PropChips props={r.props} /></div>
    </div>
  )
}

function ControlCard({ c, onLoad }: { c: ControlRow; onLoad: () => void }) {
  const warn = c.status === 'WARN'
  return (
    <div className="rounded-xl border border-line bg-panel p-3">
      <div className="flex items-center gap-2">
        <span className="font-semibold text-ink text-sm flex-1 truncate" title={c.description}>{c.name}</span>
        <span className="text-[11px] font-bold rounded px-1.5 py-0.5" style={{ color: sevColor(c.severity), background: 'var(--panel2)' }}>{c.severity}</span>
      </div>
      <div className="flex items-center gap-2 mt-2">
        <span className="inline-flex items-center gap-1 text-[11px] font-semibold"
          style={{ color: warn ? 'var(--high)' : 'var(--ok)' }}>
          {warn ? <AlertTriangle size={12} /> : <CheckCircle2 size={12} />}
          {warn ? `${c.match_count} match${c.match_count === 1 ? '' : 'es'}` : 'Pass'}
        </span>
        <span className="flex-1" />
        <button onClick={onLoad} className="text-[11px] font-semibold text-accent hover:underline">Load query</button>
      </div>
    </div>
  )
}

// A policy-as-code rule is a graph+finding condition (not a single WQL query), so it is a
// read-only row here — its POLICY-xx violations show in the Findings screen.
function PolicyCard({ p }: { p: PolicyRow }) {
  const warn = p.status === 'WARN'
  return (
    <div className="rounded-xl border border-line bg-panel p-3">
      <div className="flex items-center gap-2">
        <span className="font-semibold text-ink text-sm flex-1 truncate" title={p.description}>{p.name}</span>
        {p.pack && <span className="text-[10px] font-semibold rounded px-1.5 py-0.5 text-ink3" style={{ background: 'var(--panel2)' }}>{p.pack}</span>}
        <span className="text-[11px] font-bold rounded px-1.5 py-0.5" style={{ color: sevColor(p.severity), background: 'var(--panel2)' }}>{p.severity}</span>
      </div>
      <div className="flex items-center gap-2 mt-2">
        <span className="inline-flex items-center gap-1 text-[11px] font-semibold" style={{ color: warn ? 'var(--high)' : 'var(--ok)' }}>
          {warn ? <AlertTriangle size={12} /> : <CheckCircle2 size={12} />}
          {warn ? `${p.match_count} violation${p.match_count === 1 ? '' : 's'}` : 'Pass'}
        </span>
      </div>
    </div>
  )
}

export function Query() {
  const { scope } = useScope()
  const init = useFetch(
    () => Promise.all([activeAccountIds(), api.listControls(), api.listPolicies()])
      .then(([accts, controls, policies]) => ({ accts, controls, policies })), [])

  const [account, setAccount] = useState('')
  const [text, setText] = useState(() => prettyQuery(QUERY_EXAMPLES[0].query))
  const [kind, setKind] = useState('')
  const [preds, setPreds] = useState<Set<string>>(new Set())
  const [combine, setCombine] = useState<'and' | 'or'>('and')
  const [result, setResult] = useState<WqlResult | null>(null)
  const [err, setErr] = useState<string | null>(null)
  const [running, setRunning] = useState(false)

  // default the query target: the scoped account, else the first active account
  useEffect(() => {
    const accts = init.data?.accts ?? []
    if (!accts.length) return
    setAccount((cur) => cur || (scope !== 'org' && accts.includes(scope) ? scope : accts[0]))
  }, [init.data, scope])

  const loadQuery = (q: unknown) => { setText(prettyQuery(q)); setErr(null) }
  const applyBuilder = () => loadQuery(composeQuery(kind, [...preds], combine))
  const togglePred = (k: string) =>
    setPreds((prev) => { const n = new Set(prev); n.has(k) ? n.delete(k) : n.add(k); return n })

  async function run() {
    setErr(null); setRunning(true); setResult(null)
    let query: unknown
    try {
      query = JSON.parse(text)
    } catch (e) {
      setErr(`Invalid JSON — ${errString(e)}`); setRunning(false); return
    }
    try {
      setResult(await api.graphQuery(account, query))
    } catch (e) {
      setErr(errString(e))
    } finally {
      setRunning(false)
    }
  }

  const controls = init.data?.controls ?? []
  const policies = init.data?.policies ?? []
  const accts = useMemo(() => init.data?.accts ?? [], [init.data])

  if (init.loading) return <Loader />
  if (init.error) return <ErrorNote msg={init.error} />

  return (
    <div className="p-6 md:p-8 max-w-[1440px] mx-auto">
      <div className="mb-5">
        <h1 className="text-2xl font-extrabold tracking-tight text-ink flex items-center gap-2">
          <Terminal size={22} className="text-accent" /> Query
        </h1>
        <p className="text-ink2 text-sm mt-1 max-w-3xl">Ask the security graph a typed question (WQL) — which resources are crown-jewel and internet-reachable, which roles can reach admin. Runs read-only against one account's graph; the same engine backs offline and live.</p>
      </div>

      {accts.length === 0 ? (
        <Card><Empty icon={<Terminal size={26} />}>No scanned accounts yet. Onboard and scan an account to query its graph.</Empty></Card>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-[320px_1fr] gap-4">
          {/* ── left rail: builder · examples · saved controls ── */}
          <div className="flex flex-col gap-4 order-2 lg:order-1">
            <Card className="p-4">
              <div className="text-xs font-bold uppercase tracking-wide text-ink3 mb-3">Guided builder</div>
              <label className="block text-[11px] font-semibold text-ink3 mb-1">Kind</label>
              <select value={kind} onChange={(e) => setKind(e.target.value)}
                className="w-full rounded-lg border border-line bg-panel2 px-2 py-1.5 text-sm text-ink mb-3">
                {QUERY_KINDS.map((k) => <option key={k} value={k}>{k || 'Any kind'}</option>)}
              </select>
              <div className="text-[11px] font-semibold text-ink3 mb-1.5">Predicates</div>
              <div className="flex flex-wrap gap-1.5 mb-3">
                {QUICK_PREDS.map((p) => {
                  const on = preds.has(p.key)
                  return (
                    <button key={p.key} onClick={() => togglePred(p.key)}
                      className="rounded-full px-2 py-1 text-[11px] font-semibold border transition-colors"
                      style={on
                        ? { color: 'var(--accent)', borderColor: 'var(--accent)', background: 'color-mix(in srgb, var(--accent) 12%, transparent)' }
                        : { color: 'var(--ink2)', borderColor: 'var(--line)', background: 'transparent' }}>
                      {p.label}
                    </button>
                  )
                })}
              </div>
              {preds.size > 1 && (
                <div className="flex items-center gap-2 mb-3 text-xs">
                  <span className="text-ink3">Combine</span>
                  {(['and', 'or'] as const).map((c) => (
                    <button key={c} onClick={() => setCombine(c)}
                      className="rounded px-2 py-0.5 font-mono font-bold uppercase text-[11px]"
                      style={combine === c ? { color: 'var(--accent)', background: 'var(--panel2)' } : { color: 'var(--ink3)' }}>{c}</button>
                  ))}
                </div>
              )}
              <button onClick={applyBuilder}
                className="w-full rounded-lg bg-accent/10 text-accent font-semibold text-sm py-1.5 hover:bg-accent/20 transition-colors">
                Build query →
              </button>
            </Card>

            <Card className="p-4">
              <div className="text-xs font-bold uppercase tracking-wide text-ink3 mb-2 flex items-center gap-1.5"><BookOpen size={13} /> Examples</div>
              <div className="flex flex-col gap-1">
                {QUERY_EXAMPLES.map((ex) => (
                  <button key={ex.name} onClick={() => loadQuery(ex.query)}
                    className="text-left text-sm text-ink2 hover:text-accent px-1.5 py-1 rounded hover:bg-panel2 transition-colors">{ex.name}</button>
                ))}
              </div>
            </Card>

            <Card className="p-4">
              <div className="text-xs font-bold uppercase tracking-wide text-ink3 mb-2 flex items-center gap-1.5"><ShieldCheck size={13} /> Saved controls</div>
              {controls.length === 0 ? (
                <p className="text-xs text-ink3">No controls configured. Define saved queries on the hub via <span className="font-mono">CNAPP_CONTROLS</span> to track them as governance controls.</p>
              ) : (
                <div className="flex flex-col gap-2">
                  {controls.map((c) => <ControlCard key={c.id} c={c} onLoad={() => loadQuery(c.query)} />)}
                </div>
              )}
            </Card>

            {policies.length > 0 && (
              <Card className="p-4">
                <div className="text-xs font-bold uppercase tracking-wide text-ink3 mb-2 flex items-center gap-1.5"><FileCheck2 size={13} /> Policy-as-code</div>
                <div className="flex flex-col gap-2">
                  {policies.map((p) => <PolicyCard key={p.id} p={p} />)}
                </div>
              </Card>
            )}
          </div>

          {/* ── main: editor + run + results ── */}
          <div className="flex flex-col gap-4 order-1 lg:order-2">
            <Card className="p-4">
              <div className="flex items-center gap-2 mb-3 flex-wrap">
                <label className="text-[11px] font-semibold text-ink3">Account</label>
                <select value={account} onChange={(e) => setAccount(e.target.value)}
                  className="rounded-lg border border-line bg-panel2 px-2 py-1.5 text-sm text-ink font-mono">
                  {accts.map((a) => <option key={a} value={a}>{a}</option>)}
                </select>
                <span className="flex-1" />
                <button onClick={run} disabled={running || !account}
                  className="inline-flex items-center gap-1.5 rounded-lg bg-accent text-white font-semibold text-sm px-4 py-1.5 disabled:opacity-50 hover:brightness-110 transition-all">
                  <Play size={14} /> {running ? 'Running…' : 'Run'}
                </button>
              </div>
              <textarea value={text} onChange={(e) => setText(e.target.value)} spellCheck={false}
                rows={10} aria-label="WQL query JSON"
                className="w-full rounded-lg border border-line bg-panel2 px-3 py-2 font-mono text-[13px] text-ink resize-y focus:outline-none focus:border-accent/60" />
              {err && (
                <div className="mt-2 flex items-start gap-2 text-sm rounded-lg px-3 py-2"
                  style={{ color: 'var(--crit)', background: 'color-mix(in srgb, var(--crit) 10%, transparent)' }}>
                  <AlertTriangle size={15} className="mt-0.5 shrink-0" /> <span className="font-mono text-xs">{err}</span>
                </div>
              )}
            </Card>

            {result && (
              <Card className="p-4">
                <div className="flex items-center gap-2 mb-3">
                  <span className="text-sm font-bold text-ink">{result.count} result{result.count === 1 ? '' : 's'}</span>
                  {result.count >= 500 && <span className="text-[11px] text-ink3">(capped)</span>}
                  <span className="flex-1" />
                  <SevDot sev={result.count ? 'HIGH' : 'LOW'} />
                </div>
                {result.count === 0
                  ? <Empty icon={<Terminal size={24} />}>No nodes match this query.</Empty>
                  : <div className="flex flex-col divide-y divide-line/60">{result.nodes.map((r) => <ResultRow key={r.id} r={r} />)}</div>}
              </Card>
            )}
          </div>
        </div>
      )}
    </div>
  )
}

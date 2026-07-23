import { useState } from 'react'
import { Link } from 'react-router-dom'
import { ShieldCheck, ChevronDown, ChevronRight, Waypoints, Info, ExternalLink } from 'lucide-react'
import { useScope } from '../state/scope'
import { useFetch } from '../lib/useFetch'
import { api } from '../api/client'
import { activeAccountIds } from '../lib/orgdata'
import { Card, Loader, ErrorNote, StackBar } from '../components/ui'
import { scoreColor } from '../lib/format'
import { round1 } from '../lib/crosswalk'
import type { AccountCompliance, ComplianceScorecard, ComplianceFramework, ComplianceFrameworkMeta } from '../api/types'

type Conf = 'any' | 'high' | 'medium' | 'low'
const CONF_COLOR: Record<string, string> = { high: 'var(--low)', medium: 'var(--med)', low: 'var(--crit)' }

function mergeSC(acc: ComplianceScorecard, card: ComplianceScorecard) {
  for (const [fw, c] of Object.entries(card)) {
    const cur = (acc[fw] ??= { controls_total: 0, controls_passed: 0, controls_failed: 0, pass_rate: 0, failed_controls: [], derived: c.derived, via: c.via })
    cur.controls_total += c.controls_total
    cur.controls_passed += c.controls_passed
    cur.controls_failed += c.controls_failed
    cur.failed_controls = [...new Set([...cur.failed_controls, ...c.failed_controls])].sort()
    if (c.confidence_mix) {
      cur.confidence_mix ??= { high: 0, medium: 0, low: 0 }
      cur.confidence_mix.high += c.confidence_mix.high
      cur.confidence_mix.medium += c.confidence_mix.medium
      cur.confidence_mix.low += c.confidence_mix.low
    }
    cur.control_provenance = { ...(cur.control_provenance ?? {}), ...(c.control_provenance ?? {}) }
    cur.pass_rate = cur.controls_total ? round1((100 * cur.controls_passed) / cur.controls_total) : 100
  }
}
function mergeAll(list: AccountCompliance[]): AccountCompliance {
  const native: ComplianceScorecard = {}, derived: ComplianceScorecard = {}
  for (const c of list) { mergeSC(native, c.native); mergeSC(derived, c.derived) }
  return { native, derived, crosswalk_version: list[0]?.crosswalk_version ?? '', min_confidence: list[0]?.min_confidence ?? null }
}

interface Bundle { comp: AccountCompliance; meta: Map<string, ComplianceFrameworkMeta>; version: string }

function ConfPill({ mix }: { mix?: { high: number; medium: number; low: number } }) {
  if (!mix) return null
  return (
    <div className="flex items-center gap-1 text-[10px] font-bold">
      {(['high', 'medium', 'low'] as const).map((k) => mix[k] > 0 && (
        <span key={k} className="rounded px-1.5 py-0.5" style={{ color: CONF_COLOR[k], background: `color-mix(in srgb, ${CONF_COLOR[k]} 13%, transparent)` }}>
          {k[0].toUpperCase()}{mix[k]}
        </span>
      ))}
    </div>
  )
}

function FrameworkCard({ id, card, meta, minConf }:
  { id: string; card: ComplianceFramework; meta?: ComplianceFrameworkMeta; minConf: number }) {
  const [open, setOpen] = useState(false)
  const [srcOpen, setSrcOpen] = useState(false)
  const pass = card.pass_rate >= minConf
  const failed = [...new Set(card.failed_controls)]
  const prov = card.control_provenance ?? {}
  return (
    <Card className="overflow-hidden">
      <div className="p-5">
        <div className="flex items-start justify-between gap-2 mb-1">
          <div className="min-w-0">
            <div className="font-bold text-ink truncate">{meta?.name ?? id}</div>
            <div className="text-[11px] text-ink3 flex items-center gap-1.5 mt-0.5 flex-wrap">
              {meta?.version && <span>v{meta.version}</span>}
              {meta?.authority && <span>· {meta.authority}</span>}
              {card.derived && <span className="inline-flex items-center gap-1" style={{ color: 'var(--accent)' }}><Waypoints size={10} /> via NIST 800-53</span>}
            </div>
          </div>
          <span className="shrink-0 text-xs font-bold px-2 py-0.5 rounded-full" style={{ color: pass ? 'var(--low)' : 'var(--crit)', background: pass ? 'var(--lowbg)' : 'var(--critbg)' }}>{pass ? 'Pass' : 'Fail'}</span>
        </div>
        <div className="flex items-end gap-2 mb-2 mt-2">
          <span className="text-3xl font-extrabold tabular-nums leading-none" style={{ color: scoreColor(card.pass_rate) }}>{card.pass_rate.toFixed(0)}%</span>
          <span className="text-xs text-ink3 mb-0.5">{card.controls_passed}/{card.controls_total} controls</span>
          {card.derived && <span className="ml-auto"><ConfPill mix={card.confidence_mix} /></span>}
        </div>
        <StackBar parts={[{ value: card.controls_passed, color: scoreColor(card.pass_rate) }, { value: card.controls_failed, color: 'var(--line)' }]} />
        <div className="flex items-center gap-3 mt-3">
          {failed.length > 0 && (
            <button onClick={() => setOpen((v) => !v)} className="flex items-center gap-1 text-xs font-semibold text-accent">
              {open ? <ChevronDown size={13} /> : <ChevronRight size={13} />} {failed.length} failing control{failed.length === 1 ? '' : 's'}
            </button>
          )}
          {meta && meta.sources.length > 0 && (
            <button onClick={() => setSrcOpen((v) => !v)} className="flex items-center gap-1 text-xs text-ink3 hover:text-ink ml-auto"><Info size={12} /> sources</button>
          )}
        </div>
      </div>
      {srcOpen && meta && (
        <div className="px-5 pb-4 border-t border-line2 pt-3 flex flex-col gap-1">
          {meta.description && <p className="text-[11px] text-ink3 leading-relaxed mb-1">{meta.description}</p>}
          {meta.sources.map((s, i) => (
            <a key={i} href={s} target="_blank" rel="noreferrer" className="text-[11px] text-accent flex items-center gap-1 truncate"><ExternalLink size={10} className="shrink-0" /> {s}</a>
          ))}
        </div>
      )}
      {open && (
        <div className="px-5 pb-5 flex gap-1.5 flex-wrap border-t border-line2 pt-3">
          {failed.map((ctrl, i) => {
            const p = prov[ctrl]
            const tip = p ? `${id} ${ctrl} ← NIST ${p.via_nist.join(', ')} · ${p.confidence}` : ctrl
            return (
              <Link to="/findings" key={i} title={tip}
                className="font-mono text-xs rounded-md px-2 py-1 hover:border-accent/40 border border-line flex items-center gap-1"
                style={{ background: 'var(--panel2)', color: 'var(--ink2)' }}>
                {ctrl}
                {p && <span className="text-[9px] font-bold" style={{ color: CONF_COLOR[p.confidence] }}>{p.confidence[0].toUpperCase()}</span>}
              </Link>
            )
          })}
        </div>
      )}
    </Card>
  )
}

export function Compliance() {
  const { scope } = useScope()
  const isOrg = scope === 'org'
  const [minConf, setMinConf] = useState(80)     // conformance-% threshold (pass/fail label)
  const [conf, setConf] = useState<Conf>('any')  // mapping-confidence tier (re-derives)
  const [fam, setFam] = useState('all')

  const { data, loading, error } = useFetch<Bundle>(
    () => Promise.all([
      isOrg
        ? activeAccountIds().then((ids) => Promise.all(ids.map((id) => api.accountCompliance(id, { minConfidence: conf === 'any' ? undefined : conf })))).then(mergeAll)
        : api.accountCompliance(scope, { minConfidence: conf === 'any' ? undefined : conf }),
      api.complianceFrameworks(),
    ]).then(([comp, fw]) => ({ comp, meta: new Map(fw.frameworks.map((m) => [m.id, m])), version: fw.crosswalk_version })),
    [scope, conf])

  if (loading) return <Loader />
  if (error) return <ErrorNote msg={error} />
  if (!data) return null

  const { comp, meta } = data
  const native = Object.entries(comp.native)
  const families = ['all', ...[...new Set([...meta.values()].filter((m) => !m.native).map((m) => m.family))].sort()]
  const derived = Object.entries(comp.derived)
    .filter(([id]) => fam === 'all' || meta.get(id)?.family === fam)
    .sort((a, b) => a[1].pass_rate - b[1].pass_rate)
  const passingD = derived.filter(([, c]) => c.pass_rate >= minConf).length

  return (
    <div className="p-6 md:p-8 max-w-[1440px] mx-auto">
      <div className="flex items-start justify-between gap-4 mb-4 flex-wrap">
        <div>
          <h1 className="text-2xl font-extrabold tracking-tight text-ink flex items-center gap-2"><ShieldCheck size={22} className="text-accent" /> Compliance</h1>
          <p className="text-ink2 text-sm mt-1">{isOrg ? 'Organization' : `Account ${scope}`} · {native.length} directly tested + {derived.length} crosswalk-derived · {passingD}/{derived.length} derived at ≥ {minConf}%</p>
        </div>
        <label className="flex items-center gap-2 text-sm text-ink2">
          Min conformance
          <input type="number" min={0} max={100} value={minConf}
            onChange={(e) => setMinConf(Math.max(0, Math.min(100, Number(e.target.value) || 0)))}
            className="w-16 rounded-lg border border-line bg-panel px-2 py-1 text-sm text-ink text-right tabular-nums" /> %
        </label>
      </div>

      {/* directly tested (native) */}
      <div className="flex items-center gap-2 mb-3">
        <span className="h-[3px] w-6 rounded ow-grad" />
        <span className="text-sm font-bold text-ink">Directly tested</span>
        <span className="text-xs text-ink3">— {native.length} frameworks with per-check control tags</span>
      </div>
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 mb-8">
        {native.map(([fw, c]) => <FrameworkCard key={fw} id={fw} card={c} meta={meta.get(fw)} minConf={minConf} />)}
      </div>

      {/* crosswalk-derived */}
      <div className="flex items-center gap-2 mb-3 flex-wrap">
        <span className="h-[3px] w-6 rounded ow-grad" />
        <span className="text-sm font-bold text-ink">Crosswalk-derived via NIST 800-53</span>
        <span className="text-xs text-ink3">— coverage inferred from the NIST spine</span>
        <div className="ml-auto flex items-center gap-2 flex-wrap">
          <select value={fam} onChange={(e) => setFam(e.target.value)} className="rounded-lg border border-line bg-panel px-2 py-1 text-xs text-ink capitalize">
            {families.map((f) => <option key={f} value={f}>{f === 'all' ? 'all families' : f}</option>)}
          </select>
          <span className="text-xs text-ink3">confidence</span>
          {(['any', 'high', 'medium', 'low'] as Conf[]).map((k) => (
            <button key={k} onClick={() => setConf(k)}
              className="rounded-lg px-2 py-1 text-xs font-semibold border transition-colors capitalize"
              style={{ borderColor: conf === k ? (k === 'any' ? 'var(--accent)' : CONF_COLOR[k]) : 'var(--line)',
                color: conf === k ? (k === 'any' ? 'var(--accent)' : CONF_COLOR[k]) : 'var(--ink3)',
                background: conf === k ? 'var(--panel2)' : 'var(--panel)' }}>{k}</button>
          ))}
        </div>
      </div>
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {derived.map(([fw, c]) => <FrameworkCard key={fw} id={fw} card={c} meta={meta.get(fw)} minConf={minConf} />)}
      </div>

      <div className="flex items-start gap-2 mt-6 rounded-xl border border-line px-4 py-3 text-xs text-ink2" style={{ background: 'var(--panel2)' }}>
        <Info size={14} className="mt-0.5 shrink-0 text-ink3" />
        <span>Crosswalk-derived frameworks are inferred from the NIST 800-53 control each check is tagged with, using published authoritative crosswalks (confidence shown per mapping). They are <b>informational</b> — confirm exact scope and applicability with your assessor. The 5 directly-tested frameworks carry per-check control tags. Crosswalk {data.version}.</span>
      </div>
    </div>
  )
}

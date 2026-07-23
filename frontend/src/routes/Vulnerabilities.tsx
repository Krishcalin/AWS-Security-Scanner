import { useState } from 'react'
import {
  ShieldAlert, Upload, ChevronRight, ChevronDown, Flame, Gem, Waypoints,
  Globe, CircleOff, X, Loader2,
} from 'lucide-react'
import { useScope, isOrgScope } from '../state/scope'
import { useFetch } from '../lib/useFetch'
import { api } from '../api/client'
import { Card, Loader, ErrorNote, Empty } from '../components/ui'
import { sevColor } from '../lib/format'
import type { IngestedVuln } from '../api/types'

const RANK: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 }

// The REACHABILITY chip is the visual anchor — not CVSS. A high-CVSS unreachable
// CVE renders muted; a KEV reaching a crown datastore renders critical-red.
function reachChip(v: IngestedVuln): { label: string; fg: string; bg: string; Icon: typeof Gem } {
  if (v.suppressed) return { label: 'VEX suppressed', fg: 'var(--ink3)', bg: 'var(--panel2)', Icon: CircleOff }
  if (v.reaches_crown) return { label: 'Internet → crown', fg: 'var(--crit)', bg: 'var(--critbg)', Icon: Gem }
  if (v.on_attack_path) return { label: 'on attack path', fg: 'var(--high)', bg: 'var(--highbg)', Icon: Waypoints }
  if (v.reachable_from_internet) return { label: 'internet-reachable', fg: 'var(--med)', bg: 'var(--medbg)', Icon: Globe }
  return { label: 'not reachable', fg: 'var(--ink3)', bg: 'var(--panel2)', Icon: CircleOff }
}

function srcLabel(s: string): string {
  return s.startsWith('ingest:') ? s.slice(7) : s
}

function Row({ v, open, onToggle }: { v: IngestedVuln; open: boolean; onToggle: () => void }) {
  const rc = reachChip(v)
  const muted = v.suppressed || !v.on_attack_path
  return (
    <div className="border-b border-line last:border-0">
      <button onClick={onToggle}
        className={`flex w-full items-center gap-3 px-3 py-2.5 text-left hover:bg-panel2 transition-colors ${muted ? 'opacity-70' : ''}`}>
        <span className="shrink-0 text-ink3">{open ? <ChevronDown size={15} /> : <ChevronRight size={15} />}</span>
        {/* score stripe + value */}
        <span className="w-10 text-right shrink-0">
          <span className="font-mono text-sm font-bold tabular-nums" style={{ color: sevColor(v.priority_band) }}>{v.priority_score}</span>
        </span>
        <span className="h-6 w-1.5 rounded-full shrink-0" style={{ background: sevColor(v.priority_band) }} />
        <div className="min-w-0 w-44">
          <div className="font-mono text-[13px] font-semibold text-ink truncate flex items-center gap-1.5">
            {v.cve}
            {v.kev && <Flame size={12} style={{ color: 'var(--crit)' }} aria-label="KEV — known exploited" />}
          </div>
          <div className="text-[11px] text-ink3 truncate">{v.package}@{v.installed_version}</div>
        </div>
        {/* reachability chip — the anchor */}
        <span className="text-[11px] font-semibold px-2 py-0.5 rounded-full flex items-center gap-1 whitespace-nowrap"
          style={{ color: rc.fg, background: rc.bg }}><rc.Icon size={11} /> {rc.label}</span>
        <span className="font-mono text-[11px] text-ink3 truncate hidden lg:block flex-1">{String(v.node_id).split('/').pop()}</span>
        <span className="text-[11px] text-ink3 w-16 text-right hidden md:block tabular-nums">
          {v.epss != null ? `EPSS ${(v.epss * 100).toFixed(0)}%` : '—'}
        </span>
        <div className="hidden xl:flex items-center gap-1 w-32 justify-end">
          {v.sources.slice(0, 2).map((s) => (
            <span key={s} className="text-[10px] font-semibold px-1.5 py-0.5 rounded bg-panel2 text-ink2">{srcLabel(s)}</span>
          ))}
        </div>
      </button>
      {open && (
        <div className="px-11 pb-3 pt-1 text-xs text-ink2 flex flex-col gap-2">
          {v.driving_path ? (
            <div>
              <div className="text-[10px] uppercase tracking-wide text-ink3 mb-1">Driving path</div>
              <div className="flex flex-wrap items-center gap-1 font-mono text-[11px]">
                {v.driving_path.split(' -> ').map((n, i, arr) => (
                  <span key={i} className="flex items-center gap-1">
                    <span className="px-1.5 py-0.5 rounded bg-panel2 text-ink">{n}</span>
                    {i < arr.length - 1 && <ChevronRight size={11} className="text-ink3" />}
                  </span>
                ))}
              </div>
            </div>
          ) : (
            <div className="text-ink3">No end-to-end attack path — ranked by intrinsic exploitability only.</div>
          )}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-x-6 gap-y-1">
            <Field k="Severity (CVSS)" v={`${v.severity}${v.cvss_base != null ? ` · ${v.cvss_base}` : ''}`} />
            <Field k="Fix version" v={v.fixed_version ?? 'none available'} />
            <Field k="Owner" v={`${v.node_kind} · ${v.mapping_status}`} />
            <Field k="Reporters" v={v.sources.map(srcLabel).join(', ')} />
            <Field k="KEV" v={v.kev ? 'yes — known exploited' : 'no'} />
            <Field k="Exploit" v={v.exploit_available === 'YES' ? 'available' : '—'} />
            <Field k="Reaches crown" v={v.reaches_crown ? `yes (${v.terminal_kinds.join(', ')})` : 'no'} />
            {v.suppressed && <Field k="VEX" v="suppressed (not_affected / false_positive)" />}
          </div>
        </div>
      )}
    </div>
  )
}

function Field({ k, v }: { k: string; v: string }) {
  return (
    <div className="min-w-0">
      <div className="text-[10px] uppercase tracking-wide text-ink3">{k}</div>
      <div className="text-[12px] text-ink truncate">{v}</div>
    </div>
  )
}

function Stat({ n, label, tone }: { n: number; label: string; tone: string }) {
  return (
    <div className="rounded-xl border border-line bg-panel px-4 py-3 shadow-sm">
      <div className="text-2xl font-extrabold tabular-nums leading-none" style={{ color: tone }}>{n}</div>
      <div className="text-xs text-ink3 mt-1">{label}</div>
    </div>
  )
}

type Facet = 'reachable' | 'kev' | 'onpath' | 'all'

export function Vulnerabilities() {
  const { scope } = useScope()
  const org = isOrgScope(scope)
  const { data, loading, error } = useFetch<IngestedVuln[]>(
    () => (org ? api.orgVulns() : api.listVulns(scope)), [scope])
  const [facet, setFacet] = useState<Facet>('reachable')
  const [showSuppressed, setShowSuppressed] = useState(false)
  const [openKey, setOpenKey] = useState<string | null>(null)
  const [upload, setUpload] = useState(false)

  if (loading) return <Loader />
  if (error) return <ErrorNote msg={error} />
  const all = data ?? []

  const kevReach = all.filter((v) => v.kev && v.on_attack_path && !v.suppressed).length
  const reachable = all.filter((v) => v.on_attack_path && !v.suppressed).length

  let rows = all
  if (!showSuppressed) rows = rows.filter((v) => !v.suppressed)
  if (facet === 'reachable') rows = rows.filter((v) => v.on_attack_path || (v.kev && !v.suppressed))
  else if (facet === 'kev') rows = rows.filter((v) => v.kev)
  else if (facet === 'onpath') rows = rows.filter((v) => v.on_attack_path)
  rows = [...rows].sort((a, b) => b.priority_score - a.priority_score
    || (RANK[a.priority_band] ?? 9) - (RANK[b.priority_band] ?? 9))

  const facetBtn = (id: Facet, label: string) => (
    <button onClick={() => setFacet(id)} className="px-3 py-1.5 text-xs font-semibold rounded-lg border border-line"
      style={{ background: facet === id ? 'var(--accent)' : 'var(--panel)', color: facet === id ? '#fff' : 'var(--ink2)' }}>{label}</button>
  )

  return (
    <div className="p-6 md:p-8 max-w-[1440px] mx-auto">
      <div className="flex items-start justify-between gap-4 mb-5 flex-wrap">
        <div>
          <h1 className="text-2xl font-extrabold tracking-tight text-ink flex items-center gap-2">
            <ShieldAlert size={22} className="text-accent" /> Vulnerabilities
          </h1>
          <p className="text-ink2 text-sm mt-1">
            {org ? 'Organization' : `Account ${scope}`} · external scanner CVEs, ranked by <b className="text-ink">actual reachability</b> — not CVSS
          </p>
        </div>
        {!org && (
          <button onClick={() => setUpload(true)}
            className="inline-flex items-center gap-2 rounded-lg px-4 py-2 text-sm font-semibold text-white ow-grad shadow-sm hover:opacity-90">
            <Upload size={16} /> Upload scan
          </button>
        )}
      </div>

      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-5">
        <Stat n={all.length} label="External CVEs owned" tone="var(--ink)" />
        <Stat n={reachable} label="Reachable (on attack path)" tone="var(--high)" />
        <Stat n={kevReach} label="Reachable KEV" tone="var(--crit)" />
        <Stat n={all.filter((v) => v.suppressed).length} label="VEX-suppressed" tone="var(--ink3)" />
      </div>

      <div className="flex items-center gap-2 mb-4 flex-wrap">
        {facetBtn('reachable', 'Reachable + KEV')}
        {facetBtn('kev', 'KEV only')}
        {facetBtn('onpath', 'On attack path')}
        {facetBtn('all', 'All')}
        <label className="ml-auto text-xs text-ink2 flex items-center gap-1.5 cursor-pointer">
          <input type="checkbox" checked={showSuppressed} onChange={(e) => setShowSuppressed(e.target.checked)} />
          Show VEX-suppressed
        </label>
      </div>

      {rows.length === 0 ? (
        <Card><Empty icon={<ShieldAlert size={26} />}>
          No externally-reported CVEs in this view. Upload a SARIF / CycloneDX / SPDX scan to own and rank them.
        </Empty></Card>
      ) : (
        <Card className="overflow-hidden">
          {rows.map((v) => {
            const key = `${v.account ?? ''}|${v.node_id}|${v.cve}`
            return <Row key={key} v={v} open={openKey === key} onToggle={() => setOpenKey(openKey === key ? null : key)} />
          })}
        </Card>
      )}

      {upload && <UploadModal account={scope} onClose={() => setUpload(false)} />}
    </div>
  )
}

function UploadModal({ account, onClose }: { account: string; onClose: () => void }) {
  const [text, setText] = useState('')
  const [target, setTarget] = useState('')
  const [busy, setBusy] = useState(false)
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null)

  const submit = async () => {
    setBusy(true); setMsg(null)
    try {
      const doc = JSON.parse(text)
      const r = await api.ingest(account, doc, target || undefined)
      setMsg({ ok: true, text: `Ingested ${r.finding_count} finding(s) → ${r.resolved_node} (${r.mapping_status}).` })
    } catch (e) {
      setMsg({ ok: false, text: e instanceof SyntaxError ? 'Not valid JSON.' : `Ingest failed: ${(e as Error).message}` })
    } finally { setBusy(false) }
  }

  return (
    <div className="fixed inset-0 z-50 grid place-items-center bg-black/50 p-4" onClick={onClose}>
      <div className="w-full max-w-2xl rounded-2xl border border-line bg-panel shadow-xl" onClick={(e) => e.stopPropagation()}>
        <div className="flex items-center justify-between px-5 py-3 border-b border-line">
          <div className="text-sm font-bold text-ink flex items-center gap-2"><Upload size={16} className="text-accent" /> Upload scanner output</div>
          <button onClick={onClose} className="text-ink3 hover:text-ink"><X size={18} /></button>
        </div>
        <div className="p-5 flex flex-col gap-3">
          <p className="text-xs text-ink2">Paste a <b>SARIF</b> (Trivy/Grype/Snyk), <b>CycloneDX</b>, or <b>SPDX</b> document. OverWatch owns its CVEs against this account's graph and ranks them by attack-path reachability.</p>
          <input value={target} onChange={(e) => setTarget(e.target.value)}
            placeholder="Target resource (optional) — EC2/Lambda ARN or image ref"
            className="rounded-lg border border-line bg-panel px-3 py-2 text-sm text-ink placeholder:text-ink3 outline-none focus:border-accent/50 font-mono" />
          <textarea value={text} onChange={(e) => setText(e.target.value)} rows={10}
            placeholder='{"version":"2.1.0","runs":[…]}'
            className="rounded-lg border border-line bg-panel px-3 py-2 text-xs text-ink placeholder:text-ink3 outline-none focus:border-accent/50 font-mono resize-none" />
          {msg && (
            <div className="text-xs px-3 py-2 rounded-lg" style={{ color: msg.ok ? 'var(--low)' : 'var(--crit)', background: msg.ok ? 'var(--lowbg)' : 'var(--critbg)' }}>{msg.text}</div>
          )}
          <div className="flex justify-end gap-2">
            <button onClick={onClose} className="px-4 py-2 text-sm font-semibold text-ink2 rounded-lg border border-line hover:bg-panel2">Close</button>
            <button onClick={submit} disabled={busy || !text.trim()}
              className="inline-flex items-center gap-2 px-4 py-2 text-sm font-semibold text-white ow-grad rounded-lg disabled:opacity-50">
              {busy ? <Loader2 size={15} className="animate-spin" /> : <Upload size={15} />} Ingest
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}

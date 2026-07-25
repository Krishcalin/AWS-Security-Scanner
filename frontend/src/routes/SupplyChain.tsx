import { useState, type ReactNode } from 'react'
import {
  Boxes, GitCompareArrows, Scale, ShieldQuestion, Plus, Minus, ArrowRight,
  ShieldAlert, ShieldCheck, FileClock,
} from 'lucide-react'
import { useScope, isOrgScope } from '../state/scope'
import { useFetch } from '../lib/useFetch'
import { api } from '../api/client'
import { Card, Loader, ErrorNote, Empty, Chip } from '../components/ui'
import type {
  SbomSubject, SbomDiffData, SbomComponent, LicenseFinding, VexStatementRow,
} from '../api/types'

type Tab = 'diff' | 'components' | 'vex'

// license category → tone (semantic, separate from the accent): deny-worthy = red,
// review = amber, allow = green/neutral.
const LIC: Record<string, { fg: string; bg: string; label: string }> = {
  network_copyleft: { fg: 'var(--crit)', bg: 'var(--critbg)', label: 'network copyleft' },
  proprietary: { fg: 'var(--crit)', bg: 'var(--critbg)', label: 'proprietary' },
  strong_copyleft: { fg: 'var(--high)', bg: 'var(--highbg)', label: 'strong copyleft' },
  unknown: { fg: 'var(--med)', bg: 'var(--medbg)', label: 'unknown' },
  weak_copyleft: { fg: 'var(--ink2)', bg: 'var(--panel2)', label: 'weak copyleft' },
  permissive: { fg: 'var(--low)', bg: 'var(--lowbg)', label: 'permissive' },
}
const licTone = (c?: string | null) => LIC[c || 'unknown'] ?? LIC.unknown

const VEX_TONE: Record<string, { fg: string; bg: string }> = {
  not_affected: { fg: 'var(--low)', bg: 'var(--lowbg)' },
  fixed: { fg: 'var(--low)', bg: 'var(--lowbg)' },
  affected: { fg: 'var(--crit)', bg: 'var(--critbg)' },
  under_investigation: { fg: 'var(--med)', bg: 'var(--medbg)' },
}

function Page({ title, sub, children }: { title: string; sub: string; children: ReactNode }) {
  return (
    <div className="p-6 md:p-8 max-w-[1440px] mx-auto">
      <div className="mb-5">
        <h1 className="text-2xl font-extrabold tracking-tight text-ink flex items-center gap-2">
          <Boxes size={22} className="text-accent" /> {title}
        </h1>
        <p className="text-ink2 text-sm mt-1">{sub}</p>
      </div>
      {children}
    </div>
  )
}

const short = (p: string) => p.replace(/^pkg:/, '').split('?')[0]

// ── SBOM diff ─────────────────────────────────────────────────────────────────
function DeltaRow({ d }: { d: SbomDiffData['added'][number] }) {
  // a changed component can differ in BOTH version and license — render each independently
  // rather than trusting a single mutually-exclusive `change` label.
  const changed = d.change === 'version_changed' || d.change === 'license_changed'
  const verChanged = changed && d.from_version !== d.to_version
  const licChanged = changed && (d.from_license || '') !== (d.to_license || '')
  return (
    <div className="flex items-center gap-3 px-3 py-2 rounded-lg hover:bg-panel2 transition-colors text-sm">
      <span className="font-semibold text-ink truncate max-w-[240px]">{d.name || short(d.purl_identity)}</span>
      {verChanged && (
        <span className="text-xs text-ink2 flex items-center gap-1.5 font-mono">
          {d.from_version} <ArrowRight size={11} className="text-ink3" /> <b className="text-ink">{d.to_version}</b>
        </span>
      )}
      {licChanged && (
        <span className="text-xs flex items-center gap-1.5">
          <Chip fg={licTone(d.from_license).fg} bg={licTone(d.from_license).bg} mono>{d.from_license || '—'}</Chip>
          <ArrowRight size={11} className="text-ink3" />
          <Chip fg={licTone(d.to_license).fg} bg={licTone(d.to_license).bg} mono>{d.to_license || '—'}</Chip>
        </span>
      )}
      <span className="font-mono text-[11px] text-ink3 truncate ml-auto">{short(d.purl_identity)}</span>
    </div>
  )
}

function DiffSection({ title, icon, tone, rows }: { title: string; icon: ReactNode; tone: string; rows: SbomDiffData['added'] }) {
  if (rows.length === 0) return null
  return (
    <Card className="p-4">
      <div className="flex items-center gap-2 mb-2 text-sm font-bold" style={{ color: tone }}>
        {icon} {title} <span className="text-ink3 font-normal">{rows.length}</span>
      </div>
      <div className="flex flex-col">{rows.map((d, i) => <DeltaRow key={i} d={d} />)}</div>
    </Card>
  )
}

function DiffTab({ id }: { id: string }) {
  const subjects = useFetch<SbomSubject[]>(() => api.sbomSubjects(id), [id])
  const [subject, setSubject] = useState<string | null>(null)
  const subs = subjects.data ?? []
  const chosen = subject ?? subs[0]?.subject_key ?? null
  const diff = useFetch<SbomDiffData | null>(
    () => (chosen ? api.sbomDiff(id, { subject: chosen }) : Promise.resolve(null)), [id, chosen])

  if (subjects.loading) return <Loader />
  if (subjects.error) return <ErrorNote msg={subjects.error} />
  if (subs.length === 0) {
    return <Card><Empty icon={<GitCompareArrows size={26} />}>
      No SBOM snapshots yet. Post one from CI with the <b>OverWatch Image Scan</b> Action, then two builds become a diff.
    </Empty></Card>
  }
  const d = diff.data

  return (
    <div className="flex flex-col gap-4">
      <div className="flex items-center gap-2 flex-wrap">
        <span className="text-xs text-ink3">Subject</span>
        <select value={chosen ?? ''} onChange={(e) => setSubject(e.target.value)}
          className="rounded-lg border border-line bg-panel px-2 py-1.5 text-sm text-ink font-mono max-w-md">
          {subs.map((s) => <option key={s.subject_key} value={s.subject_key}>{short(s.subject_key)} · {s.snapshots} snapshots</option>)}
        </select>
      </div>

      {diff.loading ? <Loader /> : !d ? (
        <Card><Empty icon={<GitCompareArrows size={26} />}>This subject has only one snapshot — a second build makes it diffable.</Empty></Card>
      ) : (
        <>
          {(d.cve_delta.new.length > 0 || d.cve_delta.fixed.length > 0) && (
            <Card className="p-4">
              <div className="text-sm font-bold text-ink mb-2 flex items-center gap-1.5"><ShieldAlert size={15} className="text-accent" /> CVE delta between builds</div>
              <div className="flex gap-6 flex-wrap">
                <div>
                  <div className="text-xs font-semibold mb-1" style={{ color: 'var(--crit)' }}>+{d.cve_delta.new.length} new</div>
                  <div className="flex gap-1.5 flex-wrap">{d.cve_delta.new.map((c) => <Chip key={c} fg="var(--crit)" bg="var(--critbg)" mono>{c}</Chip>)}</div>
                </div>
                <div>
                  <div className="text-xs font-semibold mb-1" style={{ color: 'var(--low)' }}>−{d.cve_delta.fixed.length} fixed</div>
                  <div className="flex gap-1.5 flex-wrap">{d.cve_delta.fixed.map((c) => <Chip key={c} fg="var(--low)" bg="var(--lowbg)" mono>{c}</Chip>)}</div>
                </div>
              </div>
            </Card>
          )}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            <DiffSection title="Added" icon={<Plus size={15} />} tone="var(--crit)" rows={d.added} />
            <DiffSection title="Removed" icon={<Minus size={15} />} tone="var(--low)" rows={d.removed} />
            <DiffSection title="Changed" icon={<GitCompareArrows size={15} />} tone="var(--accent)" rows={d.changed} />
          </div>
          {d.added.length + d.removed.length + d.changed.length === 0 && (
            <Card><Empty icon={<ShieldCheck size={26} />}>No component changes between the latest two snapshots.</Empty></Card>
          )}
        </>
      )}
    </div>
  )
}

// ── components + license ────────────────────────────────────────────────────────
function ComponentsTab({ id }: { id: string }) {
  const [licFilter, setLicFilter] = useState<string | null>(null)
  const comps = useFetch<SbomComponent[]>(() => api.components(id, licFilter ? { license: licFilter } : {}), [id, licFilter])
  const findings = useFetch<LicenseFinding[]>(() => api.licenseFindings(id), [id])
  const rows = comps.data ?? []
  const lf = findings.data ?? []

  if (comps.loading) return <Loader />
  if (comps.error) return <ErrorNote msg={comps.error} />
  if ((comps.data ?? []).length === 0 && !licFilter) {
    return <Card><Empty icon={<Scale size={26} />}>No SBOM components yet. Post an SBOM from CI to inventory licenses.</Empty></Card>
  }

  const cats = ['network_copyleft', 'proprietary', 'strong_copyleft', 'unknown', 'weak_copyleft', 'permissive']
  return (
    <div className="flex flex-col gap-4">
      {lf.length > 0 && (
        <Card className="p-4">
          <div className="text-sm font-bold text-ink mb-1 flex items-center gap-1.5"><ShieldAlert size={15} style={{ color: 'var(--crit)' }} /> License policy</div>
          <div className="text-xs text-ink2">
            <b style={{ color: 'var(--crit)' }}>{lf.filter((f) => f.verdict === 'deny').length} denied</b> ·{' '}
            <b style={{ color: 'var(--med)' }}>{lf.filter((f) => f.verdict === 'review').length} to review</b> — computed on read from the current policy.
          </div>
        </Card>
      )}
      <div className="flex items-center gap-2 flex-wrap">
        <button onClick={() => setLicFilter(null)} className="rounded-lg px-2.5 py-1 text-xs font-semibold border"
          style={{ borderColor: !licFilter ? 'var(--accent)' : 'var(--line)', color: !licFilter ? 'var(--accent)' : 'var(--ink2)', background: !licFilter ? 'var(--accentdim)' : 'var(--panel)' }}>All</button>
        {cats.map((c) => (
          <button key={c} onClick={() => setLicFilter(c)} className="rounded-lg px-2.5 py-1 text-xs font-semibold border"
            style={{ borderColor: licFilter === c ? licTone(c).fg : 'var(--line)', color: licFilter === c ? licTone(c).fg : 'var(--ink2)', background: licFilter === c ? licTone(c).bg : 'var(--panel)' }}>
            {licTone(c).label}
          </button>
        ))}
      </div>
      {rows.length === 0 ? <Card><Empty icon={<Scale size={24} />}>No components in this filter.</Empty></Card> : (
        <Card className="overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead><tr className="text-left text-xs text-ink3 border-b border-line">
                <th className="px-4 py-2.5 font-semibold">Component</th>
                <th className="px-4 py-2.5 font-semibold">Version</th>
                <th className="px-4 py-2.5 font-semibold">License</th>
                <th className="px-4 py-2.5 font-semibold hidden md:table-cell">Category</th>
              </tr></thead>
              <tbody>
                {rows.map((c, i) => (
                  <tr key={i} className="border-b border-line2 last:border-0 hover:bg-panel2">
                    <td className="px-4 py-2.5"><span className="font-semibold text-ink">{c.name || short(c.purl_identity)}</span></td>
                    <td className="px-4 py-2.5 font-mono text-xs text-ink2">{c.version || '—'}</td>
                    <td className="px-4 py-2.5 font-mono text-xs text-ink">{c.license_spdx || '—'}</td>
                    <td className="px-4 py-2.5 hidden md:table-cell"><Chip fg={licTone(c.license_category).fg} bg={licTone(c.license_category).bg}>{licTone(c.license_category).label}</Chip></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      )}
    </div>
  )
}

// ── VEX ─────────────────────────────────────────────────────────────────────────
function VexTab({ id }: { id: string }) {
  const vex = useFetch<VexStatementRow[]>(() => api.vexStatements(id), [id])
  if (vex.loading) return <Loader />
  if (vex.error) return <ErrorNote msg={vex.error} />
  const rows = vex.data ?? []
  if (rows.length === 0) {
    return <Card><Empty icon={<ShieldQuestion size={26} />}>
      No VEX statements. Upload an <b>OpenVEX</b> or <b>CSAF-VEX</b> document to suppress false positives with an auditable justification.
    </Empty></Card>
  }
  return (
    <Card className="overflow-hidden">
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead><tr className="text-left text-xs text-ink3 border-b border-line">
            <th className="px-4 py-2.5 font-semibold">CVE</th>
            <th className="px-4 py-2.5 font-semibold">Status</th>
            <th className="px-4 py-2.5 font-semibold">Scope</th>
            <th className="px-4 py-2.5 font-semibold hidden lg:table-cell">Justification</th>
            <th className="px-4 py-2.5 font-semibold hidden md:table-cell">Format</th>
          </tr></thead>
          <tbody>
            {rows.map((v, i) => {
              const t = VEX_TONE[v.status] ?? VEX_TONE.under_investigation
              return (
                <tr key={i} className="border-b border-line2 last:border-0 hover:bg-panel2">
                  <td className="px-4 py-2.5 font-mono text-xs font-bold text-ink">{v.cve}</td>
                  <td className="px-4 py-2.5"><Chip fg={t.fg} bg={t.bg}>{v.status.replace(/_/g, ' ')}</Chip></td>
                  <td className="px-4 py-2.5 font-mono text-[11px] text-ink3">{v.purl_identity === '*' ? 'product-wide' : short(v.purl_identity)}</td>
                  <td className="px-4 py-2.5 text-xs text-ink2 hidden lg:table-cell">{v.justification || '—'}</td>
                  <td className="px-4 py-2.5 hidden md:table-cell"><Chip>{v.vex_format}</Chip></td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>
    </Card>
  )
}

export function SupplyChain() {
  const { scope } = useScope()
  const [tab, setTab] = useState<Tab>('diff')

  if (isOrgScope(scope)) {
    return (
      <Page title="Supply Chain" sub="SBOM diff · license policy · VEX — per account">
        <Card><Empty icon={<Boxes size={28} />}>Select a specific account in the scope switcher to view its SBOM timeline, license posture, and VEX statements.</Empty></Card>
      </Page>
    )
  }

  const TABS: { k: Tab; label: string; icon: ReactNode }[] = [
    { k: 'diff', label: 'SBOM Diff', icon: <GitCompareArrows size={15} /> },
    { k: 'components', label: 'Components & License', icon: <Scale size={15} /> },
    { k: 'vex', label: 'VEX', icon: <FileClock size={15} /> },
  ]

  return (
    <Page title="Supply Chain" sub={`Account ${scope} · component timeline, license policy, and VEX`}>
      <div className="flex items-center gap-1 border-b border-line mb-4">
        {TABS.map((t) => (
          <button key={t.k} onClick={() => setTab(t.k)}
            className="relative px-3.5 py-2 text-sm font-semibold transition-colors flex items-center gap-1.5"
            style={{ color: tab === t.k ? 'var(--accent)' : 'var(--ink2)' }}>
            {t.icon} {t.label}
            {tab === t.k && <span className="absolute left-2 right-2 -bottom-px h-[2px] rounded ow-grad" />}
          </button>
        ))}
      </div>
      {tab === 'diff' && <DiffTab id={scope} />}
      {tab === 'components' && <ComponentsTab id={scope} />}
      {tab === 'vex' && <VexTab id={scope} />}
    </Page>
  )
}

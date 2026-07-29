import { Link } from 'react-router'
import { Database, Lock, LockOpen, Globe, Users, ShieldAlert, ArrowRight } from 'lucide-react'
import { useScope, isOrgScope } from '../state/scope'
import { useFetch } from '../lib/useFetch'
import { api } from '../api/client'
import { Card, Loader, ErrorNote, Empty } from '../components/ui'
import { nodeMeta } from '../lib/nodes'
import type { DataInventory, OrgDataInventory, DataStore } from '../api/types'

// data-type -> tone (regulated data reads hottest)
const TYPE_TONE: Record<string, string> = {
  PCI: 'var(--crit)', PHI: 'var(--crit)', PII: 'var(--high)',
  FINANCIAL: 'var(--gold)', SECRET: 'var(--crit)', AI: 'var(--info)',
}
const typeTone = (t: string) => TYPE_TONE[t] ?? 'var(--ink2)'

function TypeChip({ t }: { t: string }) {
  return (
    <span className="rounded px-1.5 py-0.5 text-[11px] font-bold" style={{ color: typeTone(t), background: 'var(--panel2)' }}>{t}</span>
  )
}

function Stat({ label, value, tone }: { label: string; value: string | number; tone?: string }) {
  return (
    <Card className="p-4">
      <div className="text-3xl font-extrabold tabular-nums leading-none" style={{ color: tone ?? 'var(--ink)' }}>{value}</div>
      <div className="text-xs font-semibold uppercase tracking-wide mt-2 text-ink3">{label}</div>
    </Card>
  )
}

function StoreRow({ s }: { s: DataStore }) {
  const M = nodeMeta(s.kind)
  const Icon = M.icon
  return (
    <div className="flex items-center gap-3 px-3 py-2 rounded-lg hover:bg-panel2 transition-colors">
      <span className="h-7 w-7 rounded-lg grid place-items-center shrink-0" style={{ background: 'var(--panel2)', color: M.tone }}><Icon size={14} /></span>
      <div className="min-w-0 flex-1">
        <div className="text-sm font-semibold text-ink truncate flex items-center gap-1.5">
          {s.label}
          {s.data_types.map((t) => <TypeChip key={t} t={t} />)}
          {!s.data_types.length && <span className="text-[11px] text-ink3 italic">unclassified type</span>}
        </div>
        <div className="font-mono text-[11px] text-ink3 truncate">{s.node_id}</div>
      </div>
      <span className="text-ink3" title={s.encrypted ? 'encrypted at rest' : 'NOT encrypted'}>
        {s.encrypted ? <Lock size={13} /> : <LockOpen size={13} style={{ color: 'var(--crit)' }} />}
      </span>
      {(s.public || s.reachable_from_internet) && <Globe size={13} style={{ color: 'var(--crit)' }} aria-label="internet-exposed" />}
      <span className="inline-flex items-center gap-1 text-xs text-ink3 w-12 justify-end" title={`${s.reader_count} reader role(s)`}>
        <Users size={12} />{s.reader_count}
      </span>
    </div>
  )
}

// ── org roll-up ───────────────────────────────────────────────────────────────
function OrgData({ data }: { data: OrgDataInventory }) {
  const o = data.overall
  const types = Object.entries(data.by_type).sort((a, b) => b[1] - a[1])
  return (
    <div className="flex flex-col gap-4">
      <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
        <Stat label="Sensitive stores" value={o.total} tone="var(--gold)" />
        <Stat label="Exposed" value={o.exposed} tone={o.exposed ? 'var(--crit)' : 'var(--ok)'} />
        <Stat label="Unencrypted" value={o.unencrypted} tone={o.unencrypted ? 'var(--high)' : 'var(--ok)'} />
      </div>
      <Card className="p-4">
        <div className="text-xs font-bold uppercase tracking-wide text-ink3 mb-3">Regulated data across the org</div>
        {types.length === 0 ? <Empty icon={<Database size={22} />}>No classified sensitive data.</Empty> : (
          <div className="flex flex-wrap gap-2">
            {types.map(([t, c]) => (
              <span key={t} className="rounded-lg px-3 py-1.5 text-sm font-bold" style={{ color: typeTone(t), background: 'var(--panel2)' }}>{t} · {c}</span>
            ))}
          </div>
        )}
      </Card>
      <Card className="p-2">
        <div className="grid grid-cols-[1fr_auto_auto_auto] gap-x-4 px-3 py-2 text-[11px] font-bold uppercase tracking-wide text-ink3">
          <span>Account</span><span className="text-right">Stores</span><span className="text-right">Exposed</span><span className="text-right">Gaps</span>
        </div>
        {data.accounts.map((a) => (
          <Link key={a.account} to={`/data?scope=${a.account}`}
            className="grid grid-cols-[1fr_auto_auto_auto] gap-x-4 items-center px-3 py-2 rounded-lg hover:bg-panel2 transition-colors">
            <span className="font-mono text-sm text-ink truncate">{a.account}</span>
            <span className="text-sm tabular-nums text-ink2 text-right">{a.total}</span>
            <span className="text-sm tabular-nums text-right" style={{ color: a.exposed ? 'var(--crit)' : 'var(--ink3)' }}>{a.exposed}</span>
            <span className="text-sm tabular-nums text-right" style={{ color: a.gap_count ? 'var(--gold)' : 'var(--ink3)' }}>{a.gap_count}</span>
          </Link>
        ))}
      </Card>
    </div>
  )
}

// ── per-account ───────────────────────────────────────────────────────────────
function AccountData({ inv }: { inv: DataInventory }) {
  return (
    <div className="flex flex-col gap-4">
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <Stat label="Sensitive stores" value={inv.total} tone="var(--gold)" />
        <Stat label="Exposed" value={inv.exposed} tone={inv.exposed ? 'var(--crit)' : 'var(--ok)'} />
        <Stat label="Unencrypted" value={inv.unencrypted} tone={inv.unencrypted ? 'var(--high)' : 'var(--ok)'} />
        <Stat label="Classification gaps" value={inv.classification_gaps.length} tone={inv.classification_gaps.length ? 'var(--gold)' : 'var(--ok)'} />
      </div>

      {Object.keys(inv.by_type).length > 0 && (
        <Card className="p-4">
          <div className="text-xs font-bold uppercase tracking-wide text-ink3 mb-3">Regulated data types</div>
          <div className="flex flex-wrap gap-2">
            {Object.entries(inv.by_type).sort((a, b) => b[1] - a[1]).map(([t, c]) => (
              <span key={t} className="rounded-lg px-3 py-1.5 text-sm font-bold" style={{ color: typeTone(t), background: 'var(--panel2)' }}>{t} · {c}</span>
            ))}
          </div>
        </Card>
      )}

      <Card className="p-4">
        <div className="text-xs font-bold uppercase tracking-wide text-ink3 mb-2">Sensitive data stores (ranked by exposure)</div>
        {inv.stores.length === 0
          ? <Empty icon={<Database size={22} />}>No crown-jewel data stores classified in this account.</Empty>
          : <div className="flex flex-col divide-y divide-line/60">{inv.stores.map((s) => <StoreRow key={s.node_id} s={s} />)}</div>}
      </Card>

      {inv.classification_gaps.length > 0 && (
        <Card className="p-4">
          <div className="text-xs font-bold uppercase tracking-wide text-ink3 mb-2 flex items-center gap-1.5"><ShieldAlert size={13} /> Classification gaps — sensitive stores with unknown data type</div>
          <p className="text-xs text-ink3 mb-2">Enable Amazon Macie sensitive-data discovery (or tag the store) so its regulated-data type is known. A byte-level content scan is deferred to the EBS filesystem parse.</p>
          <div className="flex flex-col divide-y divide-line/60">{inv.classification_gaps.map((s) => <StoreRow key={s.node_id} s={s} />)}</div>
        </Card>
      )}
    </div>
  )
}

interface DataViewData { org: OrgDataInventory | null; inv: DataInventory | null }

export function Data() {
  const { scope } = useScope()
  const org = isOrgScope(scope)
  const { data, loading, error } = useFetch<DataViewData>(
    (): Promise<DataViewData> => org
      ? api.orgDataInventory().then((d) => ({ org: d, inv: null }))
      : api.dataInventory(scope).then((d) => ({ org: null, inv: d })),
    [scope])

  if (loading) return <Loader />
  if (error) return <ErrorNote msg={error} />
  if (!data) return null

  return (
    <div className="p-6 md:p-8 max-w-[1440px] mx-auto">
      <div className="mb-5">
        <h1 className="text-2xl font-extrabold tracking-tight text-ink flex items-center gap-2">
          <Database size={22} className="text-accent" /> Data Security
        </h1>
        <p className="text-ink2 text-sm mt-1 max-w-3xl">Your sensitive-data inventory (DSPM) — which stores hold regulated data (PII / PCI / PHI), which are exposed or unencrypted, and who can read them — classified agentlessly from Amazon Macie + data-classification tags. <Link to="/query" className="text-accent font-semibold inline-flex items-center gap-0.5">Query it <ArrowRight size={12} /></Link></p>
      </div>
      {data.org ? <OrgData data={data.org} /> : data.inv && <AccountData inv={data.inv} />}
    </div>
  )
}

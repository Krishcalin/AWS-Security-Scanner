import { useState } from 'react'
import { Plus, Cloud, RefreshCw, Play, Trash2, Building2, TriangleAlert, Loader2 } from 'lucide-react'
import { useFetch } from '../lib/useFetch'
import { api } from '../api/client'
import { Card, Loader, ErrorNote, Empty } from '../components/ui'
import { OnboardWizard } from '../components/OnboardWizard'
import { healthTone, relTime, acctLabel, scoreColor } from '../lib/format'
import type { Account } from '../api/types'

function Stat({ n, label, tone }: { n: number; label: string; tone: string }) {
  return (
    <div className="rounded-xl border border-line bg-panel px-4 py-3 shadow-sm">
      <div className="text-2xl font-extrabold tabular-nums leading-none" style={{ color: tone }}>{n}</div>
      <div className="text-xs text-ink3 mt-1">{label}</div>
    </div>
  )
}

function Row({ a, busy, onRevalidate, onRescan, onOffboard }: {
  a: Account; busy: boolean
  onRevalidate: () => void; onRescan: () => void; onOffboard: () => void
}) {
  const tone = healthTone(a.health)
  const active = a.onboarding_status === 'active'
  return (
    <div className="rounded-xl border border-line bg-panel">
      <div className={`flex items-center gap-3 px-4 py-3 ${active ? '' : 'opacity-70'}`}>
        <span className="h-2.5 w-2.5 rounded-full shrink-0" style={{ background: tone.fg }} />
        <div className="min-w-0 w-52">
          <div className="text-sm font-semibold text-ink truncate flex items-center gap-1.5">
            {acctLabel(a.alias, a.account_id)}
            {a.onboarding_method === 'stackset' && <Building2 size={12} className="text-ink3" aria-label="StackSet" />}
          </div>
          <div className="font-mono text-[11px] text-ink3">{a.account_id}</div>
        </div>
        <span className="text-xs text-ink3 w-24 hidden md:block">{a.enabled_regions.join(', ')}</span>
        <div className="w-20 text-right hidden sm:block">
          {a.posture_score != null
            ? <span className="font-mono text-sm font-bold tabular-nums" style={{ color: scoreColor(a.posture_score) }}>{a.posture_score.toFixed(0)}</span>
            : <span className="text-ink3 text-sm">—</span>}
          <div className="text-[10px] text-ink3">posture</div>
        </div>
        <span className="text-xs text-ink3 w-24 text-right hidden lg:block">{relTime(a.last_scan_at)}</span>
        <span className="ml-auto text-xs font-semibold px-2 py-0.5 rounded-full whitespace-nowrap" style={{ color: tone.fg, background: tone.bg }}>{tone.label}</span>
        <div className="flex items-center gap-0.5 shrink-0">
          <button onClick={onRevalidate} disabled={busy} title="Re-validate" className="h-7 w-7 grid place-items-center rounded-md text-ink3 hover:text-ink hover:bg-panel2 disabled:opacity-50">
            {busy ? <Loader2 size={14} className="animate-spin" /> : <RefreshCw size={14} />}
          </button>
          <button onClick={onRescan} disabled={busy || !active} title="Re-scan" className="h-7 w-7 grid place-items-center rounded-md text-ink3 hover:text-ink hover:bg-panel2 disabled:opacity-40"><Play size={14} /></button>
          <button onClick={onOffboard} disabled={busy} title="Offboard" className="h-7 w-7 grid place-items-center rounded-md text-ink3 hover:text-[var(--crit)] hover:bg-panel2 disabled:opacity-50"><Trash2 size={14} /></button>
        </div>
      </div>
      {a.health_detail && (
        <div className="flex items-start gap-2 px-4 pb-3 text-xs" style={{ color: tone.fg }}>
          <TriangleAlert size={13} className="mt-0.5 shrink-0" /> {a.health_detail}
        </div>
      )}
    </div>
  )
}

export function CloudAccounts() {
  const { data, loading, error } = useFetch<Account[]>(() => api.listAccounts(), [])
  const [added, setAdded] = useState<Account[]>([])
  const [overrides, setOverrides] = useState<Record<string, Partial<Account>>>({})
  const [removed, setRemoved] = useState<Set<string>>(new Set())
  const [busyIds, setBusyIds] = useState<Set<string>>(new Set())
  const [wizard, setWizard] = useState(false)

  if (loading) return <Loader />
  if (error) return <ErrorNote msg={error} />

  const merged: Account[] = [...added, ...(data ?? [])]
    .filter((a) => !removed.has(a.account_id))
    .map((a) => ({ ...a, ...overrides[a.account_id] }))

  const setBusy = (id: string, on: boolean) => setBusyIds((s) => { const n = new Set(s); on ? n.add(id) : n.delete(id); return n })
  const revalidate = async (a: Account) => {
    setBusy(a.account_id, true)
    try {
      const v = await api.validate(a.account_id, a.onboarding_method === 'stackset')
      setOverrides((o) => ({ ...o, [a.account_id]: { health: v.health, onboarding_status: v.health === 'healthy' ? 'active' : v.health === 'unauthorized' ? 'denied' : a.onboarding_status, health_detail: v.health === 'healthy' ? null : a.health_detail } }))
    } catch { /* ignore in demo */ } finally { setBusy(a.account_id, false) }
  }
  const rescan = async (a: Account) => {
    setBusy(a.account_id, true)
    try { await api.triggerScan([a.account_id]); setOverrides((o) => ({ ...o, [a.account_id]: { ...o[a.account_id], last_scan_at: Math.floor(Date.now() / 1000) } })) }
    catch { /* ignore */ } finally { setBusy(a.account_id, false) }
  }
  const offboard = (a: Account) => {
    if (!window.confirm(`Offboard ${acctLabel(a.alias, a.account_id)}? This stops scanning it. Delete the CloudFormation stack in the account to fully revoke access.`)) return
    setRemoved((s) => new Set(s).add(a.account_id))
  }

  const count = (fn: (a: Account) => boolean) => merged.filter(fn).length

  return (
    <div className="p-6 md:p-8 max-w-[1440px] mx-auto">
      <div className="flex items-start justify-between gap-4 mb-5">
        <div>
          <h1 className="text-2xl font-extrabold tracking-tight text-ink flex items-center gap-2"><Cloud size={22} className="text-accent" /> Cloud Accounts</h1>
          <p className="text-ink2 text-sm mt-1">{merged.length} account{merged.length === 1 ? '' : 's'} · keyless, role-based onboarding</p>
        </div>
        <button onClick={() => setWizard(true)} className="inline-flex items-center gap-2 rounded-lg px-4 py-2 text-sm font-semibold text-white ow-grad shadow-sm hover:opacity-90">
          <Plus size={16} /> Add account
        </button>
      </div>

      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-5">
        <Stat n={count((a) => a.onboarding_status === 'active')} label="Active" tone="var(--low)" />
        <Stat n={count((a) => a.health === 'degraded')} label="Degraded" tone="var(--med)" />
        <Stat n={count((a) => a.onboarding_status === 'pending')} label="Pending" tone="var(--info)" />
        <Stat n={count((a) => a.health === 'unauthorized')} label="Unauthorized" tone="var(--crit)" />
      </div>

      {merged.length === 0 ? (
        <Card><Empty icon={<Cloud size={28} />}>No accounts onboarded yet. Click <b>Add account</b> to connect your first AWS account.</Empty></Card>
      ) : (
        <div className="flex flex-col gap-2">
          {merged.map((a) => (
            <Row key={a.account_id} a={a} busy={busyIds.has(a.account_id)}
              onRevalidate={() => revalidate(a)} onRescan={() => rescan(a)} onOffboard={() => offboard(a)} />
          ))}
        </div>
      )}

      {wizard && (
        <OnboardWizard
          onClose={() => setWizard(false)}
          onComplete={(a) => { setAdded((cur) => [a, ...cur.filter((x) => x.account_id !== a.account_id)]); setRemoved((s) => { const n = new Set(s); n.delete(a.account_id); return n }) }}
        />
      )}
    </div>
  )
}

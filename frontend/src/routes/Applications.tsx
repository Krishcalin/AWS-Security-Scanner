/**
 * Applications — the AD-02 registry, editable.
 *
 * WHY THE WARNINGS ARE THE FEATURE
 * --------------------------------
 * A mis-scoped application does not fail. It saves, renders a scorecard, reports
 * zero findings, and is indistinguishable from an application that is genuinely
 * clean — until somebody acts on it. The API returns `warnings` WITH the object
 * for exactly this reason, and this screen shows them next to the row rather than
 * behind a hover, because the author is the only person who can fix them and this
 * is the only moment they are looking.
 *
 * Fatal still rejects: a key-only tag selector or an eleven-digit account id is a
 * 400 with the reason, shown inline. A missing owner saves with a warning, because
 * somebody mid-onboarding may legitimately not know the owner yet and refusing
 * would push the registry into a spreadsheet where nothing validates it at all.
 */
import { useState } from 'react'
import { AlertTriangle, Info, Plus, Trash2, Users } from 'lucide-react'
import { api } from '../api/client'
import type { Application, ApplicationInput } from '../api/types'
import { useFetch } from '../lib/useFetch'
import { Card, Empty, ErrorNote, Loader, SectionLabel } from '../components/ui'

const TIERS = ['crown-jewel', 'high', 'standard', 'unclassified'] as const

const BLANK: ApplicationInput = {
  name: '', owner: '', portfolio: '', criticality: 'unclassified',
  accounts: [], tag_selectors: [], resource_arns: [],
}

function Warnings({ items }: { items: string[] }) {
  if (!items.length) return null
  return (
    <div className="flex flex-col gap-1 mt-2 pt-2 border-t" style={{ borderColor: 'var(--line2)' }}>
      {items.map((w, i) => (
        <div key={i} className="flex items-start gap-1.5 text-[11px] leading-snug"
          style={{ color: 'var(--high)' }}>
          <AlertTriangle size={12} className="mt-px shrink-0" />
          <span>{w}</span>
        </div>
      ))}
    </div>
  )
}

function Row({ a, onDelete }: { a: Application; onDelete: () => void }) {
  return (
    <div className="rounded-xl border border-line bg-panel px-4 py-3">
      <div className="flex items-center gap-3 flex-wrap">
        <span className="font-semibold text-ink">{a.name}</span>
        <span className="text-xs text-ink3 flex items-center gap-1">
          <Users size={11} />{a.owner || <em>no owner</em>}
        </span>
        <span className="text-[10px] rounded px-1.5 py-0.5 text-ink3"
          style={{ background: 'var(--panel2)' }}>{a.criticality}</span>
        {a.portfolio && (
          <span className="text-[10px] rounded px-1.5 py-0.5 text-ink3"
            style={{ background: 'var(--panel2)' }}>{a.portfolio}</span>
        )}
        <span className="text-[11px] text-ink3 ml-auto tabular-nums">
          {a.accounts.length} account(s) · {a.tag_selectors.length} tag ·{' '}
          {a.resource_arns.length} pinned
        </span>
        <button onClick={onDelete} title="Delete application"
          className="text-ink3 hover:text-crit p-1 rounded">
          <Trash2 size={14} />
        </button>
      </div>
      <Warnings items={a.warnings} />
    </div>
  )
}

function NewForm({ onCreated }: { onCreated: () => void }) {
  const [body, setBody] = useState<ApplicationInput>(BLANK)
  const [accounts, setAccounts] = useState('')
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)

  const submit = async () => {
    setBusy(true); setErr('')
    try {
      await api.createApplication({
        ...body,
        accounts: accounts.split(',').map((s) => s.trim()).filter(Boolean),
      })
      setBody(BLANK); setAccounts(''); onCreated()
    } catch (e) {
      // The 400 carries the reason the registry refused; showing anything shorter
      // makes the author guess.
      setErr(e instanceof Error ? e.message : 'could not create application')
    } finally { setBusy(false) }
  }

  return (
    <Card className="p-4 flex flex-col gap-3">
      <SectionLabel>Define an application</SectionLabel>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-2.5">
        <input className="rounded-lg border border-line bg-panel2 px-3 py-2 text-sm"
          placeholder="Name (e.g. Payments)" value={body.name}
          onChange={(e) => setBody({ ...body, name: e.target.value })} />
        <input className="rounded-lg border border-line bg-panel2 px-3 py-2 text-sm"
          placeholder="Owner (team or person)" value={body.owner}
          onChange={(e) => setBody({ ...body, owner: e.target.value })} />
        <input className="rounded-lg border border-line bg-panel2 px-3 py-2 text-sm"
          placeholder="Portfolio (e.g. digital)" value={body.portfolio}
          onChange={(e) => setBody({ ...body, portfolio: e.target.value })} />
        <select className="rounded-lg border border-line bg-panel2 px-3 py-2 text-sm"
          value={body.criticality}
          onChange={(e) => setBody({ ...body, criticality: e.target.value })}>
          {TIERS.map((t) => <option key={t} value={t}>{t}</option>)}
        </select>
        <input className="rounded-lg border border-line bg-panel2 px-3 py-2 text-sm md:col-span-2 font-mono"
          placeholder="Account ids, comma separated (12 digits each)"
          value={accounts} onChange={(e) => setAccounts(e.target.value)} />
      </div>
      {err && <ErrorNote msg={err} />}
      <div className="flex items-center gap-3">
        <button onClick={submit} disabled={busy || !body.name.trim()}
          className="rounded-lg px-3 py-1.5 text-sm font-semibold text-white disabled:opacity-40 flex items-center gap-1.5"
          style={{ background: 'var(--accent)' }}>
          <Plus size={14} />{busy ? 'Saving…' : 'Create'}
        </button>
        <span className="text-[11px] text-ink3">
          An application with no owner or no selectors will save, and say why it
          cannot work.
        </span>
      </div>
    </Card>
  )
}

export function Applications() {
  const [nonce, setNonce] = useState(0)
  const { data, loading, error } = useFetch<Application[]>(
    () => api.listApplications(), [nonce])
  const note = api.sampleFr2Note()

  if (loading) return <Loader />
  if (error) return <ErrorNote msg={error} />

  const rows = data ?? []
  const remove = async (id: string) => {
    await api.deleteApplication(id)
    setNonce((n) => n + 1)
  }

  return (
    <div className="flex flex-col gap-4">
      <div>
        <h1 className="text-xl font-bold text-ink">Applications</h1>
        <p className="text-sm text-ink3 mt-0.5">
          Who owns what. Findings are attributed to these, and scorecards are
          issued per application — so an estate with an empty registry has no
          owner to send anything to.
        </p>
      </div>

      {note ? (
        <Card className="p-4 text-sm text-ink2 flex items-start gap-3">
          <Info size={16} className="mt-0.5 shrink-0 text-ink3" />
          <span>{note}</span>
        </Card>
      ) : (
        <>
          <NewForm onCreated={() => setNonce((n) => n + 1)} />
          {rows.length === 0 ? (
            <Card className="p-5">
              <Empty icon={<Users size={22} />}>
                No applications yet. Until one exists every finding is unowned, and
                the scorecard pack is a single unowned row.
              </Empty>
            </Card>
          ) : (
            <div className="flex flex-col gap-2.5">
              <SectionLabel>{rows.length} application(s)</SectionLabel>
              {rows.map((a) => <Row key={a.id} a={a} onDelete={() => remove(a.id)} />)}
            </div>
          )}
        </>
      )}
    </div>
  )
}

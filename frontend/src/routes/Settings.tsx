import { useState, useCallback, type ReactNode } from 'react'
import {
  Settings2, Plus, X, Send, Trash2, Pencil, KeyRound, Power, ShieldCheck,
  ShieldAlert, Radio, Bell, FlaskConical, ChevronRight, ChevronDown, Check, Inbox,
} from 'lucide-react'
import { useScope, isOrgScope } from '../state/scope'
import { useFetch } from '../lib/useFetch'
import { api } from '../api/client'
import { Card, Loader, ErrorNote, Empty, SevDot } from '../components/ui'
import type { Connector, ConnectorRule, ConnectorType, Delivery, TestResult, PreviewHit } from '../api/types'

// ── per-type metadata: label, accent, config fields, and the secret's name ──────
type FieldSpec = { key: string; label: string; placeholder?: string; kind?: 'select'; opts?: string[]; hint?: string }
interface TypeMeta { label: string; color: string; secretLabel: string; secretOptional?: boolean; fields: FieldSpec[]; blurb: string }

const TYPES: Record<ConnectorType, TypeMeta> = {
  jira: {
    label: 'Jira', color: '#2b6cb0', secretLabel: 'API token',
    blurb: 'File a Jira Cloud issue per finding. The description is rendered as ADF; priority is mapped from severity (best-effort).',
    fields: [
      { key: 'site', label: 'Site URL', placeholder: 'https://acme.atlassian.net' },
      { key: 'email', label: 'Account email', placeholder: 'bot@acme.com' },
      { key: 'project_key', label: 'Project key', placeholder: 'SEC' },
      { key: 'issue_type', label: 'Issue type', placeholder: 'Task' },
    ],
  },
  slack: {
    label: 'Slack', color: '#7c3aed', secretLabel: 'Webhook URL / bot token',
    blurb: 'Post a Block Kit alert to a channel. Webhook mode posts to one fixed channel; chat mode uses a bot token and returns a message link.',
    fields: [
      { key: 'mode', label: 'Mode', kind: 'select', opts: ['webhook', 'chat'] },
      { key: 'channel', label: 'Channel ID (chat mode)', placeholder: 'C0123456789', hint: 'Use the channel ID, not #name' },
    ],
  },
  pagerduty: {
    label: 'PagerDuty', color: '#0e9d58', secretLabel: 'Events API v2 routing key',
    blurb: 'Trigger a PagerDuty alert with a stable dedup key so re-scans update one incident. CRITICAL + on-attack-path pages on-call.',
    fields: [{ key: 'region', label: 'Region', kind: 'select', opts: ['us', 'eu'] }],
  },
  splunk: {
    label: 'Splunk HEC', color: '#c47d04', secretLabel: 'HEC token',
    blurb: 'Ship each finding as one HEC event to /services/collector/event with indexed fields for dashboards + alerts.',
    fields: [
      { key: 'host', label: 'HEC host', placeholder: 'http-inputs-acme.splunkcloud.com' },
      { key: 'port', label: 'Port', placeholder: '8088' },
      { key: 'index', label: 'Index (optional)', placeholder: 'cloudsec' },
      { key: 'sourcetype', label: 'Sourcetype', placeholder: 'overwatch:finding' },
    ],
  },
  webhook: {
    label: 'Webhook', color: '#0f766e', secretLabel: 'Signing secret', secretOptional: true,
    blurb: 'POST a signed OverWatch event envelope to an HTTPS URL. Standard-Webhooks + X-Hub-Signature-256 headers. https-only; the IMDS address is always blocked.',
    fields: [{ key: 'url', label: 'Endpoint URL', placeholder: 'https://hooks.example.com/overwatch', hint: 'https only · no link-local hosts' }],
  },
}

const TYPE_ORDER: ConnectorType[] = ['jira', 'slack', 'pagerduty', 'splunk', 'webhook']

function TypeBadge({ t }: { t: ConnectorType }) {
  const m = TYPES[t]
  return (
    <span className="inline-flex items-center rounded-md px-2 py-0.5 text-[11px] font-bold"
      style={{ color: m.color, background: `color-mix(in srgb, ${m.color} 13%, transparent)` }}>
      {m.label}
    </span>
  )
}

function Field({ label, hint, children }: { label: string; hint?: string; children: ReactNode }) {
  return (
    <label className="flex flex-col gap-1">
      <span className="text-xs font-semibold text-ink2">{label}</span>
      {children}
      {hint && <span className="text-[11px] text-ink3">{hint}</span>}
    </label>
  )
}

const inputCls = 'rounded-lg border border-line bg-panel px-3 py-1.5 text-sm text-ink placeholder:text-ink3 outline-none focus:border-accent/50'

// ── add / edit connector modal ─────────────────────────────────────────────────
function ConnectorModal({ existing, onClose, onSaved }:
  { existing: Connector | null; onClose: () => void; onSaved: () => void }) {
  const editing = !!existing
  const [type, setType] = useState<ConnectorType>(existing?.type ?? 'slack')
  const [name, setName] = useState(existing?.name ?? '')
  const [config, setConfig] = useState<Record<string, string>>(
    () => Object.fromEntries(Object.entries(existing?.config ?? {}).map(([k, v]) => [k, String(v ?? '')])))
  const [secret, setSecret] = useState('')
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState<string | null>(null)
  const meta = TYPES[type]

  const setCfg = (k: string, v: string) => setConfig((c) => ({ ...c, [k]: v }))
  const save = async () => {
    setBusy(true); setErr(null)
    try {
      const cfg: Record<string, unknown> = { ...config }
      if (cfg.port) cfg.port = Number(cfg.port)
      if (editing) {
        await api.updateConnector(existing!.connector_id, { name, config: cfg })
        if (secret) await api.rotateSecret(existing!.connector_id, secret)
      } else {
        await api.createConnector({ type, name, config: cfg, secret: secret || undefined })
      }
      onSaved()
    } catch (e) { setErr(String((e as Error)?.message ?? e)) } finally { setBusy(false) }
  }

  return (
    <div className="fixed inset-0 z-40">
      <div className="absolute inset-0 bg-black/30 backdrop-blur-sm" onClick={onClose} />
      <aside className="absolute right-0 top-0 bottom-0 w-full max-w-[520px] bg-canvas border-l border-line shadow-2xl overflow-y-auto">
        <div className="sticky top-0 z-10 bg-canvas/90 backdrop-blur border-b border-line px-6 py-4 flex items-center gap-3">
          <span className="font-bold text-ink text-lg">{editing ? 'Edit connector' : 'Add connector'}</span>
          <button onClick={onClose} className="ml-auto h-8 w-8 grid place-items-center rounded-lg border border-line text-ink3 hover:text-ink"><X size={16} /></button>
        </div>
        <div className="p-6 flex flex-col gap-4">
          {!editing && (
            <div className="grid grid-cols-5 gap-1.5">
              {TYPE_ORDER.map((t) => (
                <button key={t} onClick={() => setType(t)}
                  className="rounded-lg border px-1 py-2 text-[11px] font-bold transition-colors"
                  style={{ borderColor: type === t ? TYPES[t].color : 'var(--line)',
                    color: type === t ? TYPES[t].color : 'var(--ink3)',
                    background: type === t ? `color-mix(in srgb, ${TYPES[t].color} 10%, transparent)` : 'var(--panel)' }}>
                  {TYPES[t].label}
                </button>
              ))}
            </div>
          )}
          <p className="text-xs text-ink3 leading-relaxed">{meta.blurb}</p>

          <Field label="Name"><input className={inputCls} value={name} onChange={(e) => setName(e.target.value)} placeholder={`${meta.label} — SecOps`} /></Field>

          {meta.fields.map((f) => (
            <Field key={f.key} label={f.label} hint={f.hint}>
              {f.kind === 'select'
                ? <select className={inputCls} value={config[f.key] ?? f.opts![0]} onChange={(e) => setCfg(f.key, e.target.value)}>
                    {f.opts!.map((o) => <option key={o} value={o}>{o}</option>)}
                  </select>
                : <input className={inputCls} value={config[f.key] ?? ''} onChange={(e) => setCfg(f.key, e.target.value)} placeholder={f.placeholder} />}
            </Field>
          ))}

          <Field label={`${meta.secretLabel}${meta.secretOptional ? ' (optional)' : ''}`}
            hint={editing ? (existing!.secret_configured ? '•••••••• set — enter a new value to rotate, or leave blank to keep' : 'no secret set') : 'stored as a secret reference only — never shown again'}>
            <input className={inputCls} type="password" autoComplete="new-password" value={secret}
              onChange={(e) => setSecret(e.target.value)} placeholder={editing ? '•••••••• (unchanged)' : '••••••••'} />
          </Field>

          {err && <ErrorNote msg={err} />}
          <div className="flex gap-2 pt-1">
            <button disabled={busy || !name.trim()} onClick={save}
              className="rounded-lg px-4 py-2 text-sm font-semibold text-white ow-grad disabled:opacity-50">
              {busy ? 'Saving…' : editing ? 'Save changes' : 'Add connector'}
            </button>
            <button onClick={onClose} className="rounded-lg border border-line px-4 py-2 text-sm font-semibold text-ink2">Cancel</button>
          </div>
          <p className="text-[11px] text-ink3">New connectors start <b>disabled</b> and send nothing until you enable them.</p>
        </div>
      </aside>
    </div>
  )
}

// ── rules sub-panel ─────────────────────────────────────────────────────────────
const SEVS = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']

function RuleEditor({ connectorId, onDone }: { connectorId: string; onDone: () => void }) {
  const [name, setName] = useState('')
  const [minSev, setMinSev] = useState('HIGH')
  const [checkGlob, setCheckGlob] = useState('')
  const [onPath, setOnPath] = useState<'any' | 'yes' | 'no'>('any')
  const [busy, setBusy] = useState(false)
  const create = async () => {
    setBusy(true)
    try {
      await api.createRule(connectorId, {
        name: name || 'rule', min_severity: minSev,
        check_globs: checkGlob.trim() ? [checkGlob.trim()] : [],
        on_attack_path: onPath === 'any' ? null : onPath === 'yes',
      })
      onDone()
    } finally { setBusy(false) }
  }
  return (
    <div className="rounded-xl border border-line2 p-3 flex flex-col gap-2.5" style={{ background: 'var(--panel2)' }}>
      <div className="grid grid-cols-2 gap-2">
        <input className={inputCls} value={name} onChange={(e) => setName(e.target.value)} placeholder="Rule name" />
        <select className={inputCls} value={minSev} onChange={(e) => setMinSev(e.target.value)}>
          {SEVS.map((s) => <option key={s} value={s}>≥ {s}</option>)}
        </select>
        <input className={inputCls} value={checkGlob} onChange={(e) => setCheckGlob(e.target.value)} placeholder="Check glob e.g. S3-* (blank = any)" />
        <select className={inputCls} value={onPath} onChange={(e) => setOnPath(e.target.value as 'any' | 'yes' | 'no')}>
          <option value="any">Attack path: any</option>
          <option value="yes">On attack path only</option>
          <option value="no">Off attack path only</option>
        </select>
      </div>
      <div className="flex gap-2">
        <button disabled={busy} onClick={create} className="rounded-lg px-3 py-1.5 text-xs font-semibold text-white ow-grad disabled:opacity-50">Add rule</button>
        <button onClick={onDone} className="rounded-lg border border-line px-3 py-1.5 text-xs font-semibold text-ink2">Cancel</button>
      </div>
    </div>
  )
}

function RulesPanel({ connector, previewAccount, accountScoped }:
  { connector: Connector; previewAccount: string; accountScoped: boolean }) {
  const [nonce, setNonce] = useState(0)
  const bump = useCallback(() => setNonce((n) => n + 1), [])
  const { data: rules, loading } = useFetch<ConnectorRule[]>(() => api.listRules(connector.connector_id), [connector.connector_id, nonce])
  const [adding, setAdding] = useState(false)
  const [preview, setPreview] = useState<PreviewHit[] | null>(null)
  const [previewing, setPreviewing] = useState(false)

  const runPreview = async () => {
    setPreviewing(true)
    try { setPreview(await api.previewRules(previewAccount)) } finally { setPreviewing(false) }
  }
  const del = async (id: number) => { await api.deleteRule(connector.connector_id, id); bump() }

  return (
    <div className="px-4 pb-4 pt-1 flex flex-col gap-2 border-t border-line2">
      <div className="flex items-center gap-2 pt-2">
        <span className="text-xs font-bold text-ink2 flex items-center gap-1.5"><Radio size={13} /> Routing rules</span>
        <span className="text-xs text-ink3">— a finding fires when it matches any enabled rule</span>
        <button onClick={() => setAdding((v) => !v)} className="ml-auto text-xs font-semibold text-accent flex items-center gap-1"><Plus size={13} /> Rule</button>
        <button onClick={runPreview} disabled={previewing || !accountScoped}
          title={accountScoped ? 'Dry-run against the selected account' : 'Select a specific account to preview'}
          className="text-xs font-semibold text-ink2 flex items-center gap-1 disabled:opacity-40"><FlaskConical size={13} /> {previewing ? 'Previewing…' : 'Preview'}</button>
      </div>
      {adding && <RuleEditor connectorId={connector.connector_id} onDone={() => { setAdding(false); bump() }} />}
      {loading ? <div className="text-xs text-ink3 py-2">Loading rules…</div>
        : !rules || rules.length === 0 ? <div className="text-xs text-ink3 py-2">No rules — this connector won’t fire until you add one.</div>
        : (
          <div className="flex flex-col gap-1.5">
            {rules.map((r) => (
              <div key={r.id} className="flex items-center gap-2 rounded-lg border border-line px-3 py-2 bg-panel text-xs">
                <SevDot sev={r.min_severity} />
                <span className="font-semibold text-ink">{r.name || `rule ${r.id}`}</span>
                <span className="text-ink3">≥ {r.min_severity}</span>
                {r.check_globs.length > 0 && <span className="font-mono text-ink3">{r.check_globs.join(',')}</span>}
                {r.on_attack_path === true && <span className="text-[10px] font-bold px-1.5 py-0.5 rounded" style={{ background: 'var(--critbg)', color: 'var(--crit)' }}>on-path</span>}
                <span className="ml-auto text-ink3">{r.dedup_mode === 'renotify' ? 'renotify' : 'notify once'}</span>
                <button onClick={() => del(r.id)} className="h-6 w-6 grid place-items-center text-ink3 hover:text-crit"><Trash2 size={13} /></button>
              </div>
            ))}
          </div>
        )}
      {preview && (
        <div className="rounded-lg border border-line2 px-3 py-2 text-xs" style={{ background: 'var(--panel2)' }}>
          <div className="font-semibold text-ink2 mb-1">Dry-run vs account {previewAccount} — would fire {preview.filter((p) => p.connector_id === connector.connector_id).length} time(s), nothing sent.</div>
          <div className="flex gap-1.5 flex-wrap">
            {preview.filter((p) => p.connector_id === connector.connector_id).slice(0, 12).map((p, i) => (
              <span key={i} className="font-mono rounded px-1.5 py-0.5" style={{ background: 'var(--panel)', color: 'var(--ink2)' }}>{p.check_id}</span>
            ))}
            {preview.filter((p) => p.connector_id === connector.connector_id).length === 0 && <span className="text-ink3">no current findings match</span>}
          </div>
        </div>
      )}
    </div>
  )
}

// ── connector row ───────────────────────────────────────────────────────────────
function ConnectorRow({ c, previewAccount, accountScoped, onChanged, onEdit }:
  { c: Connector; previewAccount: string; accountScoped: boolean; onChanged: () => void; onEdit: () => void }) {
  const [open, setOpen] = useState(false)
  const [test, setTest] = useState<TestResult | null>(null)
  const [testing, setTesting] = useState(false)
  const toggle = async () => { await api.enableConnector(c.connector_id, !c.enabled); onChanged() }
  const runTest = async () => { setTesting(true); try { setTest(await api.testConnector(c.connector_id)) } finally { setTesting(false) } }
  const remove = async () => { if (confirm(`Delete connector “${c.name}” and its rules?`)) { await api.deleteConnector(c.connector_id); onChanged() } }

  return (
    <div className="rounded-xl border border-line bg-panel">
      <div className="flex items-center gap-3 px-4 py-3">
        <button onClick={() => setOpen((v) => !v)} className="h-6 w-6 grid place-items-center text-ink3 hover:text-ink">
          {open ? <ChevronDown size={16} /> : <ChevronRight size={16} />}
        </button>
        <TypeBadge t={c.type} />
        <span className="font-semibold text-ink">{c.name}</span>
        {c.secret_configured
          ? <span className="inline-flex items-center gap-1 text-[11px] font-semibold" style={{ color: 'var(--low)' }}><KeyRound size={12} /> secret set</span>
          : <span className="inline-flex items-center gap-1 text-[11px] font-semibold text-ink3"><KeyRound size={12} /> unauthenticated</span>}
        {c.last_test_status && (
          <span className="inline-flex items-center gap-1 text-[11px]" style={{ color: c.last_test_status === 'ok' ? 'var(--low)' : 'var(--crit)' }}>
            {c.last_test_status === 'ok' ? <ShieldCheck size={12} /> : <ShieldAlert size={12} />}{c.last_test_status === 'ok' ? 'test ok' : 'test failed'}
          </span>
        )}
        <div className="ml-auto flex items-center gap-1">
          <button onClick={runTest} disabled={testing} title="Send a harmless test"
            className="h-8 px-2.5 grid place-items-center rounded-lg border border-line text-ink3 hover:text-ink text-xs font-semibold gap-1 flex disabled:opacity-50">
            <Send size={13} /> {testing ? 'Testing…' : 'Test'}
          </button>
          <button onClick={onEdit} title="Edit" className="h-8 w-8 grid place-items-center rounded-lg border border-line text-ink3 hover:text-ink"><Pencil size={13} /></button>
          <button onClick={remove} title="Delete" className="h-8 w-8 grid place-items-center rounded-lg border border-line text-ink3 hover:text-crit"><Trash2 size={13} /></button>
          <button onClick={toggle} title={c.enabled ? 'Disable' : 'Enable'}
            className="h-8 px-2.5 grid place-items-center rounded-lg text-xs font-bold gap-1 flex border transition-colors"
            style={{ borderColor: c.enabled ? 'var(--low)' : 'var(--line)',
              color: c.enabled ? 'var(--low)' : 'var(--ink3)',
              background: c.enabled ? 'color-mix(in srgb, var(--low) 12%, transparent)' : 'var(--panel)' }}>
            <Power size={13} /> {c.enabled ? 'Enabled' : 'Disabled'}
          </button>
        </div>
      </div>
      {test && (
        <div className="mx-4 mb-2 rounded-lg px-3 py-2 text-xs flex items-center gap-2"
          style={{ background: test.ok ? 'color-mix(in srgb, var(--low) 10%, transparent)' : 'var(--critbg)', color: test.ok ? 'var(--low)' : 'var(--crit)' }}>
          {test.ok ? <Check size={14} /> : <ShieldAlert size={14} />}
          {test.ok ? `Delivered — ${test.detail || 'reachable'}` : `Failed — ${test.error || test.detail || 'HTTP ' + test.http_status}`}
        </div>
      )}
      {open && <RulesPanel connector={c} previewAccount={previewAccount} accountScoped={accountScoped} />}
    </div>
  )
}

// ── deliveries tab ──────────────────────────────────────────────────────────────
function statusColor(s: string): string {
  return s === 'sent' ? 'var(--low)' : s === 'failed' ? 'var(--crit)' : 'var(--ink3)'
}
function DeliveriesTab() {
  const { data, loading, error } = useFetch<Delivery[]>(() => api.listDeliveries(), [])
  if (loading) return <Loader />
  if (error) return <ErrorNote msg={error} />
  if (!data || data.length === 0) return <Card className="p-2"><Empty icon={<Bell size={26} />}>No deliveries yet. Enable a connector, add a rule, then run a scan.</Empty></Card>
  return (
    <Card className="overflow-hidden">
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="text-left text-xs text-ink3 border-b border-line">
              <th className="px-4 py-2.5 font-semibold">Status</th>
              <th className="px-4 py-2.5 font-semibold">Account</th>
              <th className="px-4 py-2.5 font-semibold">Check</th>
              <th className="px-4 py-2.5 font-semibold">Kind</th>
              <th className="px-4 py-2.5 font-semibold">HTTP</th>
              <th className="px-4 py-2.5 font-semibold">Reference / error</th>
            </tr>
          </thead>
          <tbody>
            {data.map((d) => (
              <tr key={d.id} className="border-b border-line2 last:border-0">
                <td className="px-4 py-2.5"><span className="inline-flex items-center gap-1.5 font-semibold text-xs" style={{ color: statusColor(d.status) }}><span className="h-2 w-2 rounded-full" style={{ background: statusColor(d.status) }} />{d.status}</span></td>
                <td className="px-4 py-2.5 font-mono text-xs text-ink2">{d.account}</td>
                <td className="px-4 py-2.5 font-mono text-xs text-ink">{d.check_id ?? '—'}</td>
                <td className="px-4 py-2.5 text-xs text-ink3">{d.kind ?? '—'}</td>
                <td className="px-4 py-2.5 font-mono text-xs text-ink3 tabular-nums">{d.http_status ?? '—'}</td>
                <td className="px-4 py-2.5 text-xs">{d.error
                  ? <span style={{ color: 'var(--crit)' }}>{d.error}</span>
                  : <span className="font-mono text-ink2">{d.external_ref ?? '—'}</span>}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Card>
  )
}

// ── screen ───────────────────────────────────────────────────────────────────────
type Tab = 'integrations' | 'deliveries'

export function Settings() {
  const { scope } = useScope()
  // Preview + Send-now are per-account; in org scope there is no single target, so
  // they are disabled with a hint (rather than silently acting on a hardcoded id).
  const accountScoped = !isOrgScope(scope)
  const previewAccount = scope
  const [tab, setTab] = useState<Tab>('integrations')
  const [nonce, setNonce] = useState(0)
  const bump = useCallback(() => setNonce((n) => n + 1), [])
  const { data, loading, error } = useFetch<Connector[]>(() => api.listConnectors(), [nonce])
  const [modal, setModal] = useState<{ open: boolean; edit: Connector | null }>({ open: false, edit: null })
  const [notifying, setNotifying] = useState(false)
  const [notifyMsg, setNotifyMsg] = useState<string | null>(null)

  const runNotify = async () => {
    setNotifying(true); setNotifyMsg(null)
    try {
      const r = await api.notifyAccount(previewAccount)
      setNotifyMsg(`Sent ${r.sent} · suppressed ${r.suppressed}${r.failed ? ` · failed ${r.failed}` : ''} for account ${previewAccount}.`)
      bump()
    } catch (e) { setNotifyMsg(`Failed: ${String((e as Error)?.message ?? e)}`) } finally { setNotifying(false) }
  }

  return (
    <div className="p-6 md:p-8 max-w-[1440px] mx-auto">
      <div className="mb-5 flex items-start gap-3">
        <div>
          <h1 className="text-2xl font-extrabold tracking-tight text-ink flex items-center gap-2"><Settings2 size={22} className="text-accent" /> Settings — Integrations</h1>
          <p className="text-ink2 text-sm mt-1">Route findings to your own tools. Connectors are outbound-only; OverWatch never writes to a scanned AWS account. Secrets are stored as references and never shown again.</p>
        </div>
        {tab === 'integrations' && (
          <button onClick={() => setModal({ open: true, edit: null })}
            className="ml-auto shrink-0 rounded-lg px-3.5 py-2 text-sm font-semibold text-white ow-grad flex items-center gap-1.5"><Plus size={15} /> Add connector</button>
        )}
      </div>

      <div className="flex items-center gap-1 border-b border-line mb-4">
        {(['integrations', 'deliveries'] as Tab[]).map((t) => (
          <button key={t} onClick={() => setTab(t)} className="relative px-3.5 py-2 text-sm font-semibold capitalize transition-colors"
            style={{ color: tab === t ? 'var(--accent)' : 'var(--ink2)' }}>
            {t === 'integrations' ? 'Connectors' : 'Deliveries'}
            {tab === t && <span className="absolute left-2 right-2 -bottom-px h-[2px] rounded ow-grad" />}
          </button>
        ))}
      </div>

      {tab === 'deliveries' ? <DeliveriesTab /> : (
        <>
          {loading ? <Loader /> : error ? <ErrorNote msg={error} />
            : !data || data.length === 0 ? (
              <Card className="p-2"><Empty icon={<Inbox size={26} />}>
                No connectors yet. Add Jira, Slack, PagerDuty, Splunk, or a webhook to start routing findings.
              </Empty></Card>
            ) : (
              <div className="flex flex-col gap-2.5">
                {data.map((c) => (
                  <ConnectorRow key={c.connector_id} c={c} previewAccount={previewAccount}
                    accountScoped={accountScoped}
                    onChanged={bump} onEdit={() => setModal({ open: true, edit: c })} />
                ))}
              </div>
            )}

          <div className="mt-5 flex items-center gap-3 rounded-xl border border-line px-4 py-3" style={{ background: 'var(--panel2)' }}>
            <Bell size={16} className="text-accent shrink-0" />
            <div className="text-sm text-ink2">
              {accountScoped
                ? <>Fire enabled connectors over the latest scan for <b className="text-ink font-mono">{previewAccount}</b>. Idempotent — a finding already delivered won’t re-send.</>
                : <>Select a specific account in the scope switcher to preview or send. Connectors fire automatically after each scan.</>}
            </div>
            <button onClick={runNotify} disabled={notifying || !accountScoped}
              title={accountScoped ? '' : 'Select a specific account first'}
              className="ml-auto shrink-0 rounded-lg border border-line px-3 py-1.5 text-xs font-semibold text-ink hover:border-accent/40 disabled:opacity-40">
              {notifying ? 'Sending…' : 'Send now'}
            </button>
          </div>
          {notifyMsg && <div className="mt-2 text-xs text-ink2">{notifyMsg}</div>}
        </>
      )}

      {modal.open && <ConnectorModal existing={modal.edit} onClose={() => setModal({ open: false, edit: null })}
        onSaved={() => { setModal({ open: false, edit: null }); bump() }} />}
    </div>
  )
}

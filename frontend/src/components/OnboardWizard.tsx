import { useState, type ReactNode } from 'react'
import {
  X, Check, Copy, ExternalLink, Building2, Cloud, Loader2, ShieldCheck,
  TriangleAlert, Rocket, ArrowRight, ArrowLeft, KeyRound,
} from 'lucide-react'
import { api } from '../api/client'
import { healthTone } from '../lib/format'
import type { OnboardResult, ValidationResult, Account } from '../api/types'

const STEPS = ['Scope', 'Identify', 'Deploy role', 'Validate', 'First scan']

function CopyBtn({ text }: { text: string }) {
  const [ok, setOk] = useState(false)
  return (
    <button
      onClick={() => navigator.clipboard?.writeText(text).then(() => { setOk(true); setTimeout(() => setOk(false), 1200) })}
      className="shrink-0 h-7 w-7 grid place-items-center rounded-md hover:bg-panel2 text-ink3 hover:text-ink"
    >
      {ok ? <Check size={14} style={{ color: 'var(--low)' }} /> : <Copy size={14} />}
    </button>
  )
}

function CodeBox({ text, mono = true }: { text: string; mono?: boolean }) {
  return (
    <div className="flex items-center gap-2 rounded-lg border border-line px-3 py-2" style={{ background: 'var(--panel2)' }}>
      <code className={`${mono ? 'font-mono' : ''} text-xs text-ink2 flex-1 overflow-x-auto whitespace-nowrap`}>{text}</code>
      <CopyBtn text={text} />
    </div>
  )
}

function Field({ label, children, hint }: { label: string; children: ReactNode; hint?: string }) {
  return (
    <label className="block">
      <div className="text-xs font-semibold text-ink mb-1.5">{label}</div>
      {children}
      {hint && <div className="text-[11px] text-ink3 mt-1">{hint}</div>}
    </label>
  )
}
const inputCls = 'w-full rounded-lg border border-line bg-panel px-3 py-2 text-sm text-ink placeholder:text-ink3 outline-none focus:border-accent/50'

export function OnboardWizard({ onClose, onComplete }: { onClose: () => void; onComplete: (a: Account) => void }) {
  const [step, setStep] = useState(0)
  const [scope, setScope] = useState<'single' | 'org'>('single')
  const [accountId, setAccountId] = useState('')
  const [alias, setAlias] = useState('')
  const [env, setEnv] = useState('production')
  const [autoConnect, setAutoConnect] = useState(true)
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState<string | null>(null)
  const [onboarding, setOnboarding] = useState<OnboardResult | null>(null)
  const [validation, setValidation] = useState<ValidationResult | null>(null)
  const [scanJob, setScanJob] = useState<string | null>(null)
  const [revealEid, setRevealEid] = useState(false)

  const idValid = /^[0-9]{12}$/.test(accountId)
  const orgMode = scope === 'org'
  const externalId = onboarding?.external_id
    ?? onboarding?.cfn_launch_url.match(/param_ExternalId=([^&]+)/)?.[1] ?? ''

  const doOnboard = async () => {
    setBusy(true); setErr(null)
    try {
      const r = await api.onboard({ account_id: accountId, alias, method: orgMode ? 'stackset' : 'single' })
      setOnboarding(r); setStep(2)
    } catch (e) { setErr(String((e as Error)?.message ?? e)) } finally { setBusy(false) }
  }
  const doValidate = async () => {
    setBusy(true); setErr(null); setValidation(null)
    try { setValidation(await api.validate(accountId, orgMode)) }
    catch (e) { setErr(String((e as Error)?.message ?? e)) } finally { setBusy(false) }
  }
  const doScan = async () => {
    setBusy(true); setErr(null)
    try {
      const r = await api.triggerScan([accountId])
      setScanJob(r.job_ids[0] ?? 'job-queued')
    } catch (e) { setErr(String((e as Error)?.message ?? e)) } finally { setBusy(false) }
  }
  const finish = () => {
    const now = Math.floor(Date.now() / 1000)
    onComplete({
      account_id: accountId, alias, org_id: orgMode ? 'o-kizen00demo' : null,
      onboarding_method: orgMode ? 'stackset' : 'single', onboarding_status: 'active',
      health: validation?.health ?? 'healthy', health_detail: null,
      last_scan_at: scanJob ? now : null, first_seen_at: now, updated_at: now,
      role_arn: `arn:aws:iam::${accountId}:role/CnappScannerRole`, enabled_regions: ['us-east-1'],
      external_id_configured: true, posture_score: null, posture_grade: null,
    })
    onClose()
  }

  const canNext = step === 0 ? true : step === 1 ? idValid : step === 3 ? validation?.health === 'healthy' : true

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      <div className="absolute inset-0 bg-black/40 backdrop-blur-sm" onClick={onClose} />
      <div className="relative bg-canvas border border-line rounded-2xl shadow-2xl w-full max-w-[920px] max-h-[88vh] overflow-hidden flex">
        {/* step rail */}
        <div className="w-52 shrink-0 border-r border-line p-5 hidden sm:flex flex-col gap-1" style={{ background: 'var(--panel)' }}>
          <div className="flex items-center gap-2 mb-4">
            <div className="h-7 w-7 rounded-lg ow-grad grid place-items-center text-white text-sm">🛡️</div>
            <span className="font-bold text-ink text-sm">Onboard account</span>
          </div>
          {STEPS.map((s, i) => (
            <div key={s} className="flex items-center gap-2.5 py-1.5">
              <span className="h-6 w-6 rounded-full grid place-items-center text-[11px] font-mono font-bold shrink-0"
                style={{
                  background: i < step ? 'var(--low)' : i === step ? 'var(--accent)' : 'var(--panel2)',
                  color: i <= step ? '#fff' : 'var(--ink3)',
                }}>
                {i < step ? <Check size={13} /> : i + 1}
              </span>
              <span className="text-sm font-medium" style={{ color: i === step ? 'var(--ink)' : 'var(--ink3)' }}>{s}</span>
            </div>
          ))}
        </div>

        {/* content */}
        <div className="flex-1 flex flex-col min-w-0">
          <div className="flex items-center justify-between px-6 py-4 border-b border-line">
            <h2 className="text-base font-bold text-ink">{STEPS[step]}</h2>
            <button onClick={onClose} className="h-8 w-8 grid place-items-center rounded-lg border border-line text-ink3 hover:text-ink"><X size={16} /></button>
          </div>

          <div className="flex-1 overflow-y-auto p-6">
            {err && (
              <div className="flex items-start gap-2 rounded-lg px-3 py-2 mb-4 text-sm" style={{ background: 'var(--critbg)', color: 'var(--crit)' }}>
                <TriangleAlert size={15} className="mt-0.5" /> {err}
              </div>
            )}

            {/* STEP 0 — scope */}
            {step === 0 && (
              <div className="flex flex-col gap-3">
                <p className="text-sm text-ink2">How do you want to connect? OverWatch never uses access keys — it assumes a read-only role you deploy.</p>
                {([
                  { k: 'single', icon: <Cloud size={18} />, t: 'Single AWS account', d: 'Deploy one CloudFormation stack that creates the read-only role.' },
                  { k: 'org', icon: <Building2 size={18} />, t: 'AWS Organization', d: 'A service-managed StackSet auto-enrolls every member account (and future ones).' },
                ] as const).map((o) => (
                  <button key={o.k} onClick={() => setScope(o.k)}
                    className="flex items-start gap-3 rounded-xl border-2 p-4 text-left transition-colors"
                    style={{ borderColor: scope === o.k ? 'var(--accent)' : 'var(--line)', background: scope === o.k ? 'var(--accentdim)' : 'var(--panel)' }}>
                    <span className="h-9 w-9 rounded-lg grid place-items-center shrink-0" style={{ background: 'var(--panel2)', color: 'var(--accent)' }}>{o.icon}</span>
                    <span>
                      <span className="block font-semibold text-ink">{o.t}</span>
                      <span className="block text-xs text-ink2 mt-0.5">{o.d}</span>
                    </span>
                    {scope === o.k && <Check size={18} className="ml-auto text-accent shrink-0" />}
                  </button>
                ))}
              </div>
            )}

            {/* STEP 1 — identify */}
            {step === 1 && (
              <div className="flex flex-col gap-4 max-w-md">
                <Field label={orgMode ? 'Management account ID' : 'AWS account ID'} hint="12 digits — validated client- and server-side.">
                  <input value={accountId} onChange={(e) => setAccountId(e.target.value.replace(/\D/g, '').slice(0, 12))}
                    placeholder="123456789012" className={`${inputCls} font-mono`} inputMode="numeric" />
                  {accountId && !idValid && <div className="text-[11px] mt-1" style={{ color: 'var(--crit)' }}>Must be exactly 12 digits.</div>}
                </Field>
                <Field label="Label / alias" hint="A friendly name shown across the console."><input value={alias} onChange={(e) => setAlias(e.target.value)} placeholder="prod-payments" className={inputCls} /></Field>
                <Field label="Environment tag">
                  <select value={env} onChange={(e) => setEnv(e.target.value)} className={inputCls}>
                    <option>production</option><option>staging</option><option>development</option><option>sandbox</option>
                  </select>
                </Field>
                {orgMode && (
                  <label className="flex items-center gap-2.5 text-sm text-ink2 cursor-pointer">
                    <input type="checkbox" checked={autoConnect} onChange={(e) => setAutoConnect(e.target.checked)} className="accent-[var(--accent)]" />
                    Automatically connect new member accounts
                  </label>
                )}
              </div>
            )}

            {/* STEP 2 — deploy */}
            {step === 2 && onboarding && (
              <div className="flex flex-col gap-5">
                <div className="rounded-xl border border-line p-4" style={{ background: 'var(--panel)' }}>
                  <div className="flex items-center gap-2 text-xs font-semibold text-ink3 mb-2"><KeyRound size={14} /> Trust secret (ExternalId) — shown once</div>
                  <div className="flex items-center gap-2">
                    <code className="font-mono text-sm text-ink flex-1 tracking-wide">{revealEid ? externalId : '•'.repeat(Math.min(40, externalId.length))}</code>
                    <button onClick={() => setRevealEid((v) => !v)} className="text-xs font-semibold text-accent">{revealEid ? 'Hide' : 'Reveal'}</button>
                    <CopyBtn text={externalId} />
                  </div>
                  <div className="text-[11px] text-ink3 mt-2">Minted server-side (never caller-supplied) and stored only as a secret reference. It is baked into the stack below.</div>
                </div>

                {orgMode ? (
                  <div className="rounded-xl border border-line p-4">
                    <div className="text-sm font-semibold text-ink mb-1.5">Deploy the Organization StackSet</div>
                    <p className="text-xs text-ink2 mb-3">From the management account, deploy a service-managed StackSet so every member account gets the read-only role{autoConnect ? ' and future accounts auto-enroll' : ''}.</p>
                    <a href={onboarding.cfn_launch_url} target="_blank" rel="noreferrer" className="inline-flex items-center gap-2 rounded-lg px-4 py-2 text-sm font-semibold text-white ow-grad">
                      <Rocket size={15} /> Launch StackSet <ExternalLink size={13} />
                    </a>
                  </div>
                ) : (
                  <div>
                    <div className="text-sm font-semibold text-ink mb-2">Deploy the read-only role</div>
                    <a href={onboarding.cfn_launch_url} target="_blank" rel="noreferrer" className="inline-flex items-center gap-2 rounded-lg px-4 py-2 text-sm font-semibold text-white ow-grad mb-3">
                      <Rocket size={15} /> Launch CloudFormation stack <ExternalLink size={13} />
                    </a>
                    <div className="text-xs text-ink3 mb-1.5">…or via the AWS CLI:</div>
                    <CodeBox text={onboarding.cli} />
                    <div className="text-[11px] text-ink3 mt-2">Grants <b>SecurityAudit + ViewOnlyAccess</b> only. No write permissions.</div>
                  </div>
                )}
              </div>
            )}

            {/* STEP 3 — validate */}
            {step === 3 && (
              <div className="flex flex-col gap-4">
                <p className="text-sm text-ink2">Once the stack shows <b>CREATE_COMPLETE</b>, validate the connection. OverWatch assumes the role, confirms the account id matches (a fail-closed hard stop), and runs a read canary.</p>
                <button onClick={doValidate} disabled={busy}
                  className="inline-flex items-center gap-2 rounded-lg px-4 py-2 text-sm font-semibold text-white ow-grad disabled:opacity-60 w-fit">
                  {busy ? <Loader2 size={15} className="animate-spin" /> : <ShieldCheck size={15} />}
                  {busy ? 'Validating…' : validation ? 'Re-validate' : 'Validate connection'}
                </button>

                {validation && (() => {
                  const tone = healthTone(validation.health)
                  return (
                    <div className="rounded-xl border p-4" style={{ borderColor: tone.fg }}>
                      <div className="flex items-center gap-2 mb-2">
                        <span className="text-sm font-bold px-2 py-0.5 rounded-full" style={{ color: tone.fg, background: tone.bg }}>{tone.label}</span>
                        <span className="text-sm text-ink2">{validation.summary}</span>
                      </div>
                      <div className="flex flex-col gap-1.5 mt-3">
                        {validation.checks.map((c, i) => (
                          <div key={i} className="flex items-start gap-2 text-xs">
                            {c.ok ? <Check size={14} style={{ color: 'var(--low)' }} className="mt-0.5 shrink-0" /> : <X size={14} style={{ color: 'var(--crit)' }} className="mt-0.5 shrink-0" />}
                            <span className="text-ink font-medium">{c.name}</span>
                            {c.detail && <span className="text-ink3">— {c.detail}</span>}
                          </div>
                        ))}
                      </div>
                    </div>
                  )
                })()}
              </div>
            )}

            {/* STEP 4 — first scan */}
            {step === 4 && (
              <div className="flex flex-col gap-4">
                {!scanJob ? (
                  <>
                    <div className="flex items-center gap-2 text-sm" style={{ color: 'var(--low)' }}>
                      <Check size={16} /> <b>{alias || accountId}</b> is connected and healthy.
                    </div>
                    <p className="text-sm text-ink2">Kick off the first read-only scan. Findings, attack paths, and compliance land on the dashboard when it finishes.</p>
                    <button onClick={doScan} disabled={busy} className="inline-flex items-center gap-2 rounded-lg px-4 py-2 text-sm font-semibold text-white ow-grad disabled:opacity-60 w-fit">
                      {busy ? <Loader2 size={15} className="animate-spin" /> : <Rocket size={15} />}
                      {busy ? 'Queuing…' : 'Run first scan'}
                    </button>
                  </>
                ) : (
                  <div className="flex flex-col items-center text-center gap-3 py-6">
                    <div className="h-14 w-14 rounded-2xl ow-grad grid place-items-center text-white"><Rocket size={26} /></div>
                    <div className="text-lg font-bold text-ink">Scan queued</div>
                    <div className="text-sm text-ink2 max-w-sm">Job <code className="font-mono text-xs">{scanJob}</code> is running. The account now appears in Cloud Accounts; results populate the dashboard shortly.</div>
                  </div>
                )}
              </div>
            )}
          </div>

          {/* footer */}
          <div className="flex items-center justify-between px-6 py-4 border-t border-line">
            <button onClick={() => (step === 0 ? onClose() : setStep((s) => s - 1))} disabled={busy}
              className="inline-flex items-center gap-1.5 text-sm font-semibold text-ink2 hover:text-ink disabled:opacity-50">
              <ArrowLeft size={15} /> {step === 0 ? 'Cancel' : 'Back'}
            </button>
            {step === 1 ? (
              <button onClick={doOnboard} disabled={!idValid || busy} className="inline-flex items-center gap-1.5 rounded-lg px-4 py-2 text-sm font-semibold text-white ow-grad disabled:opacity-50">
                {busy ? <Loader2 size={15} className="animate-spin" /> : null} Mint role & continue <ArrowRight size={15} />
              </button>
            ) : step === 4 ? (
              <button onClick={finish} disabled={busy} className="inline-flex items-center gap-1.5 rounded-lg px-4 py-2 text-sm font-semibold text-white ow-grad disabled:opacity-50">
                {scanJob ? 'Go to Cloud Accounts' : 'Finish'} <Check size={15} />
              </button>
            ) : (
              <button onClick={() => setStep((s) => s + 1)} disabled={!canNext || busy} className="inline-flex items-center gap-1.5 rounded-lg px-4 py-2 text-sm font-semibold text-white ow-grad disabled:opacity-50">
                Next <ArrowRight size={15} />
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}

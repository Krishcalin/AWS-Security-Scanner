import { useEffect, useState } from 'react'
import {
  totpStatus, totpBegin, totpConfirm, totpDisable,
  type TotpEnrolment, type TotpStatus,
} from '../api/auth'

/**
 * Your account's second factor: enrol, see how many recovery codes are left, or
 * turn it off.
 *
 * WHY THERE IS NO QR IMAGE. Encoding a QR correctly means Reed-Solomon over
 * GF(256), mask selection and format bits, and there is no decoder in this project
 * to verify the result against — a subtly wrong encoder produces a symbol that
 * scans as nonsense, and the user experiences that as "enrolment is broken". So the
 * two things that always work are offered instead: the `otpauth://` link, which
 * opens the authenticator directly when this page is viewed on a phone, and the
 * setup key, which every app accepts through "enter a key manually".
 *
 * Because enrolment is not active until a generated code has been typed back, a bad
 * transcription cannot lock anyone out — it simply fails to enrol.
 */
export default function Security() {
  const [status, setStatus] = useState<TotpStatus | null>(null)
  const [enrol, setEnrol] = useState<TotpEnrolment | null>(null)
  const [code, setCode] = useState('')
  const [password, setPassword] = useState('')
  const [codes, setCodes] = useState<string[] | null>(null)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  function refresh() { totpStatus().then(setStatus).catch(() => setStatus(null)) }
  useEffect(refresh, [])

  async function begin() {
    setError(''); setBusy(true)
    try { setEnrol(await totpBegin()) }
    catch (e) { setError(e instanceof Error ? e.message : 'Could not start enrolment') }
    setBusy(false)
  }

  async function confirm(e: React.FormEvent) {
    e.preventDefault(); setError(''); setBusy(true)
    try {
      setCodes(await totpConfirm(code))
      setEnrol(null); setCode(''); refresh()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'That code is not valid')
    }
    setBusy(false)
  }

  async function disable(e: React.FormEvent) {
    e.preventDefault(); setError(''); setBusy(true)
    try {
      await totpDisable(password, code)
      setPassword(''); setCode(''); setCodes(null); refresh()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not turn off two-factor')
    }
    setBusy(false)
  }

  return (
    <div className="sec-page">
      <h1 className="sec-h1">Security</h1>
      <p className="sec-sub">Two-factor authentication for this account.</p>

      {error && <p className="login-error" role="alert">{error}</p>}

      {codes && (
        <section className="sec-card sec-card-warn">
          <h2 className="sec-h2">Recovery codes</h2>
          <p className="sec-p">
            <strong>Save these now.</strong> Only fingerprints are stored, so this is
            the one time they can be shown — they can never be redisplayed, only
            regenerated. Each works once, and they are the way back in if the phone
            is lost or wiped.
          </p>
          <ul className="sec-codes">{codes.map((c) => <li key={c}><code>{c}</code></li>)}</ul>
          <button className="login-btn" onClick={() => setCodes(null)}>
            I have saved them
          </button>
        </section>
      )}

      {status?.enabled ? (
        <section className="sec-card">
          <h2 className="sec-h2">Two-factor is on</h2>
          <p className="sec-p">
            Recovery codes remaining: <strong>{status.recovery_codes_left}</strong>
            {status.recovery_codes_left === 0 &&
              ' — none left. Turn two-factor off and on again to issue a new set.'}
          </p>
          <form className="sec-form" onSubmit={disable}>
            <p className="sec-p">
              Turning it off re-proves <em>both</em> factors. A live session is not
              enough: removing 2FA from a borrowed unlocked browser would otherwise
              be trivial, and it is the one change that weakens every future sign-in.
            </p>
            <input className="login-input" type="password" placeholder="Current password"
                   autoComplete="current-password" value={password}
                   onChange={(e) => setPassword(e.target.value)} />
            <input className="login-input" inputMode="numeric" placeholder="6-digit code"
                   autoComplete="one-time-code" value={code}
                   onChange={(e) => setCode(e.target.value)} />
            <button className="login-btn sec-btn-danger" type="submit" disabled={busy}>
              Turn off two-factor
            </button>
          </form>
        </section>
      ) : enrol ? (
        <section className="sec-card">
          <h2 className="sec-h2">Add it to your authenticator</h2>
          <p className="sec-p">
            Works with Microsoft Authenticator, Google Authenticator, Authy, 1Password
            — anything that speaks the standard. Either tap the link (on a phone) or
            add the key by hand.
          </p>
          <p className="sec-p"><a className="sec-link" href={enrol.uri}>Open in authenticator app</a></p>
          <p className="sec-p">Setup key:</p>
          <p className="sec-secret"><code>{enrol.formatted_secret}</code></p>
          <form className="sec-form" onSubmit={confirm}>
            <p className="sec-p">
              Then enter the code it shows. Nothing changes until this succeeds, so a
              mistyped key cannot lock you out.
            </p>
            <input className="login-input" inputMode="numeric" placeholder="123456"
                   autoComplete="one-time-code" autoFocus value={code}
                   onChange={(e) => setCode(e.target.value)} />
            <button className="login-btn" type="submit" disabled={busy}>
              {busy ? 'Verifying…' : 'Turn on two-factor'}
            </button>
          </form>
        </section>
      ) : (
        <section className="sec-card">
          <h2 className="sec-h2">Two-factor is off</h2>
          <p className="sec-p">
            A second factor means a stolen password is not enough on its own. You will
            need an authenticator app on your phone.
          </p>
          <button className="login-btn" onClick={begin} disabled={busy}>
            {busy ? 'Preparing…' : 'Set up two-factor'}
          </button>
        </section>
      )}
    </div>
  )
}

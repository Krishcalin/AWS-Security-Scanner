/**
 * Coverage — what this scan did NOT establish.
 *
 * Every other screen in the console answers "what did we find". This one answers the
 * question that makes those answers legible: what was refused, what was skipped, and
 * which checks therefore say nothing rather than saying nothing-is-wrong.
 *
 * A check that returned AccessDenied and one that ran and passed are different claims
 * about the world. Rendering them identically is how a report gets read as a clean bill
 * of health when a third of the estate was never examined — so this page leads with the
 * distinction rather than burying it in a footnote.
 */
import { useEffect, useState } from 'react'
import { ShieldCheck, ShieldAlert, KeyRound, Globe, Info } from 'lucide-react'
import { api } from '../api/client'
import type { AccountSummary } from '../api/types'
import { useScope } from '../state/scope'
import { Card, Chip, CopyField, Empty, ErrorNote, Loader, SectionLabel } from '../components/ui'

export function Coverage() {
  const { scope } = useScope()
  const [data, setData] = useState<AccountSummary | null>(null)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    if (scope === 'org') { setData(null); return }
    setLoading(true); setError('')
    api.accountSummary(scope)
      .then(setData)
      .catch((e) => setError(e instanceof Error ? e.message : 'could not load coverage'))
      .finally(() => setLoading(false))
  }, [scope])

  if (scope === 'org') {
    return (
      <div className="flex flex-col gap-4">
        <Header />
        <Card className="p-5">
          <Empty icon={<Info size={16} />}>
            Coverage is a property of one scan of one account — which regions it reached,
            which permissions it held. Pick an account in the scope switcher above.
          </Empty>
        </Card>
      </div>
    )
  }

  if (loading) return <div className="flex flex-col gap-4"><Header /><Loader label="Reading coverage…" /></div>
  if (error) return <div className="flex flex-col gap-4"><Header /><ErrorNote msg={error} /></div>
  if (!data) return <div className="flex flex-col gap-4"><Header /><Loader /></div>

  const cov = data.coverage ?? null
  const ledger = data.permission_ledger ?? null

  // No manifest at all means the scan predates this feature. That is itself unknown
  // coverage, and saying "complete" would be inventing an assurance we do not have.
  if (!cov) {
    return (
      <div className="flex flex-col gap-4">
        <Header />
        <Card className="p-5">
          <Empty icon={<Info size={16} />}>
            This scan carries no coverage record — it ran before coverage was tracked.
            That is not the same as complete coverage. Re-scan to produce one.
          </Empty>
        </Card>
      </div>
    )
  }

  const notEvaluated = Object.entries(cov.not_evaluated ?? {})
  const unscanned = cov.unscanned_regions ?? []

  return (
    <div className="flex flex-col gap-4">
      <Header />

      {/* The verdict, first and unambiguous. */}
      <Card className="p-5">
        <div className="flex items-start gap-4">
          {cov.complete
            ? <ShieldCheck size={28} className="text-info shrink-0 mt-0.5" />
            : <ShieldAlert size={28} className="text-med shrink-0 mt-0.5" />}
          <div>
            <div className="text-lg font-semibold">
              {cov.complete
                ? 'This scan withheld nothing'
                : 'This scan did not see everything'}
            </div>
            <p className="text-sm text-ink2 mt-1 max-w-[70ch]">
              {cov.complete
                ? `Every check ran, and every enabled region was examined. The posture grade
                   for ${data.account} is measured over the whole account.`
                : `${notEvaluated.length} check${notEvaluated.length === 1 ? '' : 's'} could not
                   be evaluated and ${unscanned.length} region${unscanned.length === 1 ? ' was' : 's were'}
                   not examined. Read the posture grade for ${data.account} with that in mind:
                   the findings below are absent evidence, not negative evidence.`}
            </p>
          </div>
        </div>
      </Card>

      {/* Not evaluated ≠ passed. */}
      {notEvaluated.length > 0 && (
        <Card className="p-5">
          <SectionLabel n={String(notEvaluated.length)}>Checks that were not evaluated</SectionLabel>
          <p className="text-sm text-ink2 mt-1 mb-3 max-w-[70ch]">
            These did not pass. They did not run. Nothing in the findings list represents
            them, in either direction.
          </p>
          <div className="flex flex-col divide-y divide-line">
            {notEvaluated.map(([checkId, reason]) => (
              <div key={checkId} className="py-2.5 flex flex-wrap items-baseline gap-x-3 gap-y-1">
                <span className="font-mono text-sm font-semibold">{checkId}</span>
                <Chip fg="var(--med)" bg="var(--medbg)">not evaluated</Chip>
                <span className="text-sm text-ink2">{reason}</span>
              </div>
            ))}
          </div>
        </Card>
      )}

      {/* Regions. */}
      <Card className="p-5">
        <SectionLabel><Globe size={13} className="inline -mt-0.5 mr-1" />Regions</SectionLabel>
        <div className="mt-2 flex flex-col gap-2 text-sm">
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-ink3 w-28 shrink-0">Examined</span>
            {(cov.scanned_regions ?? []).map((r) => (
              <Chip key={r} mono fg="var(--info)" bg="var(--infobg)">{r}</Chip>
            ))}
            {(cov.scanned_regions ?? []).length === 0 && <span className="text-ink3">none recorded</span>}
          </div>
          {unscanned.length > 0 && (
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-ink3 w-28 shrink-0">Not examined</span>
              {unscanned.map((r) => (
                <Chip key={r} mono fg="var(--med)" bg="var(--medbg)">{r}</Chip>
              ))}
            </div>
          )}
        </div>
        {unscanned.length > 0 && (
          <p className="text-xs text-ink3 mt-3 max-w-[70ch]">
            A clean result across one region is not a clean result across the account.
            Re-run with <span className="font-mono">--all-regions</span> for full coverage.
          </p>
        )}
      </Card>

      {/* The ledger: what each withheld permission costs. */}
      {ledger && (ledger.annotated_policy ?? []).length > 0 && (
        <Card className="p-5">
          <SectionLabel n={String(ledger.annotated_policy.length)}>
            <KeyRound size={13} className="inline -mt-0.5 mr-1" />
            Permissions that would close the gap
          </SectionLabel>
          <p className="text-sm text-ink2 mt-1 mb-3 max-w-[70ch]">
            Every action below is read-only and individually justified. Decline any one of
            them and the checks it enables stay un-evaluated — which is a decision you can
            now make deliberately rather than by omission.
          </p>
          <div className="flex flex-col divide-y divide-line">
            {ledger.annotated_policy.map((row) => (
              <div key={row.action} className="py-3">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="font-mono text-sm font-semibold">{row.action}</span>
                  {row.enables.map((c) => (
                    <Chip key={c} mono fg="var(--accent)" bg="var(--infobg)">{c}</Chip>
                  ))}
                </div>
                <p className="text-sm text-ink2 mt-1 max-w-[74ch]">{row.why}</p>
                {row.forfeited_if_declined.length > 0 && (
                  <p className="text-xs text-ink3 mt-1">
                    Decline this and you forfeit{' '}
                    <span className="font-mono">{row.forfeited_if_declined.join(', ')}</span>.
                  </p>
                )}
              </div>
            ))}
          </div>

          <div className="mt-4">
            <SectionLabel>The minimal policy, and nothing more</SectionLabel>
            <p className="text-sm text-ink2 mt-1 mb-2 max-w-[70ch]">
              Only what is actually missing, so a reviewer can diff it against what they
              already grant.
            </p>
            <CopyField text={JSON.stringify({
              Version: '2012-10-17',
              Statement: [{
                Sid: 'CnappAIReadOnly',
                Effect: 'Allow',
                Action: ledger.missing_actions,
                Resource: '*',
              }],
            }, null, 2)} />
          </div>
        </Card>
      )}

      {/* Free checks — worth stating, because they cost the reviewer nothing. */}
      {ledger && (ledger.free ?? []).length > 0 && (
        <Card className="p-5">
          <SectionLabel>Checks that need no permission at all</SectionLabel>
          <p className="text-sm text-ink2 mt-1 mb-2 max-w-[70ch]">
            These reason over data the scan already holds — cached IAM principals and graph
            edges other checks produced. They are free.
          </p>
          <div className="flex flex-wrap gap-2">
            {ledger.free.map((c) => <Chip key={c} mono>{c}</Chip>)}
          </div>
        </Card>
      )}
    </div>
  )
}

function Header() {
  return (
    <Card className="p-5">
      <div className="text-lg font-semibold">Coverage</div>
      <p className="text-sm text-ink2 mt-1 max-w-[74ch]">
        What this scan did not establish. Every other screen shows what was found; this one
        shows the boundary of the search, so a grade is read with its denominator.
      </p>
    </Card>
  )
}

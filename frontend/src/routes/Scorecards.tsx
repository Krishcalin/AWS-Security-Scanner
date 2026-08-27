/**
 * Scorecards — FR-2, rendered so that what the backend refuses to say stays refused.
 *
 * WHY THIS SCREEN IS MOSTLY ABOUT ABSENCE
 * ---------------------------------------
 * The assembler spends most of its effort withholding: a grade with no risk model
 * behind it, a rank with no asset count to normalise by, a trend with no prior
 * month, a closure rate quoted without the approvals that produced it. Every one
 * of those arrives here as `null` plus a sentence explaining itself.
 *
 * A screen that renders those as "—" would undo all of it. An em-dash reads as
 * "zero", or as "nothing to see", and the reader moves on. So a withheld figure
 * gets the reason in its place, and the reason is the shortest honest thing that
 * fits — not a tooltip, which nobody opens, and not a footnote, which nobody
 * reaches.
 *
 * THE UNOWNED ROW
 * ---------------
 * Findings no application claims appear as a row with no owner and no grade,
 * styled so it cannot be mistaken for an application. It sorts last. It is the
 * single most useful line on the page for anyone deciding whether the registry is
 * finished, which is why it is on the page rather than in a coverage footnote.
 */
import { AlertTriangle, Crown, Info, ShieldQuestion, Users } from 'lucide-react'
import { api } from '../api/client'
import type { Scorecard, ScorecardPack } from '../api/types'
import { useFetch } from '../lib/useFetch'
import { Card, Empty, ErrorNote, Loader, SectionLabel } from '../components/ui'

const GRADE_TONE: Record<string, string> = {
  A: 'var(--ok)', B: 'var(--ok)', C: 'var(--med)', D: 'var(--high)', E: 'var(--crit)',
}

/** A figure the backend declined to produce, with the decline shown in its place. */
function Withheld({ what, why }: { what: string; why: string }) {
  return (
    <div className="flex items-start gap-1.5 text-[11px] leading-snug text-ink3">
      <ShieldQuestion size={12} className="mt-px shrink-0" />
      <span><span className="font-semibold">{what} withheld.</span> {why}</span>
    </div>
  )
}

function GradeBlock({ c }: { c: Scorecard }) {
  if (c.grade === null) {
    return (
      <div className="w-24 shrink-0">
        <div className="text-2xl font-black leading-none text-ink3">··</div>
        <div className="text-[10px] text-ink3 mt-1">no grade</div>
      </div>
    )
  }
  return (
    <div className="w-24 shrink-0">
      <div className="text-3xl font-black leading-none"
        style={{ color: GRADE_TONE[c.grade] ?? 'var(--ink2)' }}>{c.grade}</div>
      <div className="text-[11px] text-ink3 mt-0.5 tabular-nums">
        posture {c.posture}
      </div>
    </div>
  )
}

function Counts({ c }: { c: Scorecard }) {
  return (
    <div className="flex items-center gap-4 text-xs tabular-nums">
      <span><b className="text-base" style={{ color: 'var(--crit)' }}>{c.open_critical}</b>
        <span className="text-ink3 ml-1">critical</span></span>
      <span><b className="text-base" style={{ color: 'var(--high)' }}>{c.open_high}</b>
        <span className="text-ink3 ml-1">high</span></span>
      {c.excepted > 0 && (
        // Segregated, never merged (OW2-SC-008). Shown in a different tone so it
        // reads as "set aside by decision", not as "fixed".
        <span className="rounded px-1.5 py-0.5" style={{ background: 'var(--panel2)' }}>
          <b>{c.excepted}</b><span className="text-ink3 ml-1">excepted</span>
        </span>
      )}
    </div>
  )
}

function Row({ c }: { c: Scorecard }) {
  const unowned = c.app_id === '__unattributed__'
  return (
    <div className="rounded-xl border px-4 py-3.5 flex flex-col gap-2.5"
      style={{
        borderColor: unowned ? 'var(--high)' : 'var(--line)',
        background: unowned ? 'var(--panel2)' : 'var(--panel)',
      }}>
      <div className="flex items-start gap-4">
        <GradeBlock c={c} />
        <div className="flex-1 min-w-0 flex flex-col gap-1.5">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="font-semibold text-ink">{c.name}</span>
            {unowned ? (
              <span className="text-[10px] font-semibold rounded px-1.5 py-0.5"
                style={{ background: 'var(--highbg)', color: 'var(--high)' }}>
                no owner — not an application
              </span>
            ) : (
              <>
                <span className="text-xs text-ink3 flex items-center gap-1">
                  <Users size={11} />{c.owner || 'unassigned'}
                </span>
                {c.criticality === 'crown-jewel' && (
                  <span className="text-[10px] font-semibold rounded px-1.5 py-0.5 flex items-center gap-1"
                    style={{ background: 'var(--goldbg)', color: 'var(--gold)' }}>
                    <Crown size={9} />crown jewel
                  </span>
                )}
                {c.portfolio && (
                  <span className="text-[10px] text-ink3 rounded px-1.5 py-0.5"
                    style={{ background: 'var(--panel2)' }}>{c.portfolio}</span>
                )}
              </>
            )}
          </div>
          <Counts c={c} />
          <div className="text-[11px] text-ink2 leading-snug">{c.sla_line}</div>
        </div>
        <div className="w-40 shrink-0 flex flex-col gap-1 items-end text-right">
          {c.rank !== null
            ? <div className="text-xs text-ink2 tabular-nums">
              rank <b className="text-ink">{c.rank}</b> of {c.peers}
              <div className="text-[10px] text-ink3">{c.per_100_assets} per 100 assets</div>
            </div>
            : null}
          {c.trend
            ? <div className="text-[11px]"
              style={{ color: c.trend.direction === 'worsened' ? 'var(--crit)' : 'var(--ok)' }}>
              {c.trend.render}
            </div>
            : null}
        </div>
      </div>

      {/* Every withheld figure states itself here rather than rendering as a dash. */}
      {(c.grade_withheld || c.rank_withheld || !c.trend) && (
        <div className="flex flex-col gap-1 pt-2 border-t" style={{ borderColor: 'var(--line2)' }}>
          {c.grade_withheld && <Withheld what="Grade" why={c.grade_withheld} />}
          {c.rank_withheld && <Withheld what="Peer rank" why={c.rank_withheld} />}
          {!c.trend && !unowned && (
            <Withheld what="Trend" why="No prior period to compare against — a first scorecard, not a month with no change." />
          )}
        </div>
      )}
    </div>
  )
}

function CoverageBanner({ pack }: { pack: ScorecardPack }) {
  const bad = !pack.coverage.complete && pack.coverage.total > 0
  // A plain div rather than <Card>: the incomplete-coverage state needs a border
  // colour, and Card takes no style prop. Same classes, so it reads identically.
  return (
    <div className="rounded-2xl border bg-panel shadow-sm p-4 flex items-start gap-3"
      style={{ borderColor: bad ? 'var(--high)' : 'var(--line)' }}>
      {bad ? <AlertTriangle size={16} style={{ color: 'var(--high)' }} className="mt-0.5 shrink-0" />
        : <Info size={16} className="mt-0.5 shrink-0 text-ink3" />}
      <div className="text-sm text-ink2 leading-snug">{pack.headline}</div>
    </div>
  )
}

export function Scorecards() {
  const { data, loading, error } = useFetch<ScorecardPack>(() => api.scorecards(), [])

  if (loading) return <Loader />
  if (error) return <ErrorNote msg={error} />
  if (!data) return null

  const note = api.sampleFr2Note()

  return (
    <div className="flex flex-col gap-4">
      <div>
        <h1 className="text-xl font-bold text-ink">Scorecards</h1>
        <p className="text-sm text-ink3 mt-0.5">
          One card per application, with everything the scan could not establish
          said out loud rather than left blank.
        </p>
      </div>

      {note && (
        <Card className="p-4 text-sm text-ink2 flex items-start gap-3">
          <Info size={16} className="mt-0.5 shrink-0 text-ink3" />
          <span>{note}</span>
        </Card>
      )}

      {!note && <CoverageBanner pack={data} />}

      {data.scorecards.length === 0 && !note ? (
        <Card className="p-5">
          <Empty icon={<Users size={22} />}>
            No applications defined yet. Findings cannot be attributed to an owner
            until the registry has something in it — define one under Applications.
          </Empty>
        </Card>
      ) : (
        <div className="flex flex-col gap-2.5">
          <SectionLabel>Applications</SectionLabel>
          {data.scorecards.map((c) => <Row key={c.app_id} c={c} />)}
        </div>
      )}
    </div>
  )
}

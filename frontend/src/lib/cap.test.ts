/**
 * A rendered list must say when it is not the whole list.
 *
 * The backend half of this shipped first: `cnapp_service.capped()` declares every
 * truncation and an AST ratchet fails the build on a new undeclared cap. The
 * console had the same defect and that ratchet could not see it — a row showed
 * three compliance frameworks of seven, the Overview showed five attack paths of
 * however many, and the exported HTML report showed "top 25" with no hint that a
 * twenty-sixth existed.
 *
 * The report is the worst case and the reason this file exists: it leaves the
 * building and is read as complete by someone who cannot go and check.
 *
 * `no_new_silent_cap_in_the_console` is the durable half. It reads the source and
 * asserts every `.slice(0, N)` is either registered as display-only or sits next
 * to a declaration. A new one fails until its author picks a side.
 */
import { describe, it, expect } from 'vitest'
import fs from 'node:fs'
import path from 'node:path'
import { capNote, ofTotal, cap, serverCapNote } from './cap'

describe('capNote', () => {
  it('says how many were dropped', () => {
    expect(capNote(3, 7)).toBe('+4 more')
  })

  it('is null when nothing was dropped, so a caller renders nothing', () => {
    expect(capNote(7, 7)).toBeNull()
    expect(capNote(9, 7)).toBeNull()
  })

  it('never prints "+0 more"', () => {
    for (let n = 0; n < 20; n++) expect(capNote(n, n)).toBeNull()
  })

  it('treats an empty list as complete, not as truncated', () => {
    expect(capNote(0, 0)).toBeNull()
  })
})

describe('ofTotal', () => {
  it('states both numbers when the list was cut', () => {
    expect(ofTotal(25, 214)).toBe('25 of 214')
  })

  it('states one number when it was not', () => {
    expect(ofTotal(9, 9)).toBe('9')
  })
})

describe('cap', () => {
  it('returns the items, the pre-cut total, and the note together', () => {
    expect(cap([1, 2, 3, 4, 5], 3)).toEqual({
      shown: [1, 2, 3], total: 5, truncated: true, note: '+2 more',
    })
  })

  it('reports an uncut list as complete', () => {
    expect(cap([1, 2], 5)).toEqual({
      shown: [1, 2], total: 2, truncated: false, note: null,
    })
  })

  it('survives null and undefined', () => {
    for (const empty of [null, undefined]) {
      expect(cap(empty, 5)).toEqual({ shown: [], total: 0, truncated: false, note: null })
    }
  })

  it('does not alias the caller list', () => {
    const src = [1, 2, 3]
    cap(src, 10).shown.push(4)
    expect(src).toEqual([1, 2, 3])
  })

  it('keeps the total from BEFORE the cut', () => {
    const r = cap(Array.from({ length: 900 }, (_, i) => i), 500)
    expect(r.shown).toHaveLength(500)
    expect(r.total).toBe(900)
    expect(r.note).toBe('+400 more')
  })
})

describe('serverCapNote', () => {
  it('uses the wire total when the server declared one', () => {
    expect(serverCapNote(5, 47)).toBe('+42 more')
  })

  it('returns null when the server declared nothing, rather than guessing', () => {
    // An older hub sends no `_total`. Absence of a declaration is not evidence
    // that nothing was dropped, so we say nothing rather than assert completeness.
    expect(serverCapNote(5, undefined)).toBeNull()
    expect(serverCapNote(5, null)).toBeNull()
  })

  it('says nothing when the server total matches what we render', () => {
    expect(serverCapNote(5, 5)).toBeNull()
  })
})

// ── the ratchet ─────────────────────────────────────────────────────────────

const SRC = path.resolve(__dirname, '..')

/** file:line-fragment -> why this `.slice(0, N)` is not an undeclared truncation. */
const DISPLAY_ONLY: Record<string, string> = {
  'components/AttackPathCanvas.tsx': 'severity.slice(0,1) renders the first letter of a severity band. A character, not a list.',
  'components/OnboardWizard.tsx': 'bounds an account-id INPUT to 12 characters as the user types. Nothing is hidden.',
  'components/TopBar.tsx': 'label.slice(0,1) takes the first character of a name for an avatar initial. A character, not a list.',
  'lib/nodes.ts': 'truncates a long ARN tail and appends an ellipsis, which IS the declaration.',
  'routes/Registries.tsx': 'digest.slice(0,19) shortens a sha256 for display; the tag or full digest is the fallback.',
  'routes/SupplyChain.tsx': 'digest.slice(0,16) shortens a sha256 and carries the full value in title=.',
  'routes/TopRisks.tsx': 'severity.slice(0,4) abbreviates a severity label.',
  'routes/Settings.tsx': 'the line directly above states the true count ("would fire N time(s)"), so the 12-chip cap is already declared.',
  'api/client.ts': 'synthesises 5 sample findings for the scheduling PREVIEW shape. It invents rows rather than hiding them.',
}

/** Files where a cap now renders a note next to the list. */
const DECLARED = new Set([
  // cap.ts itself is absent on purpose: it slices with a VARIABLE limit, so it
  // never matches the literal pattern this ratchet scans for.
  'lib/policy.ts',
  'lib/reports.ts',
  'routes/Findings.tsx',
  'routes/Overview.tsx',
  'routes/AttackPaths.tsx',
  'routes/Vulnerabilities.tsx',
  'routes/Query.tsx',
])

function walk(dir: string, out: string[] = []): string[] {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name)
    if (e.isDirectory()) walk(p, out)
    else if (/\.tsx?$/.test(e.name) && !/\.test\.tsx?$/.test(e.name)) out.push(p)
  }
  return out
}

describe('no_new_silent_cap_in_the_console', () => {
  it('every .slice(0, N) is either display-only or declared', () => {
    const offenders: string[] = []
    for (const file of walk(SRC)) {
      const rel = path.relative(SRC, file).replace(/\\/g, '/')
      const src = fs.readFileSync(file, 'utf8')
      if (!/\.slice\(0, ?\d+\)/.test(src)) continue
      if (rel in DISPLAY_ONLY || DECLARED.has(rel)) continue
      offenders.push(rel)
    }
    expect(offenders,
      'These files cut a list without saying so. Render capNote()/serverCapNote() '
      + 'next to the list and add the file to DECLARED, or add a DISPLAY_ONLY entry '
      + 'explaining why nothing is hidden.').toEqual([])
  })

  it('the registries have not gone stale', () => {
    const withSlices = new Set(
      walk(SRC)
        .filter((f) => /\.slice\(0, ?\d+\)/.test(fs.readFileSync(f, 'utf8')))
        .map((f) => path.relative(SRC, f).replace(/\\/g, '/')),
    )
    const stale = [...Object.keys(DISPLAY_ONLY), ...DECLARED].filter((f) => !withSlices.has(f))
    expect(stale, 'registered files that no longer cap anything').toEqual([])
  })

  it('every display-only exemption states a reason', () => {
    for (const [file, why] of Object.entries(DISPLAY_ONLY)) {
      expect(why.length, `${file} is exempt without a real reason`).toBeGreaterThan(40)
    }
  })
})

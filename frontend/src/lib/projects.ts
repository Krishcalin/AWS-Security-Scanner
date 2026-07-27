// Client-side Project matcher — the exact mirror of cnapp_service._finding_in_project, so
// SAMPLE mode (matching over the findings fixtures) agrees with the live hub. Pure + testable.
import type { FindingCatalogEntry } from '../api/types'

export interface ProjectMatch { accounts?: string[]; resource_globs?: string[] }

// case-sensitive glob — a faithful fnmatch.translate so it mirrors Python's fnmatchcase
// (aws_state._glob), INCLUDING [...]/[!...] character classes, so SAMPLE == LIVE.
function globMatch(pattern: string, value: string): boolean {
  let re = ''
  let i = 0
  const n = pattern.length
  while (i < n) {
    const c = pattern[i]; i++
    if (c === '*') re += '.*'
    else if (c === '?') re += '.'
    else if (c === '[') {
      let j = i
      if (j < n && (pattern[j] === '!' || pattern[j] === '^')) j++
      if (j < n && pattern[j] === ']') j++
      while (j < n && pattern[j] !== ']') j++
      if (j >= n) { re += '\\[' }                       // unterminated '[' → literal
      else {
        let cls = pattern.slice(i, j).replace(/\\/g, '\\\\')
        i = j + 1
        if (cls[0] === '!') cls = '^' + cls.slice(1)    // [!abc] → [^abc]
        re += '[' + cls + ']'
      }
    } else {
      re += c.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')     // escape regex specials
    }
  }
  return new RegExp('^' + re + '$').test(value)
}

/** A finding belongs to a project when its account is in match.accounts (if given) AND one of
 *  its affected resources matches match.resource_globs (if given). Empty match → matches nothing. */
export function findingInProject(f: Pick<FindingCatalogEntry, 'affected'> & { account?: string }, match: ProjectMatch): boolean {
  const accts = match.accounts ?? []
  if (accts.length && (!f.account || !accts.includes(f.account))) return false
  const globs = match.resource_globs ?? []
  if (globs.length) return (f.affected ?? []).some((r) => globs.some((g) => globMatch(g, r)))
  return accts.length > 0
}

export function severityCounts(findings: FindingCatalogEntry[]): Record<string, number> {
  const c: Record<string, number> = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 }
  for (const f of findings) if (f.severity in c) c[f.severity]++
  return c
}

export const TIER_META: Record<string, { label: string; color: string }> = {
  HBI: { label: 'High business impact', color: 'var(--crit)' },
  MBI: { label: 'Medium business impact', color: 'var(--gold)' },
  LBI: { label: 'Low business impact', color: 'var(--low)' },
}

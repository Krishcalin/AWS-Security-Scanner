import { PANEL_PARAMS } from '../deeplink'
import { SCENARIOS } from './scenarios'

// Static, structural validation of the scenario registry — cheap invariants that would
// otherwise fail silently at runtime (a typo'd route, a param outside the whitelist, a
// malformed scope, a duplicate step id). Run in DEV from the provider; the anchor
// RESOLUTION check happens live (a missing anchor degrades to a centered coachmark).
const ROUTES = new Set([
  '/', '/attack-paths', '/findings', '/vulnerabilities', '/inventory', '/identity',
  '/compliance', '/remediation', '/reports', '/accounts', '/settings',
])

export function validateScenarios(): string[] {
  const errs: string[] = []
  const whitelist = PANEL_PARAMS as readonly string[]
  for (const sc of SCENARIOS) {
    if (sc.steps.length === 0) errs.push(`${sc.id}: has no steps`)
    const ids = new Set<string>()
    sc.steps.forEach((s, i) => {
      const at = `${sc.id}[${i}] ${s.id}`
      if (ids.has(s.id)) errs.push(`${at}: duplicate step id`)
      ids.add(s.id)
      if (s.route && !ROUTES.has(s.route)) errs.push(`${at}: unknown route "${s.route}"`)
      if (s.scope && s.scope !== 'org' && !/^[0-9]{12}$/.test(s.scope)) errs.push(`${at}: bad scope "${s.scope}"`)
      for (const k of Object.keys(s.params ?? {})) {
        if (!whitelist.includes(k)) errs.push(`${at}: param "${k}" not in PANEL_PARAMS`)
      }
      if (s.anchor !== undefined && s.anchor.trim() === '') errs.push(`${at}: empty anchor`)
      if (s.waitFor !== undefined && s.waitFor.trim() === '') errs.push(`${at}: empty waitFor`)
    })
  }
  return errs
}

/** DEV-only: warn (never throw) if the registry is malformed. */
export function runDevValidation(): void {
  const errs = validateScenarios()
  if (errs.length) console.warn(`[tour] scenario validation found ${errs.length} issue(s):\n` + errs.join('\n'))
}

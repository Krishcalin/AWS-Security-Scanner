/**
 * riskfactors — decompose an attack-path score into factors a reader can argue with.
 *
 * The reference dashboard this answers shows a Risk Factors table with two axes: where a
 * factor comes from, and what it drives. It is the best score-explanation UX in the
 * category. It is also the one thing that vendor cannot do honestly, because it publishes
 * neither its weights nor its formula — the bars are asserted, not derived.
 *
 * We publish both, so this table can be *computed*:
 *
 *     risk  = exposure x exploitability x max(privilege, impact) x reach x boost
 *     score = round(100 x min(1, risk))        then floors and caps override it
 *
 * A COUNTERFACTUAL, NOT A WEIGHT — AND NOT A "CONTRIBUTION"
 * ----------------------------------------------------------
 * "How much is exposure worth here?" has an exact answer in a multiplicative model: the
 * score this path would carry if that factor alone were 1.0. A reader can put it back in
 * the published formula and get the same number — checkable arithmetic rather than a bar
 * whose length we chose.
 *
 * The column is called "if neutral" and its delta "withheld", never "contribution".
 * Every factor is <= 1.0 and the model multiplies, so a factor does not ADD risk — it
 * damps the maximum. Calling that a contribution inverts the reader's intuition about
 * which number to go and fix.
 *
 * THREE WAYS A FACTOR CAN CONTRIBUTE NOTHING, ALL OF WHICH MUST BE SAID
 * ----------------------------------------------------------------------
 *  1. DOMINATED — the model takes max(privilege, impact), so the smaller of the two is
 *     not in the product at all. Drawing it as a contributing bar would be a lie.
 *  2. SATURATED — the product is clamped to 1.0 before scaling, so once it exceeds 1.0
 *     a factor can improve and move nothing.
 *  3. OVERRIDDEN — a floor or cap decided the score, and the arithmetic did not. Showing
 *     a factor table without saying so presents a derivation that did not happen.
 *
 * WHY THIS FILE DOES NOT REPLICATE THE SCORER
 * --------------------------------------------
 * It recomputes only the published product, never the floor/cap constants. Whether an
 * override bound is *observed* — by comparing the arithmetic result to the score the
 * engine actually stored — rather than predicted from copied thresholds. So this cannot
 * drift out of step with `aws_correlate.WEIGHTS` when those numbers change.
 */
import type { AttackPath } from '../api/types'

/** What a factor drives. The reference table calls this "Contribution Type". */
export type Axis = 'probability' | 'impact'

/**
 * Where a factor comes from. Three values rather than the reference table's two
 * (risk-based / asset-based), because ours genuinely has three sources and collapsing
 * threat intelligence into "risk" would hide that it is externally supplied.
 */
export type Origin = 'asset' | 'path' | 'threat'

export type FactorState = 'active' | 'dominated' | 'saturated' | 'overridden'

export interface FactorRow {
  key: string
  label: string
  /** The raw 0–1 value the engine recorded. */
  value: number
  axis: Axis
  origin: Origin
  /** What this value means in this estate, in the reader's terms. */
  meaning: string
  state: FactorState
  /**
   * The score this path would carry if THIS factor alone were neutral (1.0). Null
   * unless `active`. Stated as a resulting score rather than a bar length because it is
   * directly checkable: a reader can put 1.0 in the published formula and get this back.
   */
  ifNeutral: number | null
  /**
   * Points this factor is currently withholding (`ifNeutral - arithmeticScore`).
   *
   * Deliberately NOT called "contribution". Every factor here is <= 1.0 and the model
   * multiplies, so a factor does not add risk — it damps the maximum. A factor at 1.0
   * withholds nothing; one at 0.5 halves the score. Labelling that "contribution" would
   * invert the reader's intuition about which numbers to go and fix.
   */
  withheld: number | null
  /** Why the numbers above are null. Empty when the row is active. */
  note: string
}

export type Determination = 'arithmetic' | 'floor' | 'cap'

export interface FactorTable {
  rows: FactorRow[]
  /** What actually set the score. */
  determinedBy: Determination
  /** The score the published formula produces, before any floor or cap. */
  arithmeticScore: number
  /** The score the engine stored. */
  score: number
  /** One sentence naming what decided the number. Always shown. */
  verdict: string
  /** True when the product exceeded 1.0 and was clamped. */
  saturated: boolean
}

interface Spec { key: string; label: string; axis: Axis; origin: Origin }

/**
 * Axis and origin are assignments about OUR model, made from what each term is computed
 * from in aws_correlate — not borrowed from the reference table's taxonomy.
 */
const SPECS: Spec[] = [
  { key: 'exposure', label: 'Exposure', axis: 'probability', origin: 'asset' },
  { key: 'exploitability', label: 'Exploitability', axis: 'probability', origin: 'path' },
  { key: 'privilege', label: 'Privilege', axis: 'impact', origin: 'path' },
  { key: 'impact', label: 'Impact', axis: 'impact', origin: 'asset' },
  { key: 'reach', label: 'Reach', axis: 'impact', origin: 'path' },
  { key: 'boost', label: 'Threat boost', axis: 'probability', origin: 'threat' },
]

const num = (v: unknown, fallback = 1): number =>
  typeof v === 'number' && Number.isFinite(v) ? v : fallback

/** Plain-language reading of a factor's value. Bands, not invented precision. */
function meaningOf(key: string, v: number, p: AttackPath): string {
  switch (key) {
    case 'exposure':
      return v >= 0.95 ? 'Entry point is directly internet-reachable'
        : v >= 0.8 ? 'Entry point is reachable, with one qualifying gate'
        : 'Entry is indirect or partially gated'
    case 'exploitability':
      if (p.kev) return 'A known-exploited vulnerability sits on the path'
      return v >= 0.9 ? 'A usable flaw with public exploit code'
        : v >= 0.5 ? 'A flaw with meaningful exploitation likelihood'
        : v <= 0.2 ? 'No vulnerability on the path — exposure alone'
        : 'Limited exploitation likelihood'
    case 'privilege':
      return v >= 1 ? 'Path reaches administrative control'
        : v >= 0.6 ? 'Path reaches data-plane privilege'
        : 'Limited privilege at the terminal'
    case 'impact':
      return v >= 1 ? 'Terminal is a publicly-exposed crown jewel'
        : v >= 0.9 ? 'Terminal is a private crown jewel'
        : v >= 0.85 ? 'Terminal grants administrative control'
        : 'Terminal is not classified crown-jewel'
    case 'reach':
      return v >= 0.9 ? 'Opens most of what this identity can touch'
        : v >= 0.6 ? 'Opens a substantial share of the estate'
        : 'Narrow onward reach'
    case 'boost':
      return p.active_threat ? 'An active threat was observed against this path'
        : p.kev ? 'KEV listing raises the likelihood'
        : 'No threat-intelligence multiplier'
    default:
      return ''
  }
}

const clampScore = (product: number) =>
  Math.max(0, Math.min(100, Math.round(100 * Math.min(1, product))))

/**
 * Build the table. Pure: everything comes from `path.factors` and the path's own flags,
 * so a stored scan from any version decomposes without a rescan.
 */
export function factorTable(path: AttackPath): FactorTable {
  const f = path.factors ?? {}
  const value: Record<string, number> = {}
  for (const s of SPECS) value[s.key] = num(f[s.key], 1)

  // The model takes max(privilege, impact); the loser is not in the product at all.
  const dominant = value.privilege >= value.impact ? 'privilege' : 'impact'
  const dominated = dominant === 'privilege' ? 'impact' : 'privilege'
  // A genuine tie is not domination — both values are the term, and calling one
  // "dominated" would imply improving it is pointless when it is not.
  const tied = value.privilege === value.impact

  const product = value.exposure * value.exploitability * value[dominant]
    * value.reach * value.boost
  const arithmeticScore = clampScore(product)
  const score = num(path.score, arithmeticScore)
  const saturated = product > 1

  let determinedBy: Determination = 'arithmetic'
  if (score > arithmeticScore) determinedBy = 'floor'
  else if (score < arithmeticScore) determinedBy = 'cap'

  const rows: FactorRow[] = SPECS.map((s) => {
    const v = value[s.key]
    const base: Omit<FactorRow, 'state' | 'ifNeutral' | 'withheld' | 'note'> = {
      key: s.key, label: s.label, value: v, axis: s.axis, origin: s.origin,
      meaning: meaningOf(s.key, v, path),
    }

    if (!tied && s.key === dominated) {
      return {
        ...base, state: 'dominated', ifNeutral: null, withheld: null,
        note: `The model uses max(privilege, impact); ${dominant} is larger, so this term `
          + `is not in the product. Raising it changes nothing until it exceeds ${dominant}.`,
      }
    }
    if (determinedBy !== 'arithmetic') {
      return {
        ...base, state: 'overridden', ifNeutral: null, withheld: null,
        note: determinedBy === 'floor'
          ? 'A severity floor set this score, so the arithmetic did not decide it.'
          : 'A cap set this score, so the arithmetic did not decide it.',
      }
    }
    if (saturated) {
      return {
        ...base, state: 'saturated', ifNeutral: null, withheld: null,
        note: 'The factor product exceeded 1.0 and was clamped, so no single factor '
          + 'moves the score at this level.',
      }
    }
    // The counterfactual: neutralise this one term, hold the rest. Dividing rather than
    // rebuilding the product keeps this exact for the dominant term without needing to
    // know which of privilege/impact it was.
    const ifNeutral = clampScore(v > 0 ? product / v : product)
    return {
      ...base, state: 'active',
      ifNeutral,
      withheld: Math.max(0, ifNeutral - arithmeticScore),
      note: '',
    }
  })

  return {
    rows, determinedBy, arithmeticScore, score, saturated,
    verdict: verdictFor(determinedBy, arithmeticScore, score, saturated, path),
  }
}

function verdictFor(d: Determination, arithmetic: number, score: number,
                    saturated: boolean, p: AttackPath): string {
  if (d === 'floor') {
    const why = p.hard_floor_applied
      ? 'a known-exploited vulnerability reaches crown-jewel data'
      : 'this path reaches data or administrative control unconditioned'
    return `The factors produce ${arithmetic}, but a severity floor raised this to ${score} `
      + `because ${why}. The floor decided this score, not the arithmetic.`
  }
  if (d === 'cap') {
    return `The factors produce ${arithmetic}, but this score is capped at ${score} because `
      + `a hop on the path is condition-guarded. The cap decided this score.`
  }
  if (saturated) {
    return `The factor product exceeded 1.0 and was clamped, so the score is ${score} and `
      + `no single factor moves it at this level.`
  }
  return `The factors multiply out to ${score}. "If neutral" below is the score this path `
    + `would carry if that one factor were 1.0 and the rest held — put it in the formula `
    + `and you get the same number back.`
}

// Deep-linkable panel + scope state — the URL is the single source of truth for
// "what am I looking at (scope) and what's open (a panel)". Every panel across the
// console reads its open-state from a `?param` via `useDeepLinkPanel`, so panels are
// shareable, bookmarkable and refresh-safe — and the product tour drives them simply
// by navigating to a URL. Sibling params are always preserved (a panel link never
// drops the user's `?scope=` or a filter). Panels default to `replace` history so the
// browser Back button isn't polluted by every open/close.
import { useCallback } from 'react'
import { useSearchParams } from 'react-router'
import type { AttackPath, IngestedVuln } from '../api/types'

/** The whitelist of URL params the panels + tour own. The tour cleans exactly these
 *  on exit so a user is never stranded in a spotlight-less open panel. `scope` is the
 *  view context and is deliberately NOT cleaned by the tour (it's the user's scope). */
export const PANEL_PARAMS = [
  'detail',            // Findings / Remediation  → FindingDetail (check_id)
  'path',              // Attack Paths            → PathDetail (pathId)
  'vuln',              // Vulnerabilities         → row accordion (lossless vulnKey)
  'upload',            // Vulnerabilities         → UploadModal (account scope only)
  'onboard',           // Cloud Accounts          → OnboardWizard (internal step stays local)
  'connector', 'tab',  // Settings                → ConnectorModal / active tab
  'framework', 'controls', // Compliance          → framework drill + failing-controls reveal
  'principal',         // Identity                → PrincipalCard expander
  'view',              // Inventory               → list | tree
] as const

export type PanelParam = (typeof PANEL_PARAMS)[number]

/**
 * Bind a single URL search param to panel open-state.
 * Returns `[value, set]` where `set(null)` deletes the param (closes the panel).
 * The functional updater preserves every OTHER param, so opening a panel never
 * clobbers scope or a sibling filter.
 */
export function useDeepLinkPanel(
  key: PanelParam,
  opts: { replace?: boolean } = {},
): readonly [string | null, (next: string | null) => void] {
  const [params, setParams] = useSearchParams()
  const value = params.get(key)
  const replace = opts.replace ?? true

  const set = useCallback(
    (next: string | null) => {
      setParams(
        (prev) => {
          const p = new URLSearchParams(prev)
          if (next == null || next === '') p.delete(key)
          else p.set(key, next)
          return p
        },
        { replace },
      )
    },
    [key, setParams, replace],
  )

  return [value, set] as const
}

// ── id codecs ────────────────────────────────────────────────────────────────
// AttackPath carries NO id (api/types.ts) — it is identified by its full node chain.
// entry→terminal alone is NOT unique (the engine emits multiple parallel routes to
// the same crown from the same entry), so the id keeps a readable entry__terminal
// prefix + a short deterministic hash of the whole node path to make it collision-free.

/** Last meaningful segment of a node id/ARN (`…:db:customers-db` → `customers-db`). */
export function lastSeg(node: string): string {
  if (node === 'internet') return 'internet'
  const afterColon = node.split(':').pop() ?? node
  return afterColon.split('/').pop() || afterColon
}

/** Short, stable, non-crypto hash (djb2 → base36) — deterministic across runs. */
export function shortHash(s: string): string {
  let h = 5381
  for (let i = 0; i < s.length; i++) h = ((h << 5) + h + s.charCodeAt(i)) >>> 0
  return h.toString(36)
}

/** Collision-free, URL-safe id for an attack path: readable prefix + node-chain hash. */
export function pathId(p: Pick<AttackPath, 'entry' | 'terminal' | 'nodes'>): string {
  return `${lastSeg(p.entry)}__${lastSeg(p.terminal)}__${shortHash(p.nodes.join('>'))}`
}

/** Match an attack path against a `?path=` value (resolve from the UNFILTERED list). */
export function matchPath(paths: AttackPath[], id: string | null): AttackPath | null {
  if (!id) return null
  return paths.find((p) => pathId(p) === id) ?? null
}

/** Lossless composite identity of an ingested vuln row: `${account}|${node_id}|${cve}`. */
export function vulnKey(v: Pick<IngestedVuln, 'account' | 'node_id' | 'cve'>): string {
  return `${v.account ?? ''}|${v.node_id}|${v.cve}`
}

/** Resolve a vuln row from a `?vuln=<vulnKey>` value — exact, unambiguous, org-scope-safe. */
export function matchVuln(rows: IngestedVuln[], key: string | null): IngestedVuln | null {
  if (!key) return null
  return rows.find((v) => vulnKey(v) === key) ?? null
}

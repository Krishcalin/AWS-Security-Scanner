// TS mirror of the cnapp_api response shapes (see cnapp_service.serialize_scanner /
// aggregate_overview / get_account_summary). Keep in lockstep with the backend.

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'
export type StatusCount = { PASS: number; FAIL: number; WARN: number; INFO: number }

export interface AttackPath {
  entry: string
  terminal: string
  terminal_kind: string // 'data' | 'admin' | ...
  nodes: string[]
  edges: [string, string, string?][]
  score: number
  severity: string
  conditioned: boolean
  vuln_pivot: boolean
  kev: boolean
  active_threat: boolean
  direct_public_crown: boolean
  hard_floor_applied: boolean
  factors: Record<string, number>
  driving_findings: string[]
  rationale: string
  account?: string
}

export interface ChokePoint {
  node_id: string
  node_kind: string
  label: string
  paths_severed: number
  total_paths: number
  weighted_score: number
  targets_fully_blocked: string[]
  is_true_choke: boolean
  remediation_hint: string
  account?: string
}

export interface ComplianceFramework {
  controls_total: number
  controls_passed: number
  controls_failed: number
  pass_rate: number
  failed_controls: string[]
}
export type ComplianceScorecard = Record<string, ComplianceFramework>

export interface GraphStats {
  nodes: number
  edges: number
  node_kinds: Record<string, number>
  edge_kinds: Record<string, number>
}

// networkx node-link graph (SecurityGraph.to_dict) — the /graph endpoint
export interface GNode { id: string; kind: string; [k: string]: unknown }
export interface GEdge { source: string; target: string; kind: string; [k: string]: unknown }
export interface GraphFull { directed: boolean; multigraph: boolean; nodes: GNode[]; edges: GEdge[] }

export interface OrgOverview {
  accounts_scanned: number
  summary: StatusCount
  org_posture_score: number
  critical_attack_paths: number
  crown_jewels_at_risk: number
  accounts: { account: string; region: string; posture_score: number | null; critical_paths: number }[]
  top_attack_paths: AttackPath[]
  top_choke_points: ChokePoint[]
}

export interface AccountSummary {
  account: string
  region: string
  posture_score: number
  posture_grade: string
  summary: StatusCount
  severity_counts: Record<Severity, number>
  compliance_scorecard: ComplianceScorecard
  graph: GraphStats | null
  attack_paths: AttackPath[]
  choke_points: ChokePoint[]
}

export interface Account {
  account_id: string
  alias: string
  org_id: string | null
  onboarding_method: string
  onboarding_status: string // pending | active | denied | disabled
  health: string // healthy | degraded | unauthorized | validating | unknown
  health_detail: string | null
  last_scan_at: number | null
  first_seen_at: number | null
  updated_at: number | null
  role_arn: string | null
  enabled_regions: string[]
  external_id_configured: boolean
  posture_score?: number | null
  posture_grade?: string | null
}

export interface Finding {
  status: string
  check_id: string
  section: string
  resource: string
  message: string
  severity: string
  compliance: Record<string, string>
  remediation_cmd: string
}

// ── onboarding / validation (write flow) ─────────────────────────────────────
export interface OnboardRequest { account_id: string; region?: string; method?: string; alias?: string }
export interface OnboardResult {
  account_id: string
  role_name: string
  external_id_ref: string
  reused: boolean
  cfn_launch_url: string
  cli: string
  external_id?: string // plaintext, shown once (sample synthesizes; live embeds it in the URL)
}
export interface ValidationCheck { name: string; ok: boolean; detail?: string }
export interface ValidationResult {
  expected_account_id: string
  observed_account_id: string | null
  role_arn: string
  region: string
  org_mode: boolean
  health: string // validating | healthy | degraded | unauthorized
  ok: boolean
  summary: string
  next_revalidation_epoch: number | null
  org_account_count: number | null
  checks: ValidationCheck[]
}

// A deduped, enriched entry from _build_finding_catalog (one per distinct FAIL/WARN check).
export interface FindingCatalogEntry {
  check_id: string
  section: string
  severity: string
  status: string
  compliance: Record<string, string>
  remediation_cmd: string
  risk: string
  impact: string
  steps: string[]
  affected: string[]
  count: number
  distinct: number
  account?: string
}

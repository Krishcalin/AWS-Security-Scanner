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

export interface ControlProvenance {
  control: string
  via_nist: string[]
  confidence: string // high | medium | low
  note: string
  sources: string[]
}
export interface ComplianceFramework {
  controls_total: number
  controls_passed: number
  controls_failed: number
  pass_rate: number
  failed_controls: string[]
  // additive, crosswalk-derived only (native frameworks never carry these):
  derived?: boolean
  via?: string
  confidence_mix?: { high: number; medium: number; low: number }
  min_confidence?: 'high' | 'medium' | 'low'
  control_provenance?: Record<string, ControlProvenance>
}
export type ComplianceScorecard = Record<string, ComplianceFramework>

// The framework catalog + crosswalk reference data (GET /compliance/frameworks + crosswalk.json).
export interface ComplianceFrameworkMeta {
  id: string
  name: string
  version: string
  authority: string
  family: string // ISO | cloud | federal | payments | healthcare | privacy | general | …
  native: boolean
  near_identity: boolean
  description: string
  catalog_size: number
  sources: string[]
}
export interface CrosswalkEdge {
  nist: string
  framework: string
  targets: string[]
  confidence: string
  note: string
  sources: string[]
}
export interface CrosswalkData {
  schema: string
  spine: string
  frameworks: ComplianceFrameworkMeta[]
  crosswalk: Record<string, Record<string, { targets: string[]; confidence: string; note: string }>>
}
export interface AccountCompliance {
  account?: string
  native: ComplianceScorecard
  derived: ComplianceScorecard
  crosswalk_version: string
  min_confidence?: string | null
}

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
  scan_schedule?: string | null   // off | hourly | daily | weekly | interval:<seconds>
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

// ── connector framework (Settings) — masked shapes; a secret is NEVER returned ──
export type ConnectorType = 'jira' | 'slack' | 'pagerduty' | 'splunk' | 'webhook'

// The masked connector (cnapp_connectors.ConnectorStore._mask_connector): the API
// exposes `secret_configured` (bool), never the secret ref or value.
export interface Connector {
  connector_id: string
  type: ConnectorType
  name: string
  enabled: boolean
  config: Record<string, unknown>
  secret_configured: boolean
  created_by: string | null
  last_test_at: number | null
  last_test_status: string | null // ok | failed
  last_test_detail: string | null
  created_at: number
  updated_at: number
}

export interface ConnectorRule {
  id: number
  connector_id: string
  name: string
  enabled: boolean
  priority: number
  min_severity: string
  severities: string[]
  sections: string[]
  check_globs: string[]
  not_check_globs: string[]
  account_globs: string[]
  on_attack_path: boolean | null
  statuses: string[]
  frameworks: string[]
  controls: string[]
  min_count: number
  min_distinct: number
  dedup_mode: string // notify_once | renotify
  throttle_seconds: number
  renotify_on_escalation: boolean
  notify_on_resolve: boolean
  stop_on_match: boolean
  connector_ids: string[]
  tags: string[]
  message_template: string | null
  severity_override: string | null
  created_by?: string
}

export interface TestResult {
  ok: boolean
  http_status: number
  detail: string
  error: string | null
  external_ref: string | null
}

export interface Delivery {
  id: number
  connector_id: string
  dedup_key: string
  rule_id: number | null
  account: string
  check_id: string | null
  state: string // open | resolved
  kind: string | null
  status: string // pending | sent | failed | skipped
  http_status: number | null
  error: string | null
  external_ref: string | null
  created_at: number
  sent_at: number | null
}

export interface PreviewHit {
  connector_id: string
  connector_name: string
  rule_id: number
  check_id: string
  account: string
  severity: string
}

// ── continuous scheduling + drift (CTEM) ─────────────────────────────────────
export interface TrendRow {
  scan_id: string
  ts_epoch: number
  ts_iso: string
  posture_score: number
  grade: string
  crit: number
  high: number
  med: number
  low: number
  total_open: number
  new_count: number
  resolved_count: number
  reopened_count: number
  suppressed_count: number
  delta: number | null
}
export interface DigestFinding { check_id: string; severity: string; resource: string; on_attack_path: boolean }
export interface DriftDigest {
  account: string
  scan_id: string
  ts_epoch: number
  ts_iso: string
  window_id: string
  posture_score: number | null
  posture_grade: string | null
  posture_delta: number | null
  counts: { new: number; resolved: number; reopened: number; mutated: number; still_open: number; suppressed: number }
  sev_delta: Record<string, number>
  material_change: boolean
  newly_exposed: DigestFinding[]
  newly_on_path: DigestFinding[]
  resolved_wins: DigestFinding[]
  reopened: DigestFinding[]
  sla: { open_over_sla: number | null; sla_days: number | null }
  mttr_days_mean: number | null
  compliance_delta: { framework: string; pass_rate_delta: number; newly_failed_controls: string[] }[] | null
  headline: string
  link: string
}
export interface DigestDelivery {
  id: number
  connector_id: string
  account: string
  scan_id: string
  window_id: string
  new_count: number
  resolved_count: number
  reopened_count: number
  posture_delta: number | null
  material: number
  status: string
  http_status: number | null
  error: string | null
  external_ref: string | null
  created_at: number
  sent_at: number | null
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

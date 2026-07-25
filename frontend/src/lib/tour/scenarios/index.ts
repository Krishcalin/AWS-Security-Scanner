import type { TourScenario } from '../types'

// Canned scenarios that replay over the REAL console using the offline sample data.
// Every id below is verified against frontend/public/sample/*.json by
// scenarios.test.ts, so a drifted fixture fails the test rather than the tour.
const VILLAIN = '123456789012'                       // prod-payments, grade F
const FLAGSHIP_PATH = 'internet__customers-db__1yvkq01'   // pathId of the score-100 KEV path
// lossless vulnKey (account|node_id|cve) of the reachable Log4Shell on the payments image
const LOG4SHELL_VULN = '123456789012|123456789012.dkr.ecr.us-east-1.amazonaws.com/payments-api@sha256:a1b2c3|CVE-2021-44228'

// ── S1 · flagship: trace a critical attack path ───────────────────────────────
const attackPath101: TourScenario = {
  id: 'attack-path-101',
  title: 'Trace a critical attack path',
  persona: 'Security lead',
  summary: 'From an F-grade org to the one internet-exposed, weaponized path that reaches the customer database — and the single fix that severs it.',
  estMinutes: 2,
  steps: [
    { id: 'intro', route: '/', scope: 'org', title: 'Ranked by attack path, not check count',
      body: 'OverWatch scores toxic combinations end-to-end. Let’s trace the worst one in this org.' },
    { id: 'posture', route: '/', scope: 'org', anchor: 'org-grade', placement: 'right',
      title: 'Organization posture: F',
      body: 'Grade F, driven by 3 critical attack paths across 3 scanned accounts.' },
    { id: 'open-paths', route: '/', scope: 'org', anchor: 'kpi-critical-paths', placement: 'bottom',
      mode: { kind: 'interactive', hint: 'Click the “Critical attack paths” tile.' },
      title: 'Your turn', body: 'Open the ranked attack-path worklist.' },
    { id: 'worklist', route: '/attack-paths', scope: VILLAIN, anchor: 'path-card-0', placement: 'right',
      title: 'The worklist, scoped to prod-payments',
      body: 'The top path scores 100 — internet-exposed, weaponized (KEV), and it reaches crown-jewel data.' },
    { id: 'graph', route: '/attack-paths', scope: VILLAIN, params: { path: FLAGSHIP_PATH },
      anchor: 'path-graph', waitFor: 'path-graph', placement: 'left',
      title: 'Internet → the customer database',
      body: 'The toxic combination: internet → ALB → EC2 → instance role → the customers-db. Score 100, KEV + active threat.' },
    { id: 'why', route: '/attack-paths', scope: VILLAIN, params: { path: FLAGSHIP_PATH },
      anchor: 'path-why-score', waitFor: 'path-why-score', placement: 'left',
      title: 'Why it scores 100',
      body: 'A gated-multiplicative score: exposure × exploitability × impact × reachability × threat boost. Every factor is present, so nothing collapses it.' },
    { id: 'sever', route: '/attack-paths', scope: VILLAIN, params: { path: FLAGSHIP_PATH },
      anchor: 'path-sever', waitFor: 'path-sever', placement: 'left',
      title: 'Sever it with one cut',
      body: 'Fix prod-api-alb — a single choke point severs 2 of the 3 critical paths.' },
    { id: 'choke', route: '/remediation', scope: VILLAIN, anchor: 'choke-card-0', placement: 'bottom',
      title: 'The highest-leverage fix, ranked first',
      body: 'Remediation leads with the choke point, not the long findings list. Fix leverage first.' },
    { id: 'outro', route: '/remediation', scope: VILLAIN,
      title: 'That’s the core loop',
      body: 'Explore another account, or open the copy-paste fix for this choke point. You drove a real console — no screenshots.' },
  ],
}

// ── S2 · reachability beats CVSS ──────────────────────────────────────────────
const reachability: TourScenario = {
  id: 'reachability',
  title: 'Reachability beats CVSS',
  persona: 'Vulnerability manager',
  summary: 'Why a reachable Log4Shell outranks a higher-CVSS CVE that can’t be reached.',
  estMinutes: 2,
  steps: [
    { id: 'facets', route: '/vulnerabilities', scope: VILLAIN, anchor: 'vuln-facets', placement: 'bottom',
      title: 'Prioritize by reachability',
      body: 'External-scanner CVEs (SARIF / CycloneDX / SPDX), ranked by whether they’re actually reachable on an attack path — not by raw CVSS.' },
    { id: 'log4shell', route: '/vulnerabilities', scope: VILLAIN, params: { vuln: LOG4SHELL_VULN },
      anchor: 'vuln-row-0', waitFor: 'vuln-row-0', placement: 'bottom',
      title: 'Log4Shell — priority 94',
      body: 'CVE-2021-44228 is reachable, on the attack path, and reaches the crown datastore, so it tops the queue.' },
    { id: 'metric', route: '/vulnerabilities', scope: VILLAIN, anchor: 'vuln-stat-reachable', placement: 'bottom',
      title: 'Reachable is the metric',
      body: 'This count — reachable, on an attack path — is the queue that matters. A CVSS-9.8 that nothing can reach stays out of it.' },
  ],
}

// ── S3 · triage & route a finding ─────────────────────────────────────────────
const triageTicket: TourScenario = {
  id: 'triage-ticket',
  title: 'Triage & route a finding',
  persona: 'SecOps analyst',
  summary: 'Open a critical finding, read the fix, and route it to Slack + Jira.',
  estMinutes: 2,
  steps: [
    { id: 'queue', route: '/findings', scope: VILLAIN, anchor: 'findings-tabs', placement: 'bottom',
      title: 'Every finding, one queue',
      body: 'Misconfig, vulnerability, and data findings deduped into a single ranked worklist, with attack-path membership flagged.' },
    { id: 'detail', route: '/findings', scope: VILLAIN, params: { detail: 'IAM-02' },
      anchor: 'finding-detail-head', waitFor: 'finding-detail-head', placement: 'left',
      title: 'IAM-02 · root-user access keys',
      body: 'A leaked root key is an MFA-proof account takeover. Risk, business impact, step-by-step remediation, and a copyable one-line CLI — all here.' },
    { id: 'ticket', route: '/findings', scope: VILLAIN, params: { detail: 'IAM-02' },
      anchor: 'finding-raise-ticket', waitFor: 'finding-raise-ticket', placement: 'top',
      mode: { kind: 'interactive', hint: 'Click “Raise ticket”.' },
      title: 'Your turn', body: 'Open the ticket form — priority is mapped from the finding’s severity.' },
    { id: 'slack', route: '/settings', scope: 'org', anchor: 'connector-row-0', waitFor: 'connector-row-0', placement: 'bottom',
      title: 'Route it to Slack',
      body: 'Connectors fan findings out to your tools. Slack #cloudsec is live — High+ findings post there automatically after each scan.' },
    { id: 'more', route: '/settings', scope: 'org', anchor: 'add-connector', placement: 'bottom',
      title: 'Jira, PagerDuty, Splunk, webhooks',
      body: 'Each connector carries severity + attack-path routing rules, with a dry-run preview before anything sends.' },
  ],
}

// ── S4 · keyless onboarding ───────────────────────────────────────────────────
const onboarding: TourScenario = {
  id: 'onboarding',
  title: 'Keyless account onboarding',
  persona: 'Platform engineer',
  summary: 'Connect an AWS account with a read-only role — never an access key.',
  estMinutes: 2,
  steps: [
    { id: 'accounts', route: '/accounts', scope: 'org',
      title: 'Connect an account — keyless',
      body: '3 active, 1 pending, 1 unauthorized. OverWatch assumes a read-only role you deploy; it never uses static access keys.' },
    { id: 'add', route: '/accounts', scope: 'org', anchor: 'add-account', placement: 'bottom',
      mode: { kind: 'interactive', hint: 'Click “Add account”.' },
      title: 'Your turn', body: 'Open the onboarding wizard.' },
    { id: 'rail', route: '/accounts', scope: 'org', params: { onboard: '1' },
      anchor: 'wizard-rail', waitFor: 'wizard-rail', placement: 'right',
      title: 'Five steps',
      body: 'Scope → identify → deploy the read-only role → validate → first scan. A single CloudFormation stack, or an Org StackSet that auto-enrolls members.' },
    { id: 'role', route: '/accounts', scope: 'org', params: { onboard: '1' },
      anchor: 'wizard-rail', waitFor: 'wizard-rail', placement: 'right',
      title: 'A read-only role, no keys',
      body: 'The stack mints a SecurityAudit + ViewOnlyAccess role bound by a server-minted ExternalId — read-only, never ReadOnlyAccess, no write or data-plane grants.' },
  ],
}

// ── S5 · one scan, every framework ────────────────────────────────────────────
const complianceCrosswalk: TourScenario = {
  id: 'compliance-crosswalk',
  title: 'One scan, every framework',
  persona: 'GRC / auditor',
  summary: 'A failing SOC 2 control, then 34 more frameworks derived from one NIST spine.',
  estMinutes: 2,
  steps: [
    { id: 'soc2', route: '/compliance', scope: VILLAIN, anchor: 'framework-SOC2', waitFor: 'framework-SOC2', placement: 'bottom',
      title: 'SOC 2 on prod-payments',
      body: '33% pass — 3 of 9 controls. Directly tested against the account’s configuration.' },
    { id: 'control', route: '/compliance', scope: VILLAIN, params: { framework: 'SOC2', controls: '1' },
      anchor: 'ctrl-CC6.6', waitFor: 'ctrl-CC6.6', placement: 'top',
      title: 'The failing control',
      body: 'CC6.6 — logical access controls. The same findings driving the attack path roll up to this control.' },
    { id: 'crosswalk', route: '/compliance', scope: VILLAIN,
      title: '34 more frameworks, one scan',
      body: 'Every framework beyond the directly-tested five is derived from the NIST 800-53 control each check already carries — ISO 27001, PCI-DSS, HIPAA, and more.' },
  ],
}

export const SCENARIOS: TourScenario[] = [
  attackPath101, reachability, triageTicket, onboarding, complianceCrosswalk,
]

export function getScenario(id: string): TourScenario | undefined {
  return SCENARIOS.find((s) => s.id === id)
}

# OverWatch - AI-CNAPP Frontier Roadmap

> Converted from the published artifact
> <https://claude.ai/code/artifact/534b8c60-bc1c-4de7-be70-a7bf030eb5f0>
> ("OverWatch Frontier Roadmap"). The artifact remains the source of record for
> presentation; this file exists so the plan is reviewable in-repo, diffable, and
> available offline alongside the code it describes.
>
> **Delivery status lives in `CHANGELOG.md`, not here.** Where a premise in this
> roadmap was checked against primary sources during implementation and found
> wrong, the correction is recorded in the commit that made it. This file is kept
> as the plan *as written*, so that what was proposed stays legible next to what
> was actually built.

OverWatch Frontier Roadmap

Build plan · v1.0 · 24 Aug 2026

AI-SPM, agentic posture, zero-trust scoring and the regulatory clock — sequenced by leverage, with every slice marked in-charter, substitute, or a decision only you can make.

## Three corrections, before any slice

The research began by checking the brief against the code and found the brief wrong twice. Both corrections were independently verified in this repository, and both reclassify work.

✓ verified in repo

### The charter is config-vs-data, not read-vs-write

We have been saying “read-only.” The contract every customer actually applies is stricter and different in kind:

intentionally NOT ReadOnlyAccess — that grants workload **DATA** reads (`s3:GetObject`, `dynamodb:GetItem`, `sqs:ReceiveMessage`) which would violate the **read-only-of-CONFIG** contract.

It is pinned by two tests, stated in the marketplace listing, and shown in the onboarding wizard. It is a commercial representation. Four capabilities the research first called “in-charter” are data-plane reads under it.

✓ verified in repo

### The zero-telemetry tripwire is blind to ingest

Every assertion in `test_zero_telemetry.py` is about *egress* — telemetry SDKs, network primitives, shell-out, hardcoded hosts, SSRF guards, registry purity. **Not one covers what we ingest.**

So adding prompt-text reading to the graph passes the whole file green — and the connector plane then launders it out through customer-configured egress, wearing our name. A ~30-line Section F is the first slice in the plan, before any ingest work at all.

judgement call

### “AIDR” is a rebrand, and naming it costs a quarter

The GA proof point is three GuardDuty finding types, all defaulting to severity **Low**. Call it a pillar and it earns a module, a nav entry, a dashboard, a doc page, a test suite and three months.

Call it what it is — a detection-content pack on `aws_cdr.py` plus a severity join — and it is one sprint. There is no `/aidr` route in this roadmap.

> GuardDuty rates those findings Low because it has no idea what the identity can reach. We do. That is a severity function, not a product pillar. the one uncopyable sentence in the log-derived AIDR story

## The defect that floors your posture score at zero

Phase 0 exists because the AI pillar today is demoed empty, scanned wrong, and scored at zero. I verified the worst of the seven independently — all three legs hold.

| Leg | Where | What is true |
|---|---|---|
| **DATA runs per region** | aws_live_scanner.py:1654 | `GLOBAL_SECTIONS` holds only IAM, S3, ROUTE53, CLOUDFRONT, IAMPRIVESC, CORRELATE, CLOUDWATCH. `DATA` is absent, so AI collection re-runs in every region. |
| **The stash never resets** | aws_live_scanner.py:1772 | `_aispm_resources` is initialised once in `__init__`, appended at three sites, read at two — and cleared nowhere. It accumulates across regions. |
| **Every duplicate is charged** | compute_risk_score | `penalty += SEVERITY_WEIGHTS[…]` per FAIL, CRITICAL = 15, clamped at 0. |

In a 17-region account, one critical AI finding is re-emitted seventeen times, subtracts 255, and takes the **entire posture grade — not just the AI section — to zero**. `BDR-05` has the same shape. The fix is a one-hour reset in the region loop, and the regression test that must never come back is a synthetic scan asserting an identical score at 1 region and at 17.

Six more sit alongside it: ten `BDR-`/`AGT-` checks that penalise the score while mapping to no framework and rendering a blank detail panel; knowledge-base enumeration nested inside the per-agent loop behind a zero-agent early return, so a **RAG-only account is completely invisible**; and an exception handler that reports `AccessDenied` as *“Bedrock may not be available in this region.”*

## What unlocks what

Ordered by leverage, not by topic. Cheap-because-the-machinery-exists goes early; anything that needs a new permission waits behind the ledger that makes the ask sellable.

**0.1** ingest tripwire ─────────► everything that ingests (1.3, 2.6, 3.5, 4.6, 4.7) **0.2** P0 defect block ────────► every AI demo, every AI score **0.3** inbound graph edge ─────► AIPATH-01 becomes a scored path ──► *3.1 toxic flow* **0.4** pivot_effective ────────► AISPM-01 stops over-reporting ────► *3.1 honest scoring* **0.5** console + fixtures ─────► the demonstration of everything else **1.1** permission ledger ──────► 1.2 IAM policy ──► 2.1‥2.5, 4.2, 4.3 (all AI reads) **1.3** CDR-AI rule pack ───────► independent — ships under today's role **1.5** MCP server ─────────────► independent — cheapest high-leverage item **2.1** guardrail grading ──────► 3.1 gate multiplier · 1.4 coverage feed **2.2** AgentCore inventory ────► 2.3, 2.4, 2.5, 3.1, 3.3, 3.4, 4.7 **2.7** AI frameworks ──────────► 4.5 evidence pack **3.1** toxic flow ─────────────► *the flagship — the honest answer to "do you red team?"*

## The phases

in-charter ships under the config-read contract as it stands · boundary crosses the config/data line and must take the FLOW-00 shape · S ≤1 week · M 2–4 weeks · L 5–8 weeks

## Phase 0 - Truth & Tripwire

*3 weeks · 1 eng + 0.5 FE · claims nothing new*

Everything here fixes something already shipped and already wrong. No new pillar, no new permission, no new marketing — because the first thing built after it needs a guardrail that works.

| # | Slice | Effort | Verdict |
|---|---|---|---|
| 0.1 | Ingest-side tripwire — `test_zero_telemetry.py` §F field allowlist | S | in-charter |
| 0.2 | The P0 defect block — seven fixes, each verified against the code | S | in-charter |
| 0.3 | Inbound `EXPOSED_TO` edge + crown-marking order | S | in-charter |
| 0.4 | `pivot_effective` routing + epistemic class on every finding | S | in-charter |
| 0.5 | Console entries, AI fixtures, copilot vocabulary | S | in-charter |
| 0.6 | Global lockstep test, replacing per-phase allowlists | S | in-charter |

## Phase 1 - Permission Truth & the Free Detections

*4 weeks · two of three ship under today's role*

The permission ledger turns a policy expansion into a sellable ask: for every check we could not run, name the exact action you withheld. Two detections need no new grant at all.

| # | Slice | Effort | Verdict |
|---|---|---|---|
| 1.1 | `aws_perm_ledger.py` — per-action ledger with forfeit accounting + coverage manifest | M | in-charter |
| 1.2 | The additive read-only AI IAM policy (~25 actions) | S | decision D1 |
| 1.3 | LLMjacking + AI control-tampering rule pack — *zero new permissions* | M | in-charter |
| 1.4 | Guardrail coverage feed — no sibling dependency, deliberately | S | in-charter |
| 1.5 | `cnapp_mcp.py` — local read-only MCP server + skills | M | decision D6 |

## Phase 2 - Grade What Everyone Counts

*6 weeks · differentiation starts here*

Every vendor checks a guardrail as a boolean — “has one / doesn’t.” Grading its strength, and deriving from IAM text alone whether it is actually *mandatory*, is a claim nobody else is making.

| # | Slice | Effort | Verdict |
|---|---|---|---|
| 2.1 | `aws_aiguard.py` — guardrail grading + IAM-bound enforcement test | M | in-charter |
| 2.2 | `aws_agentcore.py` — AgentCore inventory, all agent identities | M | in-charter |
| 2.3 | Gateway authorization posture (`authorizerType: NONE` and friends) | S | in-charter |
| 2.4 | Excessive agency / human-in-the-loop bypass enumeration | M | in-charter |
| 2.5 | Agent credential exposure | S | in-charter |
| 2.6 | GuardDuty AI Protection ingest + identity re-ranking | S | in-charter |
| 2.7 | NIST AI RMF · ISO 42001 · MITRE ATLAS into the crosswalk spine | M | in-charter |

## Phase 3 - Toxic Flow — the flagship

*6–8 weeks · the in-charter answer to “do you red team?”*

Assume prompt injection lands, because it does — then compute what it reaches from the agent’s tools, role and data reach. Capability, not occurrence; labelled as an assumption, never as an incident. Structurally it is attack-path analysis pointed at an agent.

| # | Slice | Effort | Verdict |
|---|---|---|---|
| 3.1 | `aws_toxicflow.py` — the flagship computation | L | in-charter |
| 3.2 | Tool-description poisoning scan — *vendors patterns, does not author them* | S | in-charter |
| 3.3 | MCP server provenance — rogue and rug-pull detection | M | in-charter |
| 3.4 | Memory-poisoning exposure, config half only | S | in-charter |
| 3.5 | `aws_ingest_pentest.py` — garak / PyRIT / pen-test result ingest onto the graph | M | in-charter |

## Phase 4 - Depth, Data Plane & the Boundary Crossings

*6 weeks · where “in-charter as-is” stops being true*

Everything that crosses the config/data line ships in the **FLOW-00 shape** — a separate named policy, off by default, resource-scoped, failing open to a numbered note — or it does not ship. That pattern already exists for the VPC flow-log overlay; nobody needs to invent it.

| # | Slice | Effort | Verdict |
|---|---|---|---|
| 4.1 | SageMaker depth to Security Hub parity (25 controls) | M | in-charter |
| 4.2 | RAG / vector-store data plane — `s3vectors`, `aoss` | M | boundary |
| 4.3 | Model-invocation logging depth + data-event selectors | M | boundary |
| 4.4 | Shadow AI, in-account half — one CloudTrail query, one flow-log query | S | in-charter |
| 4.5 | AI compliance evidence pack | M | in-charter |
| 4.6 | Model & agent artifact scanning (pickle / deserialization) | M | crossing · D2 |
| 4.7 | `aws_aidr.py` — sibling Guardrail event ingest | M | blocked · D7 |

## Phase 5 - Zero Trust, Shown With Its Work

*the differentiator is the evidence, not the label*

“Zero Trust CNAPP” is not a build and no analyst market exists by that name. What is real is scoring an AWS estate against CISA ZTMM v2 and NIST 800-207 *from configuration alone*, and showing the evidence behind every pillar score.

| # | Slice | Effort | Verdict |
|---|---|---|---|
| 5.1 | `aws_ztmm.py` — CISA ZTMM v2 / NIST 800-207 per-function scoring | L | in-charter |
| 5.2 | `aws_perimeter.py` — data-perimeter posture scoring | M | in-charter |
| 5.3 | Nitro / TLS traffic-encryption evidence | S | in-charter |
| 5.4 | Segmentation recommendation derived from attack paths | M | in-charter |

## Phase R - The regulatory clock — its own lane, its own owner

*runs parallel · must not be eaten by the AI conversation*

Two 2026 deadlines point at our exact buyer, and the machinery for the first is already shipped. **CRA reporting starts 11 September 2026 — eighteen days from this document** — and binding machine-readable SBOM is `aws_ingest.py` + `aws_sbom_diff.py` + `aws_vex.py`. EO 14412’s FAR proposed rule lands around 19 December 2026.

| # | Slice | Effort | Verdict |
|---|---|---|---|
| R1 | CRA one-pager: map existing SBOM machinery to Annex I Part II(1) + the 24/72/14 clock | S | already built |
| R2 | CBOM — reverse the xBOM skip *for cryptography only* | M | decision D3 |

## Quick wins — days, not months

Ship these in the first two weeks regardless of how the phases are resourced. Every one is verified in the code today.

| # | Win | Where | Time |
|---|---|---|---|
| 1 | **Reset `_aispm_resources` per region** — un-floors the posture score from 0 | aws_live_scanner.py:1772 | 1 hr |
| 2 | Fill the three metadata maps for the 10 `BDR`/`AGT` orphans — lights the console panel, the report and the copilot in one move | 3 maps | ½ day |
| 3 | Add AI vocabulary to `_QUERY_ALLOW` — copilot stops abstaining on every AI question | aws_copilot.py:34 | 10 min |
| 4 | AI entries in `nodes.ts` + `QUERY_KINDS` — AI nodes stop rendering as generic circles | lib/nodes.ts:8 | 1 hr |
| 5 | Split BDR-01’s handler — stop reporting `AccessDenied` as “not available in this region” | aws_live_scanner.py:5099 | 1 hr |
| 6 | **Hoist KB enumeration** out of the per-agent loop — a RAG-only account stops being invisible | :5266,:5271,:5341 | 2 hr |
| 7 | Prefix-authoritative dashboard routing — AISPM findings stop rendering on two pages | lib/dashboards.ts:53 | 30 min |
| 8 | Correct the README prompt-injection claim | README.md:402 | 5 min |
| 9 | Global lockstep test replacing the per-phase allowlists | test_live_scanner.py:208 | ½ day |
| 10 | **The one inbound `EXPOSED_TO` edge** — “show me the AI attack path” becomes answerable | aws_live_scanner.py:10300 | 1 day |
| 11 | AI fixtures in `public/sample/**` — the AI dashboard stops rendering empty in every demo | 52 fixtures | 1 day |
| 12 | CRA one-pager — the SBOM machinery is already built; only the mapping is missing | docs/ + crosswalk | 1 day |

## The decisions only you can make

Choices with consequences, not recommendations dressed as facts.

### D1 · The IAM policy label

Publish the ~25-action additive read-only AI policy and stop claiming “ViewOnlyAccess exactly”, or keep the label and accept that the AI pillar silently returns AccessDenied-degraded results on every account using the documented role.

**There is no third option — the code already crossed this line.**

> **My read:** the promise that must survive is *read-only-of-config*, and the additive policy keeps it intact. The per-action ledger (1.1) is what makes the ask sellable rather than a policy expansion.

### D2 · Does customer prompt text ever enter the graph?

Nothing in the charter forbids it — self-hosted, nothing leaves — but it is a serious data-handling escalation for a product sold on zero-telemetry, and it crosses the config/data line the CloudFormation names explicitly. Today a sovereign buyer’s security review is one line. Add this and it becomes a data-processing agreement.

> **Recommendation:** a one-day approval traded for a six-week one, to ship a capability the sibling product owns better. If yes: opt-in per workspace, FLOW-00 shape only, hashed by default, and **the tripwire ships first**.

### D3 · Reverse the xBOM skip for CBOM only

EO 14412 has dated deadlines, a FAR rule in flight, and a buyer segment identical to our wedge. Wiz shipped CBOM at FedRAMP High a month before the EO.

> **Recommendation:** reverse for cryptography only. AIBOM / HBOM / QBOM stay skipped — no regulator mandates them.

### D4 · Do we ever cross read-only for AI red teaming?

Answer it in writing now, because it will be asked in every bake-off. Beyond the charter: active probing spends the customer’s inference bill, is **indistinguishable from LLMjacking in their own CloudTrail**, can trip GuardDuty’s own detections, and the engine is Apache-licensed garak — so building it buys a scheduler and a report.

> **Recommended answer: no.** The answer is toxic flow + graph-proven exploitability + pen-test ingest, not a fenced binary.

### D6 · The MCP client boundary

The *server* is inside the boundary; the *client* — Claude Code, Cursor — is not. A sovereign buyer’s engineer wires it to a cloud LLM and defeats zero-telemetry themselves, carrying our name.

> **Recommendation:** ship with the warning inside the tool descriptions and a documented local-model path, or don’t ship. There is no version where we control the client.

### D7 · The Guardrail sibling dependency — a portfolio decision

Our AIDR ingest plan assumes the sibling Guardrail exists and emits events. It is **2,524 LOC, 36 tests, 11 commits, no publish workflow, no Dockerfile, no console entry point — it runs from a clone.** Meanwhile prompt firewalling is commoditising: llm-guard is free, and AWS, Azure and Cloudflare ship native guardrails inside subscriptions the customer already pays for.

> **Recommendation:** do not model roadmap dependencies on it as if it were a hardened platform. Decoupled, the AI-detection story rests on 1.3 and 2.6 — both of which stand alone.

## The skip list

As valuable as the build list. A roadmap that lists everything sequences nothing.

### Charter-breaking — decline on all eight

| Item | Why it dies |
|---|---|
| Inline prompt firewall / LLM gateway | Terminates and can mutate production traffic — a failure mode is a customer outage. Sibling’s job, and commoditising to zero. |
| Active AI red teaming against live endpoints | `InvokeModel` is not List/Get/Describe. Indistinguishable from LLMjacking in the customer’s own CloudTrail. |
| Agentic red teaming (tool-executing agents) | Causes real writes *through the customer’s agent* by construction. Highest-consequence item on the list. |
| eBPF / LSM enforcement, block mode, admission webhooks | Loses the air-gapped estate — the exact wedge — and moves pricing to per-workload. **But it now needs a stated answer, not silence.** Concede out loud: no block mode, no admission gate, no sub-second kill. If a buyer’s requirement is prevention, we are not the product. |
| Agent runtime sandboxing | Not merely an agent — it is operating the customer’s agent runtime. Keep the narrow fragment; never imply containment. |
| Native auto-remediation APPLY / segmentation writes | A wrong security-group write is a production outage — exactly the liability the sovereign buyer pays us to avoid. |
| Per-tool-call authorization enforcement | Sidecar or SDK. *But the in-charter idea worth stealing:* sequence-aware authorization — the transitive permission union across an agent-to-agent delegation path, computed and never enforced. |
| Employee / browser AI usage enforcement | Breaks agentless, different buyer. The reachable fragment folds into ZTMM scoring. |

### Refused on honesty grounds, regardless of charter

| Item | Why |
|---|---|
| **EU AI Act risk-tier classification** “the moment a model is discovered” | Tier is a function of *purpose* and deployment context, not of anything visible in a cloud API response. At best it classifies from a tag the customer typed. **Declining a claim a competitor makes falsely is a differentiator with exactly our buyer.** |
| Guardrail efficacy testing | Needs an attacker path *and* an inline enforcement point. For the OSS stack the loop does not exist at all — garak writes JSONL and stops. Report configuration as a gate multiplier; never claim efficacy we have not measured. |
| Autonomous triage that auto-closes findings | Highest-risk framing with no published confirmation mechanism. The opposite of the copilot’s extractive, abstaining instinct — which should be marketed as a deliberate safety choice. |
| US state AI law modules | The landscape is *contracting*: Colorado SB 24-205 repealed May 2026; Texas TRAIGA is intent-based and generates no posture evidence. Track, don’t build. |
| “Shadow AI” and “AIDR” as nav items | The half buyers mean is unreachable; the half that is reachable is two queries. A saved control, not a pillar. |

## The positioning line

> Every CNAPP will tell you an AI agent has no guardrail. OverWatch tells you what happens next — and, for every check it could not run, exactly which permission you withheld. primary · true after Phase 1

Three claims that become true after Phase 3, each with the slice that earns it:

- **“We compute the blast radius of the identity your model runs as”** — boundary-corrected and fused onto a scored attack path. 0.3 + 0.4 + 2.2

- **“We grade your guardrail instead of counting it”** — and tell you from IAM text alone whether any guardrail is actually mandatory. 2.1

- **“We assume prompt injection lands, because it does”** — and show what it reaches, labelled as an assumption, never as an incident. 3.1

And the two *non*-claims, said out loud in the UI, because saying them is the differentiator:

- **“We do not read your prompts.”** Prompt-layer inspection requires a hop in your data path that this product deliberately does not have.

- **“We did not run a test.”** A toxic flow proves capability, not occurrence. Hand us your garak or pen-test results and we will place them on the graph.

> Our scan tells you what it did not look at. the sentence that beats every RFP answer in the market

**How this was produced.** Thirteen agents across three phases — eight parallel external capability sweeps (AccuKnox platform, AI-SPM, AIDR, AI red teaming, zero-trust CNAPP, the 2026 non-AI frontier, regulatory drivers, agentic AI), two internal audits that read this repository rather than trusting the brief, then a gap matrix, an adversarial critic whose job was to stop us building the wrong thing, and a synthesiser. Zero agent errors. 94 capabilities catalogued across ~280 fetched sources.

A separate five-agent sweep covered Orca Security in parallel and is not summarised here. Its load-bearing findings: Orca’s SideScanning patents were **invalidated by the PTAB in December 2025** and the Wiz litigation dismissed with prejudice in January 2026; their scanner reads customer blocks *inside Orca’s own AWS account* via share-and-attach, which AWS documents and their IAM policy corroborates; and their role holds snapshot create/copy/delete plus `kms:PutKeyPolicy`, so “read-only” is theirs to defend, not ours.

Claims in this document that describe OverWatch’s own code were verified against the repository at v2.35.0 before being repeated — including the two corrections to the brief and all three legs of the score-flooring defect.

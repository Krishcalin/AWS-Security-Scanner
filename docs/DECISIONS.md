# OverWatch — product decisions

The decisions in the AI-CNAPP roadmap that were flagged as *"the decisions only you can
make"*, recorded here with their answers, their reasoning, and — where one exists — the
test that keeps the answer true.

**Why this file exists.** A decision that lives only in a conversation gets re-litigated,
and worse, gets contradicted by code that nobody checked against it. D4 said it plainly:
*answer it in writing now, because it will be asked in every bake-off.* Several of these
answers are also **sales artifacts** — a sovereign buyer's security review asks exactly
these questions, and "we decided that deliberately, here is the test that enforces it" is
a different answer from "we haven't done that yet."

Where a decision has a testable consequence, `tests/test_decisions.py` enforces it. Prose
without a guard drifts; that is the whole lesson of this codebase's Phase 0.

> There is no D5. The roadmap numbers D1–D4, D6, D7.

---

## Status at a glance

| | Decision | Answer | Enforced by |
|---|---|---|---|
| **D1** | The IAM policy label | **Taken** — publish the additive read-only policy | `tests/test_perm_ledger.py` |
| **D2** | Does customer prompt text enter the graph? | **No** | Section F, `tests/test_zero_telemetry.py` |
| **D3** | Reverse the xBOM skip for CBOM only | **Built** — `--cbom` | `tests/test_cbom.py` |
| **D4** | Do we cross read-only for AI red teaming? | **Out of scope** | `tests/test_decisions.py` |
| **D6** | The MCP client boundary | **Taken** — ship it enforced | Section G, `tests/test_mcp.py` |
| **D7** | The Guardrail sibling dependency | **Decoupled** | `tests/test_decisions.py` |
| **D11** | Does auto-fix end the read-only guarantee? | **Open** — CISO | the absence of a remediation role |
| **D12** | Widen the egress allowlist for SIEM forwarding? | **Open** — CISO | Section A, `tests/test_zero_telemetry.py` |
| **D13** | Build the inbound connectors vendor-neutral? | **Open** — architecture board | *(recommendation only)* |

None of these decisions left the product in a broken or dishonest state while they were
open. D2 and D4 were questions about whether to *add* something, and the answer to each
preserves what the product already does. D3 was the one where adding was the right
answer, and it was built rather than deferred.

**D11–D13 arrived with the Phase II SRS (`OW2-SRS-001 v0.1`) and are still open.** The
same property holds: the product is not in a dishonest state while they are. Each is a
question about whether to *add* a capability, and in each case not-yet-added is the
conservative answer — the read-only guarantee holds, no new egress path exists, and no
connector has been built against an unverified vendor contract. They are recorded here
so they are answered deliberately rather than by a commit.

---

## D1 · The IAM policy label — **TAKEN**

*Publish the additive read-only AI policy and stop claiming "ViewOnlyAccess exactly", or
keep the label and accept that the AI pillar silently returns AccessDenied-degraded
results on every account using the documented role.*

**Answer: publish the additive policy.** Taken in slice 1.2 and extended in 2.1 and 2.2.

The promise that had to survive is **read-only-of-CONFIG**, and the additive policy keeps
it intact — every action in it is `Get`/`List`/`Describe`-shaped, and a test asserts that.
What makes the ask sellable rather than a policy expansion is the per-action ledger
(`aws_perm_ledger.py`): for each action, what it buys, and which findings you forfeit by
declining it.

The gap has grown three times since — 3 → 4 → 13 → 15 actions — and each growth was
computed from the policy documents rather than estimated. That is the point of the ledger:
the original estimate for this decision was "~25 actions", and the measured answer was
three.

---

## D2 · Does customer prompt text ever enter the graph? — **NO**

*Nothing in the charter forbids it — self-hosted, nothing leaves — but it is a serious
data-handling escalation for a product sold on zero-telemetry, and it crosses the
config/data line the CloudFormation names explicitly.*

**Answer: no.** OverWatch does not read prompt or completion content, and this is now a
deliberate answer rather than a feature we had not got to.

**Why.** The wedge is the sovereign, air-gapped and regulated estate, and for that buyer
the current security review is *one line*: the scanner reads configuration, never workload
data, and the CloudFormation says so explicitly. Reading prompt text turns that one line
into a data-processing agreement — a one-day approval traded for a six-week one. The
capability would also duplicate what a runtime guardrail owns better, and the detection
value we actually want (LLMjacking, control tampering) is already delivered by `AITHR-01`
and `AITHR-02` from **CloudTrail management events alone**, with no content and no new
permission.

**What enforces it.** Section F of `tests/test_zero_telemetry.py` — added in slice 0.1
precisely because the tripwire proved we did not *send* data while saying nothing about
what we *absorb*. It rejects any ingest module that reads conversation-content keys, and
it is proven to fire against a deliberately poisoned fixture.

**Reversing this is possible and the conditions are known.** If it is ever reversed:
opt-in per workspace, `FLOW-00` shape only, hashed by default, and **the tripwire ships
before the capability**, not after.

---

## D3 · Reverse the xBOM skip for CBOM only — **BUILT**

*EO 14412 has dated deadlines, a FAR rule in flight, and a buyer segment identical to our
wedge.*

**Answer: reversed for cryptography only. Built and shipped** — `aws_cbom.py`, emitted on
`--cbom FILE`.

**Why it was worth building, and why it was cheap.** The regulatory driver and the
operational question are the same one: *which of this estate's cryptography does a quantum
computer break*, and nobody can migrate what they have not enumerated. The cost turned out
to be small because the scanner **already reads the material** for other checks —
`kms.describe_key` for KMS-02/03/04, `acm.describe_certificate` for ACM-01..05,
`elb.describe_listeners` for ELB-02/03. The CBOM adds **no API call and no IAM
permission**; it is those responses projected into a format a regulator and a migration
team both recognise. A test pins that, so a future edit that introduces a dedicated fetch
is reminded the decision was approved on that basis.

**It is an inventory, not a verdict.** RSA-2048 and P-256 are the correct choice today and
the wrong choice eventually. They are not misconfigurations, and a tool that reported them
as failures would teach operators to dismiss the category. So no check IDs, no severity,
no posture-score impact — a document plus `quantum_exposure()`, which answers the count
and the names so a migration can be planned against a horizon the customer chooses.

**CycloneDX 1.6**, because `cryptoProperties` does not exist before it. The rest of the
product emits 1.5 and that stays correct for those documents.

**The document states its own scope limit.** An agentless scan cannot see cryptography
inside a workload, so `metadata.properties` says so explicitly rather than implying
completeness by omission.

**AIBOM / HBOM / QBOM stay skipped.** No regulator mandates them, and building a bill of
materials nobody is required to produce is scope with a story attached.

---

## D4 · Do we ever cross read-only for AI red teaming? — **NO, AND OUT OF SCOPE**

*Answer it in writing now, because it will be asked in every bake-off.*

**Answer: no — and it is a declared non-goal rather than an unbuilt feature.**
OverWatch will not perform active adversarial probing of a customer's models, agents or
guardrails, in either of its forms: probing live endpoints, or driving the customer's own
tool-executing agent. Not behind a flag, not opt-in, not "in a sandbox account".

See **Declared non-goals** below for the scope statement a bake-off question lands on.

**Why — four independent reasons, any one of which is sufficient:**

1. **It spends the customer's money.** Adversarial probing is inference, and inference is
   billed. A security tool that runs up an unbounded bill on the estate it is auditing is
   a different product with a different contract.
2. **It is indistinguishable from an attack in the customer's own telemetry.** The
   CloudTrail signature of a red-team probe is the CloudTrail signature of LLMjacking —
   which we know precisely, because `AITHR-01` is the rule that detects it. We would be
   generating the exact events our own detection is built to alarm on.
3. **It can trip the provider's detections.** GuardDuty and the model providers' own abuse
   systems do not know our probe is authorised.
4. **The engine is not the product.** garak is Apache-licensed. Building this buys a
   scheduler and a report, not a differentiator.

**What we say instead, and it is a stronger answer:** the question "can this agent be made
to do something harmful" is answered by **toxic flow** — trace what the execution role
actually reaches — plus **graph-proven exploitability**, plus **pen-test ingest** for
customers who do run adversarial exercises. That answer survives a customer asking "and
what did it cost me to find out?"

**What enforces it.** `tests/test_decisions.py` asserts that no module invokes a model,
agent or guardrail, and that every action in the permission ledger is read-shaped.

---

## D8 · Do we read the vectors themselves? — **NO**

*Slice 4.2 audits the RAG vector store. `s3vectors` exposes `ListVectors` and
`GetVectors`; `aoss` exposes an index API. Do we use them?*

**Answer: no, and the roadmap's "boundary" label for 4.2 was wrong — not because the
crossing is hard, but because almost nothing needs it.**

The verification came first. Every security question worth asking about a RAG store
turned out to be answerable from configuration:

| Question | Answered by | Class |
|---|---|---|
| Is the corpus endpoint reachable from the internet? | `aoss:GetSecurityPolicy` (network) | config |
| Who may retrieve from it? | `aoss:GetAccessPolicy` (data) | config |
| Is it on a key the customer can revoke? | `aoss:BatchGetCollection.kmsKeyArn` | config |
| Is the S3 Vectors bucket exposed? | `s3vectors:GetVectorBucketPolicy` | config |
| Is that bucket on a customer key? | `s3vectors:GetVectorBucket` | config |
| **What is actually in the corpus?** | **`GetVectors` / `ListVectors`** | **data** |

Only the last row crosses, and what it returns is embeddings — vectors computed from the
customer's documents, and partially invertible back toward them. That is the escalation
**D2** declined for prompt text, and the argument transfers without modification: a
security product that ingests the corpus it is auditing has become a second copy of the
thing at risk. The blast radius of OverWatch being breached would then include the
customer's document set.

**What we do instead.** The same thing `MCP-04` does with the MCP tool list: say the
blind spot out loud. Every `VEC-*` finding carries
`aws_vectorstore.CONTENTS_NOT_READ` — *"this check reads configuration only and does NOT
read the stored vectors"* — because a vector-store finding silent on contents reads as
*contents checked, contents clean*, which is a phantom pass produced by omission rather
than by assertion.

**What this costs.** OverWatch cannot tell you whether a corpus contains regulated data,
and cannot classify a vector store the way `DSPM-01` classifies an S3 bucket. That is a
real gap and it is named rather than hidden. The compensating position is that
`VEC-01/02/03` tell you who can *reach* and *read* the corpus, which is the question that
decides whether the contents matter.

**The consequence for the IAM ask.** The additive policy contains nine `aoss:` and
`s3vectors:` actions, all `Get`/`List`/`BatchGet` of configuration. `s3vectors:GetVectors`
and `s3vectors:ListVectors` are absent and always will be; a test asserts the module
never names them in executable code.

## D9 · Do we detect third-party AI SaaS from flow logs? — **NO**

*Slice 4.4 specified "one CloudTrail query, one flow-log query". The flow-log query was
meant to catch employees using hosted assistants. Do we build it?*

**Answer: no. The CloudTrail half ships as specified; the flow-log half is refused and
replaced with the config-only question underneath it.**

**Why it cannot work from this vantage point.** VPC flow logs record IP addresses, not
hostnames. Detecting `api.openai.com` therefore means matching against a provider IP
allowlist, and:

| | |
|---|---|
| the major providers front their APIs with | Cloudflare and Fastly **shared** ranges |
| so an address match fires on | every CDN-fronted site in the estate |
| and providers rotate addresses | continuously, silently |
| so a miss looks exactly like | a clean bill of health |

That last row is the disqualifying one. It is the same objection slice **3.2** raised
against shipping injection phrasings for tool-description poisoning: *a detection product
whose every miss reads as a clean bill of health, and whose every over-match teaches
operators to skip the category*. Refusing it once is worth nothing if the next slice does
it.

**What ships instead.** `SHAI-03` asks the config-only question underneath: does Bedrock
traffic have a **governed path** at all? A VPC with no Bedrock interface endpoint reaches
Bedrock over NAT or an internet gateway, where no VPC endpoint policy can bound which
models are reachable. That is a real control gap, readable from `ec2:DescribeVpcEndpoints`,
with no false-positive engine attached.

**And the gap is declared rather than implied.** `SHAI-00` states, on every scan, that
third-party hosted assistants are not detectable from an AWS account and that answering
that question needs an egress proxy or a CASB. A reader who sees a shadow-AI section with
no mention of hosted assistants will otherwise assume they were covered — the same
phantom-pass-by-omission `MCP-04` and `VEC-*` exist to prevent.

**What this costs.** OverWatch does not answer the shadow-AI question most organizations
ask first. That is a real limit, named here rather than papered over with a rule that
would appear to answer it.

## D10 · Do we read model artifacts? — **YES, OPT-IN, IN THE FLOW-00 SHAPE**

*Slice 4.6 scans model artifacts for pickle deserialization payloads. That needs
`s3:GetObject`. The roadmap labelled it "crossing · D2". Does it ship?*

**Answer: the config half ships in-charter and always on; the artifact read ships opt-in,
behind its own named policy. And the roadmap's label was imprecise.**

**It is a crossing, but not D2's.** D2 concerns *prompt and completion content* — what
users typed and what models replied. A model artifact is neither. The actual crossing is
the **`s3:GetObject` action class**, which `deploy/cnapp-scanner-role.yaml` already
documents as deliberately excluded from the role, and which VPC flow-log content reads
crossed first in **FLOW-00**. So this follows the shape FLOW-00 established rather than
inventing one, and the permission ledger's own guard enforced it: the additive policy
test names `s3:GetObject` as belonging to "the separate opt-in blocks", and rejected the
first attempt to put `MART-04` in the always-on ask.

**Why the crossing is worth offering at all.** A serialized model is not data. Pickle
encodes instructions and `REDUCE` calls whatever the stream names, so loading an artifact
executes code holding the loader's credentials — in a SageMaker endpoint, the execution
role. The config half establishes that somebody *could* replace the artifact; only reading
it establishes that somebody *did*.

**Why it is safe to offer.** The scan **never unpickles**:

| | |
|---|---|
| parser | `pickletools.genops`, which walks opcodes without running them |
| verified by | a test that pickles a payload opening a file, scans it, and asserts the file does not exist |
| enforced by | a test asserting `pickle.load`, `torch.load` and `joblib.load` never appear in executable code |
| read bound | 8 MB, ranged; a truncated stream is reported as truncated, never as clean |
| what is read | opcodes and the module/name pairs they reference — no tensor payload |

A scanner that unpickled an artifact to determine whether unpickling it is safe would be
the vulnerability, wearing a security label.

**What restraint it ships with.** `EXECUTABLE` and `MALICIOUS` are separate verdicts.
Almost every real PyTorch checkpoint contains `REDUCE` — that is how the format rebuilds
a tensor — so only a global with no explainable reason to be in a serialized model earns
the stronger word. Reporting every model as malicious is how a scanner gets switched off.

**A correction worth recording.** The danger table was first authored from memory and
listed `builtins.open` — a pair pickle **never** emits, because `open` pickles as
`_io.open`. The commonest payload there is would have been missed by a table that read
correctly. It is now driven by observation, with a test that pickles each callable and
asserts the table names what CPython actually emits. `os.system` likewise pickles as
`posix.system` on Linux and `nt.system` on Windows, and both are listed because the
platform that matters is the artifact's, not the scanner's.

## Declared non-goals

Scope statements, not gaps. Each of these is something OverWatch will not build, recorded
here because "we have not done that" and "we will not do that, and here is why" are
different answers to the same bake-off question — and only one of them lets a buyer plan.

### AI red teaming — **out of scope** (D4)

Both forms, and the second is the more important one:

| | Why it is out |
|---|---|
| **Active probing of live model endpoints** | `InvokeModel` is not `List`/`Get`/`Describe`. It spends the customer's inference budget, and its CloudTrail signature is *identical* to LLMjacking — we would be generating the exact events `AITHR-01` exists to alarm on. |
| **Agentic red teaming** (driving the customer's tool-executing agent) | Causes real **writes**, through the customer's own agent, by construction. An agent under test does not know the instruction is a drill, and neither does the system it writes to. This is the highest-consequence item on the list. |

Not behind a flag, not opt-in, not "in a sandbox account". A flag would make it a
supported capability with a support burden and an incident path, and the first customer
outage caused by an authorised probe is indistinguishable — to them — from the attack we
were hired to prevent.

**What we offer instead, and it is a better answer to the underlying question.** "Can this
agent be made to do something harmful?" is answered by **toxic flow** — trace what the
execution role actually reaches — plus **graph-proven exploitability**, plus **pen-test
ingest** for customers who do run adversarial exercises and want the results correlated.
That answer survives the follow-up question a probe cannot: *and what did it cost me to
find out?*

**Enforced by** `tests/test_decisions.py`, which walks the AST of every module and fails on
a call to `invoke_model`, `invoke_agent`, `converse`, `apply_guardrail`,
`retrieve_and_generate`, `invoke_endpoint` or `invoke_agent_runtime` — and separately
asserts every action in the permission ledger is read-shaped, because the first step across
this line would arrive in a policy document rather than in code.

### Also out of scope

`AIBOM` / `HBOM` / `QBOM` — see D3. No regulator mandates them, and the CBOM reversal
covers cryptography only.

The AI-CNAPP roadmap's skip list carries further charter-breaking items — inline prompt
firewalling, eBPF/LSM enforcement and block mode, agent runtime sandboxing, native
auto-remediation writes, and EU AI Act risk-tier classification. Those are the roadmap's
recommendations and are **not** recorded as decisions here, because promoting a
recommendation to a ruling without one having been made is how a scope document stops
being worth reading. See `docs/AI_CNAPP_ROADMAP.md` § *The skip list*.

---

## D6 · The MCP client boundary — **TAKEN**

*The server is inside the boundary; the client — Claude Code, Cursor — is not.*

**Answer: ship it, with the boundary enforced rather than advertised.** Taken in slice 1.5.

The roadmap proposed warnings inside the MCP tool descriptions. Those are read by the
*model*, not by the engineer editing a config file, which makes them a disclaimer rather
than a boundary. So instead: the server **refuses to start** without an explicit
acknowledgement, identifiers are **redacted by default**, and every tool call is
**audited**.

The reasoning that made this shippable at all: a scan already writes every finding, ARN
and account ID to a JSON report on disk, so an MCP server is a **convenience** delta, not
a new capability. What it adds is our name on the path — which is a reason to shape it,
not a reason to abstain.

**What enforces it.** Section G of `tests/test_zero_telemetry.py` and `tests/test_mcp.py`.
Section G's header states plainly what it *cannot* prove — that the client kept the data
inside the boundary — because Sections A–F prove OverWatch sends nothing, and a local
stdio server passes every one of them trivially while being the largest egress decision in
the product.

---

## D7 · The Guardrail sibling dependency — **DECOUPLED**

*The AIDR ingest plan assumes the sibling Guardrail exists and emits events.*

**Answer: no roadmap dependency on it. Verified, and now enforced.**

**Measured rather than recalled**, in the sibling repo:

| | |
|---|---|
| commits | 11 |
| Python | 2,524 LOC |
| test files | 6 |
| Dockerfile | none |
| console entry point | none |
| release/publish workflow | none (a `ci.yml` exists — CI, not publishing) |

That is a promising prototype. It is not a platform another product can take a dependency
on, and treating it as one would make OverWatch's roadmap contingent on a repo that
currently runs from a clone.

**The good news is that nothing does.** OverWatch contains **zero** references to it, and
the AI-detection story already stands alone: slice 1.3 (`aws_airules.py`) derives
LLMjacking and control-tampering detections from **CloudTrail management events**,
importing only `aws_cdr` and `aws_deepplane`. Slice 2.6 (GuardDuty AI Protection ingest)
likewise consumes an AWS-native source.

**The standing rule:** if the sibling is ever integrated, it is as *an optional detection
source behind the existing connector plane* — the same contract as any third-party feed,
with the same tripwire applying to what it sends us. It is never a prerequisite for a
capability OverWatch claims.

**What enforces it.** `tests/test_decisions.py` asserts no import of, or reference to, the
sibling product.

---

## D11 · Does auto-fix end the read-only guarantee? — **OPEN**

**The ask.** `OW2-AR-010` through `OW2-AR-015` specify a controlled auto-fix catalogue:
approved actions only, blast-radius assessment, rollback, a separately credentialed
remediation role, and a global kill switch. `CON-04` anticipates the split and requires
the role be separate, auditable and disableable.

**Why it is a decision and not a sprint.** OverWatch is read-only of configuration by
construction. `aws_remediate.py` generates Terraform, CloudFormation and CLI and
explicitly never applies any of it. The SRS is responsible about auto-fix and it is
buildable — but it changes what the product *is*, from a system that cannot damage the
estate to one that can, and **that guarantee is binary**. Once a remediation role exists,
"OverWatch cannot alter production" stops being true, and the assurance argument for
every other module changes with it.

**The recommendation, not the answer.** Build the governance in II-B and withhold the
execution: the catalogue, the change-record linkage, the before/after capture, the
rollback path and the kill switch — with the executing role **absent from the
deployment**. That delivers everything `AR-010`–`AR-014` specify about *control*, and
leaves the grant of write access as its own explicit, dated approval rather than a side
effect of a sprint.

**What holds the line meanwhile.** No remediation role exists, and no module calls a
mutating AWS API.

---

## D12 · Widen the egress allowlist for SIEM forwarding? — **OPEN**

**The ask.** `OW2-CC-030/031` require findings and platform audit events forwarded to the
enterprise SIEM within five minutes, as JSON over an HTTPS event API and/or CEF/syslog.

**Why it is a decision.** `tests/test_zero_telemetry.py` enumerates every file permitted
to open an outbound connection and fails the build when a new one appears. A CEF/syslog
transport needs a path that is not currently on that list.

**This is not a genuine conflict.** The rule exists to prevent *vendor* telemetry, not
operator-directed integration, and the connector plane already forwards findings to
Splunk HEC under operator control — satisfying `CON-01` and `OW2-DR-003` as written. What
is required is that the allowlist be widened **deliberately**, in a commit whose message
says so.

**The recommendation.** Approve. The cost of the tripwire is exactly this friction, and
the friction is the feature: the next outbound call added without a reason will also stop
the build.

---

## D13 · Build the inbound connectors vendor-neutral? — **OPEN**

**The ask.** `OW2-CC-020` (ManageEngine ServiceDesk Plus), `OW2-CC-040` (the PAM
platform) and `OW2-PA-002` (IBM Instana) all require inbound integrations.

**Why it is a decision.** All three depend on service accounts that do not yet exist
(`AD-01`), and PAM is worse than that: Appendix D item 1 records that the product's API
scope is still unconfirmed, and the vendor is unnamed in the document. **Building against
an unverified contract produces a connector that compiles and does not work.**

**The recommendation.** Build each against a vendor-neutral normalised record, with the
vendor's field names in an alias map rather than in the logic. This is the call
`aws_ingest_aidr.py` and `aws_ingest_credexp.py` already made when their upstream
contracts could not be verified, and both shipped and tested without one. It keeps
`AD-01` off the critical path for the II-A gate — a service account arriving late then
costs an alias map, not a rewrite.

**What holds the line meanwhile.** No connector has been built against an unverified
vendor contract.

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

None of these decisions left the product in a broken or dishonest state while they were
open. D2 and D4 were questions about whether to *add* something, and the answer to each
preserves what the product already does. D3 was the one where adding was the right
answer, and it was built rather than deferred.

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

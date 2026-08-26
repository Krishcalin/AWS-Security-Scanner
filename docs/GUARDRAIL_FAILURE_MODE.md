# CI/CD guardrails — the declared failure mode

Proposed additions to **OW2-SRS-001 §3, FR-5**, for ratification. Fixes review
defect **D5**.

Implemented by [`aws_guardrail.py`](../aws_guardrail.py).

---

## 1. The gap

`OW2-GR-003` says each policy supports **block**, **warn** and **audit** per
environment, and that "production shall default to block for the baseline set after
a defined bake-in period."

`OW2-IF-001` says "connector failure shall never block **scanning**."

Nothing in FR-5 says what the **pipeline gate** does when the policy evaluation
service cannot be reached. Both readings are available, and both are bad:

| Reading | Consequence |
|---|---|
| **Fail closed** | Every production deploy halts — including the deploy that fixes the outage that caused it. The gate becomes the incident. |
| **Fail open** | The control is silently disabled across the entire estate while every pipeline shows a green check. Nobody finds out until an audit. |

A guardrail whose failure mode is undeclared is discovered *during* an incident, by
the people least able to reason about it at the time. `OW2-GR-004`'s 120-second
budget makes this concrete rather than theoretical: something must happen at 120
seconds, and the specification does not say what.

---

## 2. Proposed requirements

> **`OW2-GR-008`** — *Declared gate failure mode.* **Priority: M**
>
> Where the guardrail evaluation service is unavailable, times out, or completes
> only partially, the pipeline verdict shall be derived from the **strictest
> enforcement mode configured for the policies that did not evaluate**, in the
> target environment. An evaluation that did not complete shall never be recorded
> or reported as a pass.
>
> **`OW2-GR-009`** — *Break-glass override.* **Priority: M**
>
> Where an undecidable gate would block, deployment may proceed only under an
> override that carries an identified actor, a stated justification, and a
> mandatory expiry. Overrides shall be recorded distinctly from passes, counted in
> the weekly report required by `OW2-GR-005`, and shall never be represented as a
> successful evaluation. An expired override shall block; it shall not degrade to a
> warning.
>
> **`OW2-GR-010`** — *Timeout is not consent.* **Priority: M**
>
> A pipeline that stops waiting for a verdict shall treat the absence of a result
> as an incomplete evaluation under `OW2-GR-008`. It shall not proceed as though
> the change had passed.

Suggested companion amendment:

* **`OW2-GR-005`** — append: "the weekly report shall separately count verified
  passes, blocks, overrides, and deployments permitted without a completed
  evaluation."

---

## 3. The rule, and why it is shaped this way

### 3.1 An unavailable gate does what its strictest configured mode would have done

Blocking everything is the brutal reading of fail-closed, and it is **not** what the
enforcement modes say. A policy in `audit` mode never blocks; an unreachable service
must not start blocking on its behalf. Equally, a policy in `block` mode must not
stop blocking merely because the thing that enforces it fell over.

Deriving the failure action from the configured mode means losing the service can
neither silently **downgrade** enforcement nor silently **escalate** it. The
environment's own policy decides, which is what `OW2-GR-003` already intended.

### 3.2 Every permissive path is one of exactly two things

There is no third path, and no function argument that produces a clean pass from an
incomplete evaluation:

| Path | Exit | Rendered as |
|---|---|---|
| Completed evaluation, nothing blocking | `0` | **PASSED** |
| Strictest applicable mode was warn/audit | `2` | **ALLOWED WITHOUT EVALUATION — this is not a pass; no policy was checked against this change** |
| Attributed, justified, unexpired override | `2` | **ALLOWED UNDER OVERRIDE — the gate did not clear this change** |
| Anything else | `1` | **BLOCKED** |

Exit code **2** is the load-bearing one, mirroring `scripts/overwatch_evidence.py`,
where `2` already means *unauthenticated* rather than *failed*. A pipeline that
wants strictness fails on `2`; one that does not still proceeds; and either way the
weekly report can count them without parsing prose.

### 3.3 Break-glass is expensive on purpose

Fail-closed without a usable override is unusable — the deploy that fixes the outage
has to ship. So the override is a real, supported path, and it costs:

* an **actor**, because an unattributed override cannot be reviewed by anyone;
* a **justification** of at least 20 characters, because a field that accepts
  `temp` produces an audit trail that looks complete and says nothing;
* an **expiry**, because an override without one is a permanent policy change made
  during an incident;
* a line in the **weekly report** to ISD.

An expired override **blocks**. It does not quietly degrade to a warning — that
would make expiry decorative.

An override also does not launder a verdict the gate actually produced. Break-glass
applies to an *undecidable* gate, never to overruling a real blocking violation the
engine found and reported.

### 3.4 Silence about a policy is not a pass for it

A caller reporting a completed evaluation that names fewer policies than were
declared is reclassified as **partial**. This is the case a caller is most likely to
get wrong, and the failure is silent by construction: the policies nobody mentioned
are exactly the ones nobody notices.

A partial evaluation that already found a blocking violation still **blocks**. An
incomplete evaluation that found a breach is still a breach.

### 3.5 The latency budget

The review's first phrasing was that exceeding the 120-second budget should make the
result "explicitly an override, never a pass." That is right for the case that
matters and wrong as a general rule, so it is implemented more precisely:

* The pipeline **gave up waiting** and has no result → timeout, treated exactly like
  unavailable. This is `OW2-GR-010`, and it matters because a CI config that reads
  its own timeout as success is the single cheapest way to disable the whole
  control while leaving every pipeline green.
* A complete evaluation **arrived late** → honoured on its merits. Ignoring a real
  BLOCK because it was slow would be worse. The breach is recorded so `OW2-GR-004`
  stays measurable rather than aspirational.

---

## 4. The bridge to `OW2-GR-006`

`OW2-GR-006` asks for reconciliation: a resource that violates a guardrail policy
but exists in the estate should raise a finding tagged *guardrail bypass*.

`unverified_allows()` returns every change that shipped without the gate clearing
it. **That is the search list.** A change permitted under an override or a degraded
allow is precisely where to look for a resource that violates a policy nobody
checked — so the two requirements connect rather than each needing its own
discovery mechanism.

---

## 5. What is being asked for

1. **Adopt `OW2-GR-008`, `OW2-GR-009` and `OW2-GR-010`** as M-priority
   requirements in FR-5. (§2)
2. **Ratify exit code 2** — *proceeded without a completed evaluation* — as
   distinct from both pass and block, and require pipelines to surface it. (§3.2)
3. **Amend `OW2-GR-005`** so the weekly report counts the four categories
   separately. (§2)
4. **Confirm who may hold break-glass** and the maximum override lifetime. The
   implementation enforces that an expiry exists; the policy for how long it may be
   is yours, and belongs beside the change-class decision in Appendix D item 3.

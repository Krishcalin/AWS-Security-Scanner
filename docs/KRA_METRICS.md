# KRA metrics — proposed requirement OW2-KM-007

New requirement text for **OW2-SRS-001 §3, FR-8**, for ratification alongside the
metric dictionary `OW2-KM-002` calls for.

Implemented by [`aws_kra.py`](../aws_kra.py). The dictionary is emitted by
`metric_dictionary()` as data, derived from the metric declarations, so a metric
and its published definition cannot drift apart.

---

## 1. The gap

Every KRA in `OW2-KM-001` is a ratio or a count whose denominator comes from
**enumeration** — and enumeration is precisely what fails when a permission is
missing or a region is unreachable.

So the failure mode is not noise. It has a direction, and the direction is
flattering:

| Lost capability | What the KRA reports | The stated target |
|---|---|---|
| `iam:ListUsers` | MFA coverage **100%** | 100% |
| A region unreachable | Internet-exposed critical workloads **0** | zero |
| `organizations:ListAccounts` | Discovery coverage **100%** of the accounts we heard about | 100% |

**In every case the reward for losing visibility is a better number** — and that
number is the one that reaches the BBSC under `OW2-KM-002`.

The SRS comes close to catching this twice and does not:

* `OW2-DT-008` measures asset-discovery coverage — but coverage is itself one of
  the metrics that can be flattered, and nothing bounds the metric by it.
* `OW2-PA-006` flags forecasts with insufficient history — the right instinct,
  applied only to FR-4.

Nothing requires a **metric** to state the population it was computed over, and
nothing forbids reporting a refused read as a pass.

---

## 2. Proposed requirement

> **OW2-KM-007** — *Population disclosure and negative assurance.* **Priority: M**
>
> Every metric, scorecard and evidence artefact shall state the population it was
> computed over, and shall enumerate the members of that population that could not
> be evaluated, together with the reason each could not be evaluated.
>
> A check or subject whose read was refused shall never be reported as passing,
> counted as compliant, or omitted from a denominator.
>
> Where the unevaluated remainder is sufficient to change whether a target is met,
> the metric shall be reported as **NOT ESTABLISHED** rather than as met. NOT
> ESTABLISHED is not a failure of the estate and shall be reported in its own
> column, distinct from both met and not-met, so that the remediation — restoring
> the missing read — is visibly an access problem rather than a security one.
>
> Where the authoritative population itself cannot be enumerated, no value shall be
> reported for that metric.

Suggested companion amendments:

* **`OW2-KM-001`** — append: "each metric shall additionally state its population
  and its coverage of that population."
* **`OW2-KM-002`** — append: "the metric dictionary shall define the NOT
  ESTABLISHED verdict and its distinction from a missed target."
* **`OW2-SC-002`** — append: "a scorecard shall state its attribution coverage; per
  application totals that exclude unattributed findings shall say so."

---

## 3. How it is implemented

### 3.1 A partial population yields a range, not a value

A metric computed over an incomplete population does not have a value; it has an
interval. Both ends are computed:

```
best    the value if every unevaluated member turned out compliant
worst   the value if every unevaluated member turned out adverse
```

and the verdict follows from where the **whole interval** sits:

| Condition | Verdict |
|---|---|
| The **worst** end still meets the target | `MET` — true regardless of what was unreadable |
| The **best** end still misses the target | `NOT_MET` — true regardless |
| The interval straddles the target | `NOT_ESTABLISHED` — the unread data decides |

### 3.2 The asymmetry is the point

> **`NOT_MET` survives incomplete data. `MET` does not.**

Having already found three internet-exposed critical workloads, the target of zero
is missed whatever else was unreadable — that verdict is safe. Having found none
while a region was unreachable, **nothing has been established at all**.

A product that renders those two zeroes identically is the product this requirement
exists to prevent.

Note also that a bound never discards observed evidence. With 9 of 10 users
carrying MFA and 5 unreadable, the best case is 14/15 = 93.3%, not 100% — the one
user already known to lack MFA survives every scenario.

### 3.3 The denominator can itself be unknown

`OW2-KM-001(d)`, asset-discovery coverage, is measured against AWS Organizations
enumeration. If `organizations:ListAccounts` is refused there is no denominator, so
there is no interval either — not even an unbounded one.

That is a **distinct state** from an incomplete population, and it is handled
separately, because a coverage metric quietly reporting 100% of the accounts it
happened to hear about is the most confident wrong answer in the whole set.

### 3.4 The summary line

A scorecard summary counts NOT ESTABLISHED in its own column:

```
1 of 4 KRA targets met; 1 not met; 2 not established — the data needed to
decide them was not readable, so they are neither passes nor failures.
```

Folding unknowns into *met* is the defect. Folding them into *not met* would blame
the estate for a permissions problem and would drive the wrong remediation.

---

## 4. Where this rule already applies in OverWatch

`OW2-KM-007` generalises a discipline the codebase already applies in four places,
which is why it can be met on day one rather than being a commitment to build:

| Surface | How the rule appears |
|---|---|
| Finding resolution | The resolve transition is **coverage-gated**: a finding closes only when a scan that provably executed that check fails to re-observe it. A partial scan cannot mass-resolve. |
| Evidence packs | Coverage sits inside the **signed** root, so stripping the record of what the scan could not reach breaks verification. |
| Posture score | The letter grade is **withheld** below 90% check coverage, and the unassessed penalty band is published beside the score. |
| Risk model | An unmeasured factor is excluded and its weight redistributed, never scored `0.0`; below 50% weight coverage the composite is refused. See [`RISK_MODEL.md`](RISK_MODEL.md) §3. |

---

## 5. What is being asked for

1. **Adopt `OW2-KM-007`** as an M-priority requirement in FR-8. (§2)
2. **Ratify the three-verdict vocabulary** — `MET` / `NOT_MET` / `NOT_ESTABLISHED`
   — and the rule that NOT ESTABLISHED occupies its own column in every report,
   export and board pack. (§3.1, §3.4)
3. **Confirm the BBSC hand-off carries all three**, not a two-state pass/fail
   collapse. This is Appendix D open item 5, and it is the point at which the
   requirement is most likely to be quietly lost: a spreadsheet with a red/green
   column has nowhere to put "nobody knows".

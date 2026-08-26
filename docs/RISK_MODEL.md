# Cloud Risk Score — Model v1 (corrected)

Replacement text for **Appendix B of OW2-SRS-001 v0.1**, for ratification at the
security steering committee (Appendix D, open item 2).

Implemented by [`aws_riskscore.py`](../aws_riskscore.py). The published methodology
`OW2-CC-003` requires is emitted by `RiskModel.methodology()` as data, not prose, so
the UI, the PDF export and the API all render the same model and cannot drift apart.

---

## 1. What was wrong with Appendix B as drafted

Three defects, all in the same short table.

### 1.1 The weights do not sum

| Factor | Weight |
|---|---:|
| Severity-weighted open findings | 30% |
| Exploitability | 20% |
| Exposure | 20% |
| Asset criticality | 15% |
| Hygiene trend | 10% |
| **Total** | **95%** |
| Compensating controls | −15% (credit) |

The five positive factors sum to **95**, not 100, and a −15% credit is then
subtracted from an unstated base. A composite whose positive weights top out at 95
cannot be read against a 0–100 scale without a normalisation step the document never
specifies, so the top grade (A ≥ 90) is either unreachable or reachable only by a
rescaling nobody wrote down.

### 1.2 The score runs the wrong way against its own banding

Every factor in the table is one where **more means worse** — severity-weighted
findings, exploitability, exposure, asset criticality. The banding underneath reads
`A ≥ 90 · B 80–89 · C 70–79 · D 60–69 · E < 60`.

As written, **an estate with maximum severity, maximum exploitability and maximum
exposure scores 95 and is awarded an A.**

The document is carrying two different quantities under one name. FR-1 calls it a
"Cloud Risk Score"; `OW2-SC-002` calls it a "security posture score and letter
grade". They point in opposite directions and are not the same number.

### 1.3 Compensating controls are the wrong instrument

`OW2-CC-002(e)` credits EDR presence, PAM vaulting and a WAF in path as a sixth
weighted factor. An EDR sensor does not make an internet-reachable unpatched host
less reachable or less unpatched — it makes the consequence more likely to be
*noticed*. Credited as a weight, an estate improves its published risk score by
buying tooling without changing a single exposure, and `OW2-KM-001(b)` — which
targets **zero** internet-exposed critical workloads — then disagrees with the
composite about the same estate.

---

## 2. The corrected model

### 2.1 Two numbers, one relationship

```
contributionᵢ = normalised weightᵢ × factorᵢ × 100
risk          = Σ contributionᵢ, creditable ones × (1 − control credit)   [§2.3]
posture       = 100 − risk
grade         = band(posture)
```

* **Risk** — 0–100, **higher is worse**. This is the FR-1 "Cloud Risk Score".
* **Posture** — 0–100, **higher is better**. This is the FR-2 score the letter
  grade bands.

Appendix B's banding thresholds are preserved **exactly** and applied to the
posture. This is also the convention `aws_live_scanner.compute_risk_score` already
uses, so FR-1 and FR-2 stop disagreeing and neither has to move.

### 2.2 Weights are relative, not percentages

The engine normalises whatever weights it is given to sum to 1.0. The declared
column below is Appendix B's own numbers, unchanged.

| Factor | Declared | Normalised | Inputs |
|---|---:|---:|---|
| Severity-weighted open findings | 30 | 31.58% | Counts by severity, normalised per 100 assets |
| Exploitability | 20 | 21.05% | CVSS, EPSS, KEV presence on open vulnerabilities |
| Exposure | 20 | 21.05% | Internet-reachable resources; exposure paths from the twin |
| Asset criticality | 15 | 15.79% | Crown-jewel / criticality tags on affected assets |
| Hygiene trend | 10 | 10.53% | 90-day direction of finding volume and SLA compliance |
| **Total** | **95** | **100.00%** | |

**Why normalise rather than renumber the table.** Renumbering fixes the instance;
normalising fixes the class. Any hand-authored weight set drifts the moment somebody
adds a sixth factor or an administrator retunes one under `OW2-CC-004`, and the same
defect returns silently. Weights become a statement of *relative importance* — which
is the only thing anyone means by them — and the arithmetic can no longer be wrong
because nobody is doing arithmetic.

A consequence worth stating: **ratifying a tidier 100-sum table will not move
anybody's published score.** `30/20/20/15/10` and `6/4/4/3/2` are the same model.

### 2.3 Compensating controls: a bounded multiplier on the creditable factors only

```
risk   = Σ contributions, creditable ones × (1 − credit)
credit = 0                              if the exposure gate is tripped
       = 0                              if no gate verdict was supplied
       = min(control_coverage, 0.15)    otherwise
```

**Only `findings` is creditable.** Detection and containment genuinely reduce the
risk carried by a population of open issues — they are found sooner and contained
faster. They do not touch the other four:

| Factor | Creditable | Why not |
|---|---|---|
| Severity-weighted open findings | **yes** | detection and containment shrink the exposure window of an open issue |
| Exposure | no | a control does not make an asset less reachable — this is the whole objection |
| Exploitability | no | a KEV entry is a property of the vulnerability, not of the response to it |
| Asset criticality | no | a property of the asset |
| Hygiene trend | no | a measurement of the process, not a credit against it |

**This does not preserve Appendix B's 15-point magnitude, deliberately.** Against
the Appendix B weights the maximum *effective* credit is 0.15 × 31.58% ≈ **4.7
points**, not 15. The 15 was attached to the wrong instrument; keeping its size
while fixing the instrument would have been having it both ways. The effective
ceiling is published in `methodology()` so nobody discovers it by subtraction.

**Two guards, not one.** Restricting the credit to creditable factors is the
principled fix. The exposure gate is a second, stricter one:

* **Gate condition.** Credit is withheld entirely whenever the scope contains at
  least one internet-reachable asset carrying a KEV-listed or CRITICAL finding on an
  unconditioned path — there, even the findings credit is wrong, because the control
  sits downstream of a compromise that has already succeeded.
* **A tripped gate must carry a reason.** The engine refuses to construct one
  without it: a withheld credit has to be explainable to whoever asks why their
  score did not move.
* **A missing verdict withholds the credit rather than granting it.** "Nobody
  evaluated exposure" must never read as "exposure is fine". A caller requesting
  credit without supplying a gate verdict gets zero credit and a stated reason.

> **Wiring status.** `ExposureGate` is a caller-supplied verdict and **nothing
> computes it yet** — the score engine is not yet wired to live factor inputs. Until
> it is, every real call path supplies no verdict, which withholds credit. That is
> the safe direction to be un-wired in, but it is un-wired, and the producer is part
> of the "wire the score engine to live factor inputs" item in the Phase II plan.

### 2.4 Banding (unchanged from Appendix B)

| Grade | Posture |
|---|---|
| A | ≥ 90 |
| B | 80–89 |
| C | 70–79 |
| D | 60–69 |
| E | < 60 |

> **Reconciliation item.** `aws_live_scanner.score_to_grade` currently returns `F`
> for the lowest band where the SRS specifies `E`. One of the two should change;
> the SRS letter is used here.

---

## 3. An unmeasured factor is not a factor worth zero

If EPSS and KEV data are unavailable, exploitability is not `0.0` — it is unknown.
Scoring it `0.0` **lowers the risk of an estate nobody measured**, which is the
phantom pass wearing a percentage sign, and it is the most likely way for this
engine to publish a reassuring number about an estate it could not read.

So:

* An unavailable factor is **excluded**, and its weight is **redistributed** across
  the factors that do have data.
* The exclusion and the resulting weight coverage are reported on every score and
  rendered by `RiskScore.caveat()`.
* Below **50%** weight coverage the score is **refused** — `risk`, `posture` and
  `grade` are all `None`. A composite resting on a minority of its factors is not a
  composite.

Worked example, all factors at maximum:

| | Exploitability handled as | Reported risk |
|---|---|---:|
| Honest | excluded, weight redistributed | **100** |
| Naive | scored `0.0` | **79** |

The naive column is a 21-point discount for a missing data feed.

This is the same discipline proposed as new requirement `OW2-KM-007` in the Phase II
review, applied to the score rather than to a KRA.

---

## 4. Model versioning (`OW2-CC-004`)

Every score carries a `model_version` — a digest of the weight set, the credit
ceiling, the bands and the coverage floor. Deriving it from the model's own content
rather than from a hand-maintained integer means an administrator cannot retune a
weight and leave the version behind: **every published score carries proof of which
model produced it**, satisfying the requirement that historical scores are never
silently recomputed.

Current model version: `mf8d9d9a02860`.

Rescaling the weights produces the same score but a different version. Flagging a
no-op recalculation is the safe direction to be wrong in.

---

## 5. What the steering committee is being asked to ratify

1. **The direction convention** — risk ascending, posture descending, grade bands
   the posture. (§2.1)
2. **The declared weights** — Appendix B's own `30/20/20/15/10`, carried forward
   unchanged, now with a defined normalisation. Retuning them is an
   `OW2-CC-004` configuration change, not a code change. (§2.2)
3. **Compensating controls creditable against `findings` only**, the ~4.7-point
   effective ceiling that follows, and the gate condition. (§2.3)
4. **The 50% weight-coverage floor** below which a score is refused. (§3)
5. **`E` vs `F`** for the lowest band. (§2.4)

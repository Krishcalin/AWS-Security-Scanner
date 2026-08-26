# FR-4 — splitting collection from forecasting

Proposed amendment to **OW2-SRS-001 §2.7 (phasing)** and **§3, FR-4**, for
ratification. Fixes review defect **D6**.

Implemented by [`aws_trend.py`](../aws_trend.py).

---

## 1. The gap

**AD-04:** *"Predictive analytics (FR-4) requires ≥6 months of clean trend data post
FR-1/FR-2 go-live before forecast outputs are treated as production-grade."*

**§2.7:** FR-4 sits in **II-C, months 6–12.**

Those two statements are in direct tension. II-C begins at month 6 — which is
precisely when the data AD-04 requires *starts* accumulating, not when six months of
it exist. Under the schedule as drafted:

| Phase II month | Usable history | Forecast status |
|---|---|---|
| 6 (II-C opens) | ~0 months | insufficient |
| 9 | ~3 months | insufficient |
| 12 (II-C gate) | ~6 months | *just* production-grade, unvalidated |

So **every forecast produced inside Phase II carries the `OW2-PA-006` label
"indicative — insufficient history"** — an honest label, on a feature nobody should
act on, attached to the deliverable most likely to be shown to a board.

Worse, the II-C gate requires the forecast list "published monthly with driver
explanations **and accuracy tracking enabled**" (`§7.2`). Accuracy tracking needs
predictions that have *resolved*. A 30-day forecast made in month 12 resolves in
month 13, after Phase II has closed. The gate cannot be met as written.

---

## 2. Proposed amendment

> **Split FR-4 into FR-4a (collection) and FR-4b (forecasting).**
>
> **FR-4a — Trend collection and analytics. Move to II-A.** `OW2-PA-001`
> time-series materialisation, trend reporting, and the data-sufficiency indicator
> `OW2-PA-006`. This is nearly free: the `findings` table already carries
> `first_seen_epoch`, `last_seen_epoch`, `resolved_epoch`, `times_seen` and
> `reopen_count`, and `scans` already carries per-scan posture history. The raw
> material for a time series exists and is currently unexploited.
>
> **`OW2-PA-005` — SLA-breach risk. Move to II-A.** It is arithmetic, needs no
> history, and is the half of FR-4 an owner can actually act on. *Already
> delivered — see `aws_sla.at_risk()`.*
>
> **FR-4b — Cloud Risk Forecast. Move to Phase III.** `OW2-PA-003`, `OW2-PA-004`
> and `OW2-PA-007`, beginning when AD-04's window has actually elapsed.
>
> **Amend `OW2-PA-006`:** below the minimum fittable history, no forecast value
> shall be produced — the output is a refusal, not a labelled number. (§3 below.)

Consequential change to `§7.2`, the II-C gate: replace *"forecast list published
monthly with driver explanations and accuracy tracking enabled"* with *"trend
analytics published monthly with a data-sufficiency indicator; forecast accuracy
tracking armed and reporting its own insufficiency until predictions resolve."*

---

## 3. Why refusing beats labelling

`OW2-PA-006` as drafted says thin outputs "shall be labelled". A label is a string
beside a number, and **the number is what gets copied into the slide.**

This is the same argument that withheld the posture letter grade below 90% coverage,
and that made a KRA report `NOT_ESTABLISHED` rather than a flattering percentage: the
caveat travels separately from the value, and only the value survives the journey.

So the implementation uses three tiers rather than two:

| Tier | Condition | Output |
|---|---|---|
| `INSUFFICIENT` | < 3 usable periods | **no projected value at all** |
| `INDICATIVE` | fittable, below AD-04's window | value + band + the `PA-006` label; **never a KRA input** |
| `PRODUCTION` | meets AD-04 | value + band |

What is still reported at every tier is the **observed series**, because what was
measured is a fact and only the extrapolation is a claim. A refusal is not a blank
screen; it is the history without the prediction.

`Projection.kra_eligible` is a property rather than a flag, so a scorecard cannot
wire an indicative forecast into a KRA by accident.

---

## 4. Six months elapsed is not six months of data

AD-04 says **clean** trend data, and that word is load-bearing.

A period in which the scan could not reach half the estate contributes a data point
that is an artefact of what was not seen, not a measurement of the estate. Counting
it toward sufficiency means a forecast built on six months of holes reports itself
as production-grade.

`Series` therefore counts **usable periods**, not elapsed calendar time. A period is
usable when it carries a value *and* its scan coverage met the floor (default 90%).
Excluded periods are named with their reason, and the exclusion appears as a
forecast driver — so the reader is told the fit rests on fewer observations than the
calendar suggests.

This is the `OW2-KM-007` rule (review defect D3) reaching forward into FR-4, and it
is why the two defects share a fix: **a metric and a forecast fail the same way, by
quietly narrowing what they were computed over.**

---

## 5. Accuracy tracking has its own sufficiency question

`OW2-PA-007` exists *"to build executive confidence before KRAs reference
forecasts."* An accuracy figure computed over two resolved predictions builds
**false** confidence, so `accuracy()` refuses on the same principle the forecast
does, and reports *not established* until enough predictions have resolved.

A prediction whose target date has not arrived is **unresolved**, never scored as a
miss. Counting a pending forecast as wrong is as dishonest as counting it as right.

---

## 6. What is being asked for

1. **Split FR-4 into FR-4a and FR-4b**, moving collection and `OW2-PA-005` into
   II-A and the forecast into Phase III. (§2)
2. **Amend the II-C gate** in §7.2, which cannot be met as written because a
   forecast made in month 12 resolves in month 13. (§2)
3. **Amend `OW2-PA-006`** so insufficient history produces a refusal rather than a
   labelled number. (§3)
4. **Confirm the coverage floor** for a period to count as clean. The
   implementation defaults to 90%, matching the posture-grade floor; the number is
   a policy choice and belongs beside the `OW2-KM-007` ratification.

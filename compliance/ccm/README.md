# CSA CCM applicability matrices

Three facets of the CSA Cloud Controls Matrix, held as data: who typically owns
each control, which layer of the cloud stack it applies to, and which internal
function has a stake in it.

| File | Axis | Sections | Values |
|---|---|---:|---|
| `ownership.yaml` | service model | 3 | `CSP-Owned` / `CSC-Owned` / `Shared` |
| `architectural-relevance.yaml` | cloud stack component | 6 | boolean |
| `organizational-relevance.yaml` | organizational function | 9 | boolean |

208 control ids × 18 sections = **3,744 rows**.

## These files are generated

Edit `scripts/gen_ccm_matrix.py`, not the YAML. The three files are keyed by one
control-id universe, and hand-editing is how three copies of one universe drift
apart with nothing detecting it. `tests/test_ccm_matrix.py` fails on a hand edit.

```bash
python scripts/gen_ccm_matrix.py            # regenerate
python scripts/gen_ccm_matrix.py --check    # CI: fail if stale
python -m pytest tests/test_ccm_matrix.py   # 33 guards
```

## What was corrected from the source export

**`I&S` → `IVS`.** There is no `I&S` domain in the CCM. The export used it for
Infrastructure & Virtualization Security: 9 controls (IVS has 9), sorting
between IPY and LOG, which is exactly where IVS belongs. `compliance/crosswalk.json`
cites `IVS-03/04/06/09`, so the export silently failed to join on **162 rows**
(9 controls × 18 sections).

**`IAM-16` restored.** The export stopped at `IAM-15`. IAM was the only domain
*short* of the published CCM — every other divergence was a surplus — which
points at a dropped row rather than a version difference, and the crosswalk
cites `IAM-16` today.

Its value is **not invented**. Every `IAM-16` row is `null` and the id is named
in each file's `unresolved` block, so the gap is visible *in* the data rather
than absent from it. A guessed value would be indistinguishable from an
authored one, which is the failure this whole exercise is about.

Together these take the crosswalk join from **31/36 to 36/36**.

## Open questions, deliberately not answered here

**The version is `null` and `version_status` is `unverified`.** The export
declared no version. Its id universe is 207 controls across 17 domains, which
does not match the 197 published for CCM v4.0.x, and `compliance/crosswalk.json`
pins `CSA-CCM-4` at `4.0`. Per-domain deltas against v4.0:

| Domain | Here | v4.0 | Δ |
|---|---:|---:|---:|
| AIS | 8 | 7 | +1 |
| DCS | 18 | 15 | +3 |
| IAM | 16 | 16 | 0 (after restore) |
| LOG | 14 | 13 | +1 |
| SEF | 10 | 8 | +2 |
| STA | 16 | 14 | +2 |
| TVM | 12 | 10 | +2 |

Reconcile against the authoritative release, record the deltas, then set
`version` and flip `version_status`. A test forbids stamping a version while
the status says unverified — a guessed version is worse than an absent one.

**`DSP-17` is the only reversal in the ownership matrix.** IaaS `CSP-Owned` →
PaaS `CSP-Owned` → SaaS `CSC-Owned`. Every other row is monotone toward the
provider. It is carried from the export unchanged and named in
`MONOTONICITY_EXCEPTIONS`, so a *second* reversal fails the suite. Confirm it
against the published CCM.

## Verifying against the original export

The exception lists in the generator were transcribed from a spreadsheet
export. To confirm the transcription cell by cell:

```bash
python scripts/ccm_verify_source.py --source path/to/original/exports
```

It compares all 3,726 source cells, applies only the two documented
corrections, and exits 1 naming any cell that disagrees.

## Status: reference data, not posture

Nothing in the engine reads these files yet. They describe *typical* division
of responsibility, not observed configuration, so if they are ever surfaced
they belong on the display side — like the `POLICY-xx` and `DSPM-GAP`
overlays — and must never reach the posture score.

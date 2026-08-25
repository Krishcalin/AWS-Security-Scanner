# OverWatch and the EU Cyber Resilience Act

**Regulation (EU) 2024/2847.** What OverWatch does and does not help with, and the two
dates that are routinely conflated.

---

## Two obligations, two dates

Almost every summary of the CRA runs these together. They are different duties with
different deadlines, and only one of them is close.

| Obligation | Applies from | What it actually requires |
|---|---|---|
| **Article 14** — vulnerability and incident reporting | **11 September 2026** | A *process*: on becoming aware of an actively exploited vulnerability or a severe incident, file an early warning within **24 hours**, a full notification within **72 hours**, and a final report within **14 days** of a corrective measure being available (one month for incidents). Filed **once**, via the CRA **Single Reporting Platform**, to the CSIRT of the manufacturer's main establishment and shared with ENISA. |
| **Annex I** — essential requirements, including the SBOM | **11 December 2027** | *Product properties*. Part I is 13 requirements lettered (a)–(m); Part II is 8 vulnerability-handling requirements numbered (1)–(8). **II(1)** requires a machine-readable software bill of materials covering at least top-level dependencies. |

Chapter IV (notification of conformity assessment bodies) applied from 11 June 2026.

**The distinction matters commercially.** OverWatch's SBOM machinery — `aws_ingest.py`
(CycloneDX/SPDX), `aws_sbom_diff.py`, `aws_vex.py` — addresses **Annex I II(1)**, which
is the **2027** date. It does nothing for the Article 14 reporting clock. Anyone
presenting an SBOM feature as an answer to the September 2026 deadline has merged two
unrelated obligations.

---

## The scope caveat — read this before quoting a score

CRA obligations attach to the **product with digital elements** that a manufacturer
places on the EU market. OverWatch assesses the **AWS estate that product runs on**.

Those are not the same object. A perfectly configured account tells you nothing about
whether the software shipped from it has a secure-by-default configuration, and a
failing check does not by itself put a manufacturer out of conformity.

So the crosswalk below produces **supporting evidence for a conformity argument**,
never conformity itself. It is the same stance the rest of OverWatch's compliance
mapping takes — informational, confirm with your assessor — and it is worth stating
twice here because CRA carries administrative fines up to **€15 million or 2.5% of
worldwide annual turnover**.

---

## What the crosswalk covers

`EU-CRA` is a derived framework in `compliance/crosswalk.json`, projected from the
NIST SP 800-53 Rev 5 spine like the other 34 derived frameworks. 38 edges, one from
every control in the frozen 38-control universe.

**11 of the 21 Annex I requirements are reachable** from cloud configuration:

| Requirement | Reached via |
|---|---|
| **I(a)** no known exploitable vulnerabilities | SI-2 |
| **I(b)** secure by default | CM-6 |
| **I(d)** protection from unauthorised access | AC-3, AC-6(+3), AC-2(3), AC-14, CM-5, IA-2, IA-2(1), IA-5, IA-5(1) |
| **I(e)** confidentiality of stored/transmitted data | SC-28, SC-8, SC-8(1), SC-13, SC-12, SC-12(1) |
| **I(f)** integrity of data | SI-7, SC-8, SC-20, AU-9 |
| **I(h)** availability, incl. DoS resilience | SC-5, CP-9 |
| **I(j)** limited attack surface | SC-7, SC-7(8), CM-7, AC-6 |
| **I(l)** security monitoring and recording | AU-2, AU-12, SI-4, AU-6, AU-6(1), AU-5, AC-6(9) |
| **II(1)** identify components and vulnerabilities, SBOM | **CM-8**, RA-5 |
| **II(2)** remediate without delay | SI-2 |
| **II(3)** regular security testing | CA-8, RA-5, RA-5(2) |

### What it does not reach, and why

The other ten are outside what an agentless cloud-configuration scanner can see. This
is not a backlog — most of them are properties of a development and support process,
not of infrastructure:

| Requirement | Why not |
|---|---|
| **I(c)** security update mechanism, incl. automatic install | A property of the shipped product's updater |
| **I(g)** data minimisation | Requires knowing the product's lawful purpose |
| **I(i)** no negative impact on other devices/networks | Behavioural, observed in use |
| **I(k)** exploitation mitigation techniques | Compile-time and runtime hardening of the binary |
| **I(m)** secure data removal and transfer | A product feature, not a configuration |
| **II(4)** publicly disclose fixed vulnerabilities | An organisational disclosure practice |
| **II(5)** coordinated vulnerability disclosure policy | A published policy |
| **II(6)** contact address for reporting | A published contact |
| **II(7)** secure update distribution | The product's own distribution channel |
| **II(8)** disseminate updates without delay | An operational commitment |

**Article 14 reporting appears nowhere in that table**, because it is not an Annex I
requirement and not a technical control. It is a duty to notice, decide and file
within a clock. No scanner discharges it.

---

## If you are a CRA manufacturer

Two things OverWatch genuinely gives you, and one it does not.

**It gives you the SBOM artefact.** `aws_ingest.py` consumes CycloneDX and SPDX;
`aws_sbom_diff.py` shows what changed between builds; `aws_vex.py` records exploitability
statements so a component that is present but unreachable can be documented as such
rather than remediated pointlessly. That is the II(1) artefact, and it is already built
and tested. Its deadline is December 2027.

**It gives you the evidence trail** for the eleven Annex I requirements above, mapped to
controls and exportable through the existing reporting pipeline.

**It does not give you an Article 14 process.** By 11 September 2026 a manufacturer needs
a named owner, a decision rule for what counts as *actively exploited* or *severe*, an
enrolled route to the Single Reporting Platform, and the ability to move inside 24 hours.
That is organisational work. OverWatch can tell you a vulnerability is present and
reachable, which shortens the *decide* step — it cannot file for you.

---

## Sources

- Regulation (EU) 2024/2847 — <https://eur-lex.europa.eu/eli/reg/2024/2847/oj>
- European Commission, CRA summary — <https://digital-strategy.ec.europa.eu/en/policies/cra-summary>
- European Commission, CRA reporting obligations — <https://digital-strategy.ec.europa.eu/en/policies/cra-reporting>

Dates and the Annex I structure on this page were verified against the Commission's own
published guidance, not inferred from secondary summaries.

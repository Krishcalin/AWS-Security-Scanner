# OverWatch design-doc diagrams & generator

This folder regenerates `docs/OverWatch_System_Design_and_Architecture.docx` and its five figures.

## Files

| File | What it is |
|------|-----------|
| `gen_diagrams.py` | Renders the five architecture PNGs (pure Pillow, 3× supersampled) into this folder. |
| `gen_overwatch_doc.py` | Builds the Word document (pure python-docx), embedding the PNGs from this folder; writes `../OverWatch_System_Design_and_Architecture.docx`. |
| `fig1_architecture.png` | Figure 1 — logical architecture (three tiers). |
| `fig2_topology.png` | Figure 2 — runtime topology (hub in the security VPC). |
| `fig3_pipeline.png` | Figure 3 — scan pipeline & engine fan-out. |
| `fig4_attackpath.png` | Figure 4 — the attack-path graph (the differentiator). |
| `fig5_egress.png` | Figure 5 — egress containment (zero-telemetry). |

## Regenerate

```bash
pip install python-docx pillow          # one-time
cd docs/diagrams
python gen_diagrams.py                   # -> the 5 PNGs (this folder)
python gen_overwatch_doc.py             # -> ../OverWatch_System_Design_and_Architecture.docx
```

Then open the `.docx` in Word and **References → Update Table** to build the page-numbered
table of contents (python-docx writes the TOC as a field Word populates on open).

## Notes

- The generators are pure and offline — no network, consistent with the OverWatch charter.
- `gen_diagrams.py` prefers Windows system fonts (Segoe UI / Consolas) and falls back to the
  Pillow default; on Linux install a sans TTF or adjust the font lists at the top of the file.
- Content is authored in `gen_overwatch_doc.py`; edit prose/tables there and re-run. Keep figure
  captions in sync with the diagram code in `gen_diagrams.py`.

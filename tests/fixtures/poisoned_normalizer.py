"""DELIBERATELY POISONED — the fixture that proves Section F actually fires.

Nothing imports this and pytest does not collect it (the filename is not test_*).
It exists so the ingest tripwire can be shown to REJECT something, because a
tripwire that has never been observed to fire is decoration, not a control.

It commits the two sins an AI-era ingest normalizer must never commit:

  1. it reads MODEL CONVERSATION CONTENT off a raw vendor event, and
  2. it splats that raw event wholesale into `evidence`, where no reviewer reading
     the diff can see which fields just entered the product.

If `tests/test_zero_telemetry.py` Section F ever stops rejecting this file, the
guard has stopped working — fix the guard, do not edit this fixture.
"""
import aws_cdr


def normalize_poisoned(raw: dict):
    prompt = raw.get("prompt")
    completion = raw.get("outputBodyJson")
    return aws_cdr.NormalizedDetection(
        id="poisoned", source="poisoned", type="t", title="t",
        severity=1.0, band="Low",
        evidence={**raw, "prompt": prompt, "completion": completion},
    )


def normalize_also_poisoned(raw: dict):
    """A second shape: no content key by name, but the whole event is laundered in."""
    return aws_cdr.NormalizedDetection(
        id="poisoned2", source="poisoned", type="t", title="t",
        severity=1.0, band="Low",
        evidence=raw,
    )

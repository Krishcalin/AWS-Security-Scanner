"""Phase 0 · slice 0.2(d) — the AI report says which regions it did not look at.

BEDROCK, BEDROCK_AGENTS and SAGEMAKER enumerate REGIONAL resources. Run against one
region, they report success whether or not the account's AI estate lives there, so an
account running Bedrock in us-west-2 and scanned from us-east-1 gets a CLEAN AI
report. Not an empty one — a clean one, which is the version nobody re-reads.

This is the same failure class as rendering AccessDenied as "may not be available in
this region": an absence of evidence presented as evidence of absence.
"""
from __future__ import annotations

import os
import sys
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aws_live_scanner import AWSLiveScanner, compute_risk_score

ALL_REGIONS = ["us-east-1", "us-west-2", "eu-west-1", "ap-southeast-1", "eu-central-1"]


def _scanner(sections, *, all_regions=False, regions=None):
    with patch("aws_live_scanner.HAS_BOTO3", True):
        s = AWSLiveScanner(region="us-east-1", verbose=False, sections=sections,
                           all_regions=all_regions)
        s.account = "123456789012"
    s._client = lambda service, region=None: MagicMock()
    s._all_regions = list(regions) if regions is not None else list(ALL_REGIONS)
    return s


def _notes(s):
    return [r for r in s.results if r.check_id == "AISPM-00"]


def test_a_single_region_scan_says_which_regions_it_skipped():
    """THE FIX. Without this the report is clean and wrong."""
    s = _scanner(["BEDROCK"])
    s._aispm_region_coverage_note()
    notes = _notes(s)
    assert notes, "a single-region AI scan must say what it did not examine"
    msg = notes[0].message
    assert "us-west-2" in msg and "eu-west-1" in msg
    assert "4 other enabled region" in msg


def test_the_note_refuses_the_inference_the_reader_would_otherwise_make():
    """The sentence that matters is not the region list — it is the denial that a
    clean result means anything about the regions we never looked at."""
    s = _scanner(["BEDROCK"])
    s._aispm_region_coverage_note()
    msg = _notes(s)[0].message
    assert "not evidence that no AI resources exist elsewhere" in msg
    assert "--all-regions" in msg


def test_an_all_regions_scan_emits_no_note():
    """The sweep really is complete there, and a note that fires when the thing it
    warns about cannot happen trains people to ignore it."""
    s = _scanner(["BEDROCK"], all_regions=True)
    s._aispm_region_coverage_note()
    assert not _notes(s)


def test_no_note_when_no_ai_section_was_selected():
    s = _scanner(["IAM", "S3"])
    s._aispm_region_coverage_note()
    assert not _notes(s)


def test_exactly_one_note_however_many_ai_sections_run():
    """Three identical notes is noise, and noise is how a real note gets skipped."""
    s = _scanner(["BEDROCK", "BEDROCK_AGENTS", "SAGEMAKER"])
    for _ in range(3):
        s._aispm_region_coverage_note()
    assert len(_notes(s)) == 1


def test_the_note_names_which_ai_sections_were_limited():
    s = _scanner(["BEDROCK", "SAGEMAKER"])
    s._aispm_region_coverage_note()
    msg = _notes(s)[0].message
    assert "BEDROCK" in msg and "SAGEMAKER" in msg


def test_an_unreadable_region_list_is_reported_as_undetermined_not_as_complete():
    """_get_all_regions falls back to [self.region] when describe_regions is denied,
    so an empty 'others' cannot be told apart from a genuine single-region account.
    Claiming either one would be asserting something we do not know."""
    s = _scanner(["BEDROCK"], regions=["us-east-1"])
    s._aispm_region_coverage_note()
    notes = _notes(s)
    assert notes, "an undetermined region list must still be disclosed"
    msg = notes[0].message
    assert "single-region" in msg and "could not be read" in msg
    assert "not distinguishable" in msg


def test_the_note_never_costs_posture_score():
    """A coverage disclosure is not a finding against the customer."""
    s = _scanner(["BEDROCK"])
    s._aispm_region_coverage_note()
    assert compute_risk_score(s.results) == 100.0
    assert all(r.status == "INFO" for r in _notes(s))


def test_the_note_fires_from_the_section_itself_not_only_from_data():
    """A scan scoped to --sections BEDROCK must still disclose its own limits; the
    note cannot depend on DATA being selected."""
    s = _scanner(["BEDROCK"])
    bedrock = MagicMock()
    bedrock.get_model_invocation_logging_configuration.side_effect = \
        Exception("Could not connect to the endpoint URL")
    s._clients["bedrock:us-east-1"] = bedrock
    s._client = lambda service, region=None: s._clients.get(
        f"{service}:{region or s.region}", MagicMock())
    s._check_bedrock()
    assert _notes(s), "the note must be emitted by the AI section itself"


def test_the_note_fires_even_when_the_account_has_no_ai_resources_at_all():
    """The case the slice exists for. An empty stash is not a reason to stay quiet —
    it is the reason to speak."""
    s = _scanner(["BEDROCK"])
    assert not s._aispm_resources
    s._aispm_region_coverage_note()
    assert _notes(s)

"""Leaked-credential ingest: the redaction, the join, and the refusal to overclaim.

THE TEST THAT MATTERS MOST IS THE ONE ABOUT WHAT DOES *NOT* GET STORED
-----------------------------------------------------------------------
Breach records carry plaintext passwords. A security product that stores them becomes a
credential honeypot -- a worse outcome than the risk it was reporting, and a far more
attractive target than the estate it was watching. So `normalize` builds a NEW record
from an allowlist rather than copying and deleting, and the tests below attack that from
both directions: known secret fields must be digested, and *unknown* ones must be dropped
by default rather than by recognition. The second is the one that matters, because it is
the property that survives the vendor adding `password_plaintext_v2` next year.

The rest hold two lines that are easy to cross when a feature is judged on how much it
finds: matching is exact and never fuzzy (a near-match attributes somebody else's breach
to this estate), and a hit is never reported as a compromise (the credential may have
been rotated in 2019).
"""
from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine import aws_epistemics  # noqa: E402
from engine import aws_ingest_credexp as ce  # noqa: E402

PW = "hunter2-correct-horse"

DEHASHED_ISH = {
    "id": "1234", "email": "Alice@Acme.com", "username": "alice",
    "password": PW, "hashed_password": "$2b$12$abcdef",
    "database_name": "LinkedIn 2012", "ip_address": "203.0.113.9",
    "name": "Alice Smith", "phone": "+1-555-0100", "address": "1 Main St",
}


# ── THE REDACTION ───────────────────────────────────────────────────────────
def test_the_plaintext_password_never_survives_normalization():
    n = ce.normalize(DEHASHED_ISH)
    assert PW not in str(n)
    assert PW not in repr(n)


def test_the_hashed_password_never_survives_either():
    """A bcrypt hash is still credential material -- crackable offline, and useless to
    us. Keeping it would be hoarding somebody's secret for no analytical gain."""
    n = ce.normalize(DEHASHED_ISH)
    assert "$2b$12$abcdef" not in str(n)


def test_an_UNKNOWN_secret_field_is_dropped_by_DEFAULT_not_by_recognition():
    """THE property that matters. A denylist protects against the fields somebody
    thought of; an allowlist protects against the field the vendor adds next year."""
    rec = {"email": "a@acme.com", "password_plaintext_v2": "s3cret",
           "recovery_answer": "my first pet", "totp_seed": "JBSWY3DPEHPK3PXP"}
    n = ce.normalize(rec)
    blob = str(n)
    for leaked in ("s3cret", "my first pet", "JBSWY3DPEHPK3PXP"):
        assert leaked not in blob


def test_personal_data_beyond_the_credential_is_also_dropped():
    """Name, phone and address are not needed to answer 'can this identity reach our
    crown jewels', so ingesting them would be collecting PII for no purpose."""
    n = ce.normalize(DEHASHED_ISH)
    blob = str(n)
    assert "Alice Smith" not in blob and "555-0100" not in blob and "Main St" not in blob


def test_the_presence_of_a_credential_is_recorded_even_though_the_value_is_not():
    n = ce.normalize(DEHASHED_ISH)
    assert n["has_password"] is True
    assert n["secret_digest"].startswith("sha256:")


def test_a_record_with_no_credential_says_so():
    n = ce.normalize({"email": "a@acme.com", "database_name": "Some Breach"})
    assert n["has_password"] is False and n["secret_digest"] is None


def test_the_digest_is_stable_and_distinguishing():
    a = ce.digest_secret("same", salt="s")
    b = ce.digest_secret("same", salt="s")
    c = ce.digest_secret("different", salt="s")
    assert a == b and a != c


def test_the_salt_changes_the_digest():
    """Without this an attacker who steals the database rainbow-tables every common
    password in it."""
    assert ce.digest_secret(PW, salt="a") != ce.digest_secret(PW, salt="b")


def test_an_unsalted_digest_is_FLAGGED_rather_than_silently_accepted():
    exp = ce.normalize_many([DEHASHED_ISH])
    cov = ce.coverage(exp, salt="")
    assert any("rainbow table" in n for n in cov["not_evaluated"])


def test_a_salted_run_does_not_raise_the_salt_warning():
    exp = ce.normalize_many([DEHASHED_ISH], salt="pepper")
    cov = ce.coverage(exp, salt="pepper", estate_domains=["acme.com"])
    assert not any("rainbow table" in n for n in cov["not_evaluated"])


# ── what IS kept, because it is what the join needs ─────────────────────────
def test_the_identifiers_needed_for_attribution_survive():
    n = ce.normalize(DEHASHED_ISH)
    assert n["email"] == "alice@acme.com"        # lowercased for exact matching
    assert n["username"] == "alice"
    assert n["source"] == "LinkedIn 2012"
    assert n["ip_address"] == "203.0.113.9"


def test_the_domain_is_derived_from_the_email_not_trusted_from_the_record():
    """A record whose `domain` disagrees with its `email` would attribute the exposure
    to the wrong organisation."""
    n = ce.normalize({"email": "bob@real.com", "domain": "attacker-supplied.com"})
    assert n["domain"] == "real.com"


def test_an_aws_key_id_is_extracted_from_free_text():
    """An access key id is an identifier, not a secret -- and it is the single most
    actionable thing a breach corpus can hold for a cloud estate."""
    n = ce.normalize({"email": "a@acme.com",
                      "notes": "found in dump: AKIAIOSFODNN7EXAMPLE alongside creds"})
    assert n["access_key_id"] == "AKIAIOSFODNN7EXAMPLE"


@pytest.mark.parametrize("prefix", ["AKIA", "ASIA", "AROA", "AIDA"])
def test_the_other_aws_key_id_prefixes_are_recognised(prefix):
    n = ce.normalize({"username": "u", "blob": f"{prefix}IOSFODNN7EXAMPLE"})
    assert n["access_key_id"].startswith(prefix)


def test_vendor_field_aliases_are_mapped():
    """DeHashed's contract could not be verified, so the normalizer accepts the shapes
    peers use rather than committing to one."""
    n = ce.normalize({"mail": "c@acme.com", "login": "carol", "obtained_from": "Dump X"})
    assert n["email"] == "c@acme.com" and n["username"] == "carol"
    assert n["source"] == "Dump X"


# ── exposure kind, because freshness changes what a hit means ────────────────
def test_a_stealer_log_is_distinguished_from_an_old_breach():
    """Malware on a live machine today is a different fact from a 2012 dump, and
    ranking them identically wastes the responder's attention."""
    assert ce.normalize({"email": "a@b.com",
                         "database_name": "RedLine Stealer Logs"})["kind"] == ce.STEALER_LOG
    assert ce.normalize({"email": "a@b.com",
                         "database_name": "LinkedIn 2012"})["kind"] == ce.BREACH


def test_a_combolist_is_distinguished_because_it_is_mostly_recycled():
    assert ce.normalize({"email": "a@b.com",
                         "source": "Combolist 2021"})["kind"] == ce.COMBOLIST


def test_an_unattributed_source_is_unknown_rather_than_assumed_to_be_a_breach():
    assert ce.normalize({"email": "a@b.com"})["kind"] == ce.UNKNOWN_KIND


# ── the join: exact, never fuzzy ────────────────────────────────────────────
PRINCIPALS = [
    {"kind": "IAMUser", "name": "alice", "email": "alice@acme.com"},
    {"kind": "IAMRole", "name": "deploy"},
]


def test_an_exact_email_match_attributes_the_exposure():
    exp = ce.normalize_many([DEHASHED_ISH])
    hits = ce.correlate(exp, PRINCIPALS)
    assert len(hits) == 1
    assert hits[0]["matched_on"] == "email"
    assert hits[0]["principals"][0]["name"] == "alice"


def test_a_NEAR_match_does_not_attribute():
    """`alice.smith@acme.com` is not `alice@acme.com`. Attributing somebody else's
    breach to this estate is worse than a gap, because nobody can check it."""
    exp = ce.normalize_many([{"email": "alice.smith@acme.com", "password": "x"}])
    hits = ce.correlate(exp, PRINCIPALS)
    assert hits == [] or hits[0]["principals"] == []


def test_an_exposure_for_nobody_in_the_estate_is_dropped_entirely():
    exp = ce.normalize_many([{"email": "stranger@elsewhere.com", "password": "x"}])
    assert ce.correlate(exp, PRINCIPALS) == []


def test_a_domain_match_without_a_principal_is_kept_but_FLAGGED_as_weaker():
    """Somebody at the company was breached, but not an identity we can name. Worth
    surfacing, and worth distinguishing from a confirmed principal match."""
    exp = ce.normalize_many([{"email": "hr-person@acme.com", "password": "x"}])
    hits = ce.correlate(exp, PRINCIPALS, estate_domains=["acme.com"])
    assert len(hits) == 1
    assert hits[0]["domain_match_only"] is True
    assert hits[0]["principals"] == []


def test_a_leaked_key_matches_a_LIVE_key_id():
    exp = ce.normalize_many([{"username": "svc", "blob": "AKIAIOSFODNN7EXAMPLE"}])
    hits = ce.correlate(exp, PRINCIPALS, known_key_ids=["AKIAIOSFODNN7EXAMPLE"])
    assert hits[0]["matched_on"] == "access_key_id"


def test_a_leaked_key_that_is_NOT_live_is_not_attributed():
    exp = ce.normalize_many([{"username": "svc", "blob": "AKIAIOSFODNN7EXAMPLE"}])
    assert ce.correlate(exp, PRINCIPALS, known_key_ids=["AKIAOTHERKEY12345678"]) == []


def test_matching_is_case_insensitive_on_identifiers_but_still_exact():
    exp = ce.normalize_many([{"email": "ALICE@ACME.COM", "password": "x"}])
    assert ce.correlate(exp, PRINCIPALS)[0]["principals"][0]["name"] == "alice"


# ── coverage: absence of findings must not read as safety ───────────────────
def test_a_leaked_key_with_NO_key_inventory_is_reported_as_unevaluated():
    """THE honest branch. Without a live key list the highest-value join simply did not
    happen, and silence there is indistinguishable from 'your keys are fine'."""
    exp = ce.normalize_many([{"username": "svc", "blob": "AKIAIOSFODNN7EXAMPLE"}])
    cov = ce.coverage(exp, known_key_ids=[], estate_domains=["acme.com"])
    assert any("no live key inventory" in n for n in cov["not_evaluated"])


def test_supplying_a_key_inventory_clears_that_note():
    exp = ce.normalize_many([{"username": "svc", "blob": "AKIAIOSFODNN7EXAMPLE"}])
    cov = ce.coverage(exp, known_key_ids=["AKIAIOSFODNN7EXAMPLE"],
                      estate_domains=["acme.com"])
    assert not any("no live key inventory" in n for n in cov["not_evaluated"])


def test_missing_estate_domains_is_reported():
    cov = ce.coverage(ce.normalize_many([DEHASHED_ISH]))
    assert any("No estate domains" in n for n in cov["not_evaluated"])


def test_the_provenance_says_a_hit_is_not_a_compromise():
    """A breach record is a third party's observation of a CORPUS, not of this estate.
    The credential may have been rotated years ago."""
    cov = ce.coverage(ce.normalize_many([DEHASHED_ISH]))
    assert cov["provenance"] == aws_epistemics.OBSERVED
    assert "does not establish that the credential still works" in cov["provenance_note"]
    assert "NOT an observation of this estate" in cov["provenance_note"]


def test_the_counts_are_reported_for_a_clean_ingest():
    cov = ce.coverage(ce.normalize_many([DEHASHED_ISH]), salt="s",
                      estate_domains=["acme.com"])
    assert cov["total_exposures"] == 1 and cov["with_credential"] == 1


# ── this module must never reach the network ────────────────────────────────
def test_the_module_imports_no_egress_primitive():
    """Polling a breach API would widen the zero-telemetry allowlist -- and would send
    the customer's people to a third party as a side effect of a scan. That decision
    belongs to the operator, outside the product."""
    import ast
    path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        "aws_ingest_credexp.py")
    tree = ast.parse(open(path, encoding="utf-8").read())
    banned = {"urllib.request", "http.client", "requests", "httpx", "socket",
              "aiohttp", "urllib3", "subprocess"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            assert not banned & {a.name for a in node.names}
        if isinstance(node, ast.ImportFrom) and node.module:
            assert node.module not in banned


# ── malformed input ─────────────────────────────────────────────────────────
@pytest.mark.parametrize("bad", [None, "x", 7, [], {}])
def test_malformed_records_are_dropped_not_raised(bad):
    assert ce.normalize(bad) is None


def test_a_record_with_nothing_to_join_on_is_dropped():
    """An exposure attributable to nobody cannot be acted on and is not worth storing."""
    assert ce.normalize({"database_name": "Some Breach", "password": "x"}) is None


def test_normalize_many_skips_the_unusable_and_keeps_the_rest():
    out = ce.normalize_many([DEHASHED_ISH, None, {"password": "orphan"},
                             {"email": "b@acme.com"}])
    assert len(out) == 2


def test_correlate_survives_empty_inputs():
    assert ce.correlate(None, None) == []
    assert ce.coverage(None)["total_exposures"] == 0

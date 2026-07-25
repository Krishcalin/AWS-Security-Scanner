"""Phase-4 Slice-4 · B3 — aws_license: SPDX normalization + category + policy (pure)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import aws_license as lic


def test_null_licenses_are_unknown():
    for raw in (None, "", "NOASSERTION", "NONE"):
        assert lic.normalize_spdx(raw) == ("UNKNOWN", "unknown")


def test_deprecated_id_fold():
    assert lic.normalize_spdx("GPL-2.0") == ("GPL-2.0-only", "strong_copyleft")
    assert lic.normalize_spdx("LGPL-2.1") == ("LGPL-2.1-only", "weak_copyleft")
    assert lic.normalize_spdx("AGPL-3.0") == ("AGPL-3.0-only", "network_copyleft")


def test_with_exception_is_stripped():
    assert lic.normalize_spdx("GPL-2.0-only WITH Classpath-exception-2.0") == \
        ("GPL-2.0-only", "strong_copyleft")


def test_categories():
    assert lic.category_of("MIT") == "permissive"
    assert lic.category_of("Apache-2.0") == "permissive"
    assert lic.category_of("MPL-2.0") == "weak_copyleft"
    assert lic.category_of("GPL-3.0-only") == "strong_copyleft"
    assert lic.category_of("AGPL-3.0-only") == "network_copyleft"
    assert lic.category_of("SSPL-1.0") == "proprietary"
    assert lic.category_of("BUSL-1.1") == "proprietary"
    assert lic.category_of("LicenseRef-Custom") == "unknown"


def test_expression_or_takes_most_permissive():
    # a consumer may pick MIT → the effective obligation is permissive, not AGPL
    assert lic.normalize_spdx("MIT OR AGPL-3.0-only") == ("MIT", "permissive")
    assert lic.normalize_spdx("GPL-3.0-only OR Apache-2.0") == ("Apache-2.0", "permissive")


def test_expression_and_takes_most_restrictive():
    # must satisfy BOTH → the effective obligation is the AGPL arm
    assert lic.normalize_spdx("MIT AND AGPL-3.0-only") == ("AGPL-3.0-only", "network_copyleft")
    assert lic.normalize_spdx("MIT AND BSD-3-Clause") == ("MIT", "permissive")


def test_nested_and_of_or():
    # (MIT OR Apache-2.0) AND GPL-3.0-only  →  OR resolves to permissive, AND to GPL
    r = lic.normalize_spdx("(MIT OR Apache-2.0) AND GPL-3.0-only")
    assert r == ("GPL-3.0-only", "strong_copyleft")


def test_default_policy_verdicts():
    assert lic.evaluate_license("MIT", "permissive") == "allow"
    assert lic.evaluate_license("LGPL-2.1-only", "weak_copyleft") == "allow"
    assert lic.evaluate_license("GPL-3.0-only", "strong_copyleft") == "review"
    assert lic.evaluate_license("UNKNOWN", "unknown") == "review"
    assert lic.evaluate_license("AGPL-3.0-only", "network_copyleft") == "deny"
    assert lic.evaluate_license("SSPL-1.0", "proprietary") == "deny"


def test_policy_id_override_and_custom_policy():
    pol = {"deny": [], "review": ["strong_copyleft"], "allow": ["permissive"],
           "ids": {"AGPL-3.0-only": "allow"}}
    # custom policy: AGPL no longer denied by category, and the exact id is allow-listed
    assert lic.evaluate_license("AGPL-3.0-only", "network_copyleft", pol) == "allow"
    assert lic.evaluate_license("GPL-3.0-only", "strong_copyleft", pol) == "review"


def test_assess_convenience():
    a = lic.assess("AGPL-3.0")
    assert a == {"spdx_id": "AGPL-3.0-only", "category": "network_copyleft", "verdict": "deny"}

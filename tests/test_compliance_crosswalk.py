#!/usr/bin/env python3
"""
Tests for the compliance-breadth slice — the NIST 800-53 -> 30+ framework crosswalk.

Covers the loader (structural + fabrication guards, digest, overlay), the pure
crosswalk_scorecard fold (native-invariance, off-switch, 1->N / N->1 / omission /
coverage-stability / min_confidence), the emission (compliance_payload keys), the
service methods, and — most importantly — the CI ACCURACY VALIDATOR over the SHIPPED
reference file (every mapped NIST control is one of the 38 the product actually uses;
no fabricated framework; sources present).
"""
import types

import pytest

import aws_live_scanner as als
import compliance_crosswalk as cx


# ── fixtures ───────────────────────────────────────────────────────────────────
def _R(status, cid):
    return types.SimpleNamespace(status=status, check_id=cid, section="S3", resource="b",
                                 message="m", severity="HIGH",
                                 compliance=als.COMPLIANCE_MAP.get(cid, {}))


def _universe():
    return als._nist_universe_from_map(als.COMPLIANCE_MAP)


def _mini_reader(data):
    return lambda _path: data


# a tiny synthetic crosswalk for precise fold assertions
_MINI = {
    "frameworks": [
        {"id": "NIST", "name": "NIST", "native": True},
        {"id": "FW1", "name": "Framework One", "family": "test", "sources": ["https://ex/1"]},
        {"id": "FW2", "name": "Framework Two", "family": "test", "sources": ["https://ex/2"]},
    ],
    "crosswalk": {
        "AC-3": {"FW1": {"targets": ["a", "b"], "confidence": "high", "note": "1->N"},
                 "FW2": {"targets": ["x"], "confidence": "medium", "note": ""}},
        "AC-6": {"FW1": {"targets": ["a"], "confidence": "low", "note": "N->1 onto a"}},
        "SI-2": {"FW2": {"targets": ["y"], "confidence": "high", "note": ""}},
        # SC-28 maps to NOTHING here -> omission
    },
}


def _load_mini():
    return cx.load_crosswalk(reader=_mini_reader(_MINI))


# ── loader ──────────────────────────────────────────────────────────────────────
def test_load_shipped_file_is_valid():
    xw, fw, digest = cx.load_crosswalk(nist_universe=_universe())
    assert digest.startswith("cw-")
    natives = [k for k, v in fw.items() if v["native"]]
    derived = [k for k, v in fw.items() if not v["native"]]
    assert set(natives) == {"CIS", "PCI-DSS", "HIPAA", "SOC2", "NIST"}
    assert len(derived) >= 30                       # the breadth goal
    # every mapped NIST control is one of the 38 the product actually tags
    assert set(xw.keys()) <= set(_universe())


def test_loader_rejects_edge_targeting_a_native_framework():
    bad = {"frameworks": [{"id": "NIST", "native": True}, {"id": "PCI-DSS", "native": True}],
           "crosswalk": {"AC-3": {"PCI-DSS": {"targets": ["7.2.1"], "confidence": "high"}}}}
    with pytest.raises(cx.CrosswalkError):
        cx.load_crosswalk(reader=_mini_reader(bad))


def test_loader_rejects_unknown_nist_when_universe_given():
    bad = {"frameworks": [{"id": "NIST", "native": True}, {"id": "FW1"}],
           "crosswalk": {"ZZ-99": {"FW1": {"targets": ["a"], "confidence": "high"}}}}
    with pytest.raises(cx.CrosswalkError):
        cx.load_crosswalk(reader=_mini_reader(bad), nist_universe=frozenset({"AC-3"}))


def test_loader_rejects_blank_target_and_bad_confidence():
    with pytest.raises(cx.CrosswalkError):
        cx.load_crosswalk(reader=_mini_reader(
            {"frameworks": [{"id": "FW1"}], "crosswalk": {"AC-3": {"FW1": {"targets": [" "], "confidence": "high"}}}}))
    with pytest.raises(cx.CrosswalkError):
        cx.load_crosswalk(reader=_mini_reader(
            {"frameworks": [{"id": "FW1"}], "crosswalk": {"AC-3": {"FW1": {"targets": ["a"], "confidence": "certain"}}}}))


def test_loader_rejects_unknown_framework_and_duplicate_id():
    with pytest.raises(cx.CrosswalkError):
        cx.load_crosswalk(reader=_mini_reader(
            {"frameworks": [{"id": "FW1"}], "crosswalk": {"AC-3": {"NOPE": {"targets": ["a"], "confidence": "high"}}}}))
    with pytest.raises(cx.CrosswalkError):
        cx.load_crosswalk(reader=_mini_reader(
            {"frameworks": [{"id": "FW1"}, {"id": "FW1"}], "crosswalk": {}}))


def test_digest_is_stable_under_reordering():
    a = cx.load_crosswalk(reader=_mini_reader(_MINI))[2]
    reordered = {"crosswalk": _MINI["crosswalk"], "frameworks": list(reversed(_MINI["frameworks"]))}
    b = cx.load_crosswalk(reader=_mini_reader(reordered))[2]
    assert a == b


def test_overlay_adds_a_framework():
    overlay = {"frameworks": [{"id": "CUSTOM", "name": "Acme Internal", "family": "custom", "sources": ["https://acme/policy"]}],
               "crosswalk": {"AC-3": {"CUSTOM": {"targets": ["ACME-1"], "confidence": "medium"}}}}
    xw, fw, _ = cx.load_crosswalk(reader=_mini_reader(_MINI), overlay=overlay)
    assert "CUSTOM" in fw and xw["AC-3"]["CUSTOM"]["targets"] == ["ACME-1"]


def test_get_crosswalk_fail_open_on_missing_file():
    assert cx.get_crosswalk("/nonexistent/crosswalk.json") == ({}, {}, "")


def test_loader_rejects_missing_confidence_and_non_dict_edge():
    with pytest.raises(cx.CrosswalkError):
        cx.load_crosswalk(reader=_mini_reader(
            {"frameworks": [{"id": "FW1"}], "crosswalk": {"AC-3": {"FW1": {"targets": ["a"]}}}}))
    with pytest.raises(cx.CrosswalkError):
        cx.load_crosswalk(reader=_mini_reader(
            {"frameworks": [{"id": "FW1"}], "crosswalk": {"AC-3": {"FW1": ["a", "b"]}}}))


def test_data_file_universe_is_enforced_in_production_path():
    # the shipped file self-declares nist_universe; an edge outside it is rejected
    # WITHOUT the caller passing a universe (production loads via get_crosswalk).
    bad = {"nist_universe": ["AC-3"], "frameworks": [{"id": "FW1"}],
           "crosswalk": {"ZZ-99": {"FW1": {"targets": ["a"], "confidence": "high"}}}}
    with pytest.raises(cx.CrosswalkError):
        cx.load_crosswalk(reader=_mini_reader(bad))     # no nist_universe arg — file field guards


def test_shipped_file_declares_the_actual_38_universe():
    import json
    import os
    path = os.path.join(os.path.dirname(cx.__file__), "compliance", "crosswalk.json")
    data = json.load(open(path, encoding="utf-8"))
    assert set(data.get("nist_universe", [])) == set(_universe()), \
        "the data file's declared nist_universe must match COMPLIANCE_MAP's NIST axis"


# ── fold: native-invariance + off-switch ────────────────────────────────────────
def test_fold_off_returns_empty():
    card = als.compliance_scorecard([_R("FAIL", "S3-01")])
    assert als.crosswalk_scorecard(card, None) == {}
    assert als.crosswalk_scorecard(card, {}) == {}


def test_native_scorecard_untouched_by_fold():
    card = als.compliance_scorecard([_R("FAIL", "S3-01"), _R("PASS", "S3-03")])
    xw, fw, _ = _load_mini()
    als.crosswalk_scorecard(card, xw, fw)
    # the native card must not have grown derived-only keys
    assert "derived" not in card["NIST"] and "confidence_mix" not in card["PCI-DSS"]


# ── fold: derivation correctness ────────────────────────────────────────────────
def test_fold_1_to_N_and_omission():
    # AC-3 FAILs (via S3-01); it maps 1->N onto FW1 {a,b}
    card = als.compliance_scorecard([_R("FAIL", "S3-01")])
    assert card["NIST"]["failed_controls"] == ["AC-3"]  # sanity: S3-01 -> AC-3
    xw, fw, _ = _load_mini()
    d = als.crosswalk_scorecard(card, xw, fw, nist_universe=_universe())
    # FW1 universe = {a (from AC-3,AC-6), b (from AC-3)}; both fail because AC-3 failed
    assert set(d["FW1"]["failed_controls"]) == {"a", "b"}
    assert d["FW1"]["control_provenance"]["a"]["via_nist"] == ["AC-3", "AC-6"]  # N->1 dedup
    # confidence of 'a' = MAX(high from AC-3, low from AC-6) = high
    assert d["FW1"]["control_provenance"]["a"]["confidence"] == "high"


def test_fold_N_to_1_fails_if_any_backing_fails():
    # only AC-6 fails (IAM-07 -> AC-6(5)? use a check that yields AC-6). Build directly:
    card = {"NIST": {"failed_controls": ["AC-6"]}}
    xw, fw, _ = _load_mini()
    d = als.crosswalk_scorecard(card, xw, fw, nist_universe=frozenset({"AC-3", "AC-6", "SI-2"}))
    # 'a' backed by AC-3(pass) + AC-6(fail) -> fails (any); 'b' backed by AC-3 only -> passes
    assert "a" in d["FW1"]["failed_controls"] and "b" not in d["FW1"]["failed_controls"]


def test_fold_min_confidence_rederives_precisely():
    # AC-3 FAILs. FW2 has AC-3(medium)->x and SI-2(high)->y; at high-only the medium
    # edge drops, so x leaves the universe entirely (precise, not a lossy filter).
    card = als.compliance_scorecard([_R("FAIL", "S3-01")])
    xw, fw, _ = _load_mini()
    uni = _universe()
    allc = als.crosswalk_scorecard(card, xw, fw, nist_universe=uni)
    hi = als.crosswalk_scorecard(card, xw, fw, nist_universe=uni, min_confidence="high")
    assert allc["FW2"]["controls_total"] == 2 and allc["FW2"]["failed_controls"] == ["x"]
    assert hi["FW2"]["controls_total"] == 1 and hi["FW2"]["failed_controls"] == []  # only y, which passed


def test_fold_note_is_deterministic_for_a_multi_edge_control():
    # 'a' is reached via AC-3 (note '1->N') and AC-6 (note 'N->1 onto a'); the winning
    # note must NOT depend on set iteration order — sorted(nist_all) makes AC-3 first.
    card = {"NIST": {"failed_controls": ["AC-3", "AC-6"]}}
    xw, fw, _ = _load_mini()
    uni = frozenset({"AC-3", "AC-6", "SI-2"})
    notes = {als.crosswalk_scorecard(card, xw, fw, nist_universe=uni)["FW1"]["control_provenance"]["a"]["note"]
             for _ in range(8)}
    assert len(notes) == 1                              # deterministic across repeated folds


def test_fold_coverage_stability_independent_of_firing_subset():
    xw, fw, _ = _load_mini()
    uni = _universe()
    c1 = als.crosswalk_scorecard(als.compliance_scorecard([_R("FAIL", "S3-01")]), xw, fw, nist_universe=uni)
    c2 = als.crosswalk_scorecard(als.compliance_scorecard([_R("FAIL", "S3-01"), _R("PASS", "IAM-02")]), xw, fw, nist_universe=uni)
    assert c1["FW1"]["controls_total"] == c2["FW1"]["controls_total"]   # universe is stable


# ── emission ────────────────────────────────────────────────────────────────────
def test_compliance_payload_has_three_keys_and_native_matches():
    results = [_R("FAIL", "S3-01"), _R("PASS", "S3-03")]
    payload = als.compliance_payload(results)
    assert set(payload) == {"compliance_scorecard", "compliance_crosswalk", "compliance_crosswalk_meta"}
    assert payload["compliance_scorecard"] == als.compliance_scorecard(results)   # byte-identical native
    assert payload["compliance_crosswalk_meta"]["generated_from"] == "NIST-800-53-Rev5"
    assert payload["compliance_crosswalk_meta"]["frameworks"] >= 30


# ── service ──────────────────────────────────────────────────────────────────────
def _svc():
    from cnapp_registry import AccountRegistry
    from cnapp_service import InMemoryResultStore, PlatformService
    results = InMemoryResultStore()
    results.put("123456789012", {"compliance_scorecard": als.compliance_scorecard(
        [_R("FAIL", "S3-01"), _R("FAIL", "IAM-02"), _R("PASS", "S3-03")])})
    return PlatformService(registry=AccountRegistry.open(":memory:"), results=results,
                           hub_role_arn="a", cfn_template_url="b",
                           secret_writer=lambda a, v: "ssm://x", secret_reader=lambda r: "x",
                           clock=lambda: 1)


def test_service_list_frameworks_and_edges():
    svc = _svc()
    fw = svc.list_compliance_frameworks()
    assert fw["spine"] == "NIST-800-53-Rev5" and len(fw["frameworks"]) >= 35
    edges = svc.get_crosswalk("PCI-DSS-4")
    assert edges and all(e["framework"] == "PCI-DSS-4" for e in edges)


def test_service_account_compliance_native_plus_derived():
    svc = _svc()
    comp = svc.get_account_compliance("123456789012")
    assert set(comp["native"]) == {"CIS", "PCI-DSS", "HIPAA", "SOC2", "NIST"}
    assert len(comp["derived"]) >= 30
    assert comp["derived"]["PCI-DSS-4"]["derived"] is True
    # min_confidence tightens the universe
    hi = svc.get_account_compliance("123456789012", min_confidence="high")
    assert hi["derived"]["PCI-DSS-4"]["controls_total"] <= comp["derived"]["PCI-DSS-4"]["controls_total"]
    # framework filter
    only = svc.get_account_compliance("123456789012", frameworks=["PCI-DSS-4"])
    assert set(only["derived"]) == {"PCI-DSS-4"}


def test_service_account_compliance_missing_account_is_none():
    assert _svc().get_account_compliance("999999999999") is None


def test_org_compliance_carries_derived_confidence_and_provenance():
    from cnapp_registry import AccountRegistry
    from cnapp_service import InMemoryResultStore, PlatformService
    reg = AccountRegistry.open(":memory:")
    results = InMemoryResultStore()
    for aid in ("111111111111", "222222222222"):
        reg.upsert_account(aid, now_epoch=1, role_arn="r", external_id_ref="ssm://x")
        reg.set_onboarding_status(aid, "active", 1)
        results.put(aid, {"compliance_scorecard": als.compliance_scorecard([_R("FAIL", "S3-01")])})
    svc = PlatformService(registry=reg, results=results, hub_role_arn="a", cfn_template_url="b",
                          secret_writer=lambda a, v: "ssm://x", secret_reader=lambda r: "x", clock=lambda: 1)
    org = svc.org_compliance()
    pci = org["derived"]["PCI-DSS-4"]
    assert pci["confidence_mix"]["high"] > 0            # provenance survived the merge (was dropped)
    assert pci["control_provenance"]                    # failed-control provenance survived too
    assert pci["controls_total"] == 2 * svc.get_account_compliance("111111111111")["derived"]["PCI-DSS-4"]["controls_total"]


# ── CI ACCURACY VALIDATOR (the fabrication gate over the SHIPPED file) ──────────
def test_shipped_crosswalk_accuracy_gate():
    universe = _universe()
    xw, fw, digest = cx.load_crosswalk(nist_universe=universe)   # rejects any fabricated NIST id
    derived = [m for m in fw.values() if not m["native"]]
    assert len(derived) >= 30, "breadth goal: >=30 derived frameworks"
    # every derived framework is version/authority/source describable + has >=1 edge
    reachable = set()
    for nist, fwmap in xw.items():
        assert nist in universe                                  # drift/fabrication guard
        for fid, edge in fwmap.items():
            assert not fw[fid]["native"]                         # never a native target
            assert edge["targets"] and all(t.strip() for t in edge["targets"])
            assert edge["confidence"] in ("high", "medium", "low")
            reachable.add(fid)
    for m in derived:
        assert m["id"] in reachable, f"{m['id']} has no crosswalk edges"
        assert m["sources"], f"{m['id']} has no authoritative source citation"
    # ids unique (loader already guarantees) + native/derived never collide
    assert len({m["id"] for m in fw.values()}) == len(fw)

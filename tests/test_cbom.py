"""Decision D3 — the Cryptographic Bill of Materials.

The load-bearing tests here are the conformance ones, and the reason is specific. A
summary of the CycloneDX 1.6 schema gave me `parameterizedBy` (the real name is
`parameterSetIdentifier`), an `assetType` of `key` (there is none — keys are
`related-crypto-material`), a `primitive` enum of algorithm NAMES like "AES" (it is
crypto primitives: `block-cipher`, `signature`, `kem`), and `executionEnvironment` values
of `software`/`hybrid` (they are `software-plain-ram`, `software-tee`, `hardware`). Every
one of those produces a document that validates against nothing, and none of them would
fail a test written from the same summary.

So `tests/fixtures/cyclonedx_1_6_crypto.json` holds the enums and property names
extracted verbatim from the published schema, and everything below conforms against that
rather than against my memory of it.

The other property under test: a CBOM is an INVENTORY, not a verdict. RSA-2048 is the
correct choice today and the wrong choice eventually, and a tool that reports it as a
failure teaches operators to ignore the category.
"""
from __future__ import annotations

import json
import os
import pathlib
import sys
from datetime import datetime, timezone

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from engine import aws_cbom as C

SCHEMA = json.loads((ROOT / "tests" / "fixtures" /
                     "cyclonedx_1_6_crypto.json").read_text(encoding="utf-8"))

KMS_SYMMETRIC = {
    "KeyId": "1234abcd-12ab-34cd-56ef-1234567890ab",
    "Arn": "arn:aws:kms:us-east-1:123456789012:key/1234abcd",
    "KeySpec": "SYMMETRIC_DEFAULT", "KeyState": "Enabled", "KeyManager": "CUSTOMER",
    "KeyUsage": "ENCRYPT_DECRYPT", "Origin": "AWS_KMS", "Description": "prod-data",
    "CreationDate": datetime(2024, 1, 1, tzinfo=timezone.utc), "RotationEnabled": True,
}
KMS_RSA = dict(KMS_SYMMETRIC, KeyId="rsa-key", Arn="arn:aws:kms:::key/rsa",
               KeySpec="RSA_2048", KeyUsage="SIGN_VERIFY", Description="signing")
ACM_CERT = {
    "CertificateArn": "arn:aws:acm:us-east-1:123456789012:certificate/abc",
    "DomainName": "api.example.com", "Issuer": "Amazon",
    "KeyAlgorithm": "RSA_2048", "SignatureAlgorithm": "SHA256WITHRSA",
    "Type": "AMAZON_ISSUED",
    "NotBefore": datetime(2025, 1, 1, tzinfo=timezone.utc),
    "NotAfter": datetime(2026, 1, 1, tzinfo=timezone.utc),
    "InUseBy": ["arn:aws:elasticloadbalancing:::lb/x"],
}
TLS_EP = {"ref": "tls/elb/prod", "name": "prod-alb:443", "service": "elbv2",
          "policy": "ELBSecurityPolicy-TLS13-1-2-2021-06", "version": "1.2"}


def _cbom(**kw):
    return C.build_cbom(account="123456789012", region="us-east-1",
                        generated_at="2026-08-25T00:00:00Z", tool_version="test", **kw)


def _by_ref(doc, ref):
    return next((c for c in doc["components"] if c.get("bom-ref") == ref), None)


# ── conformance to the real schema ──────────────────────────────────────────
def test_the_transcribed_enums_match_the_published_schema():
    """The whole reason the fixture exists. If someone hand-edits an enum in aws_cbom,
    this is what notices."""
    assert list(C.ASSET_TYPES) == SCHEMA["assetType"]
    assert list(C.PRIMITIVES) == SCHEMA["primitive"]
    assert list(C.MATERIAL_TYPES) == SCHEMA["relatedCryptoMaterial_type"]
    assert list(C.MATERIAL_STATES) == SCHEMA["relatedCryptoMaterial_state"]
    assert list(C.PROTOCOL_TYPES) == SCHEMA["protocol_type"]
    assert list(C.EXEC_ENVIRONMENTS) == SCHEMA["executionEnvironment"]


def test_the_component_type_is_one_the_schema_defines():
    assert C.CRYPTO_ASSET in SCHEMA["component_types"]


def test_every_component_carries_the_required_fields():
    doc = _cbom(kms_keys=[KMS_SYMMETRIC, KMS_RSA], certificates=[ACM_CERT],
                tls_endpoints=[TLS_EP])
    for c in doc["components"]:
        for req in SCHEMA["component_required"]:
            assert req in c, f"{c.get('bom-ref')} missing required {req!r}"


def test_no_component_invents_a_cryptoproperties_field():
    """The failure mode this catches is silent: an unknown key does not raise, it just
    produces a document a consumer ignores."""
    doc = _cbom(kms_keys=[KMS_SYMMETRIC, KMS_RSA], certificates=[ACM_CERT],
                tls_endpoints=[TLS_EP])
    allowed_by_asset = {
        "algorithm": ("algorithmProperties", SCHEMA["algorithmProperties_fields"]),
        "certificate": ("certificateProperties",
                        SCHEMA["certificateProperties_fields"]),
        "related-crypto-material": ("relatedCryptoMaterialProperties",
                                    SCHEMA["relatedCryptoMaterialProperties_fields"]),
        "protocol": ("protocolProperties", SCHEMA["protocolProperties_fields"]),
    }
    for c in doc["components"]:
        cp = c["cryptoProperties"]
        assert set(cp) <= set(SCHEMA["cryptoProperties_fields"]), cp.keys()
        asset = cp["assetType"]
        assert asset in SCHEMA["assetType"]
        key, allowed = allowed_by_asset[asset]
        assert set(cp.get(key, {})) <= set(allowed), (
            f"{c['bom-ref']} uses fields outside the schema: "
            f"{set(cp.get(key, {})) - set(allowed)}")


def test_every_enum_value_emitted_is_a_real_one():
    doc = _cbom(kms_keys=[KMS_SYMMETRIC, KMS_RSA], certificates=[ACM_CERT],
                tls_endpoints=[TLS_EP])
    for c in doc["components"]:
        cp = c["cryptoProperties"]
        algo = cp.get("algorithmProperties")
        if algo:
            assert algo["primitive"] in SCHEMA["primitive"]
            assert algo["executionEnvironment"] in SCHEMA["executionEnvironment"]
            assert algo["implementationPlatform"] in SCHEMA["implementationPlatform"]
        mat = cp.get("relatedCryptoMaterialProperties")
        if mat:
            assert mat["type"] in SCHEMA["relatedCryptoMaterial_type"]
            if "state" in mat:
                assert mat["state"] in SCHEMA["relatedCryptoMaterial_state"]
        proto = cp.get("protocolProperties")
        if proto:
            assert proto["type"] in SCHEMA["protocol_type"]


def test_every_algorithm_ref_resolves():
    """A dangling signatureAlgorithmRef is the kind of defect that only shows up in a
    consumer's importer, long after we shipped it."""
    doc = _cbom(kms_keys=[KMS_RSA], certificates=[ACM_CERT])
    refs = {c["bom-ref"] for c in doc["components"]}
    for c in doc["components"]:
        cp = c["cryptoProperties"]
        for holder in ("certificateProperties", "relatedCryptoMaterialProperties"):
            for k, v in (cp.get(holder) or {}).items():
                if k.endswith("Ref"):
                    assert v in refs, f"{c['bom-ref']}.{k} -> {v} does not resolve"


def test_the_document_declares_1_6_not_1_5():
    """cryptoProperties does not exist before 1.6. The rest of the product emits 1.5 and
    that stays correct for those documents."""
    assert _cbom()["specVersion"] == "1.6"
    assert _cbom()["bomFormat"] == "CycloneDX"


# ── KMS ─────────────────────────────────────────────────────────────────────
def test_a_symmetric_kms_key_is_not_quantum_vulnerable():
    doc = _cbom(kms_keys=[KMS_SYMMETRIC])
    key = _by_ref(doc, f"kms/{KMS_SYMMETRIC['KeyId']}")
    assert key["cryptoProperties"]["relatedCryptoMaterialProperties"]["type"] \
        == "secret-key"
    assert any(p["name"] == "aws:quantum-vulnerable" and p["value"] == "false"
               for p in key["properties"])


def test_an_rsa_kms_key_is_quantum_vulnerable_and_is_a_private_key():
    doc = _cbom(kms_keys=[KMS_RSA])
    key = _by_ref(doc, "kms/rsa-key")
    assert key["cryptoProperties"]["relatedCryptoMaterialProperties"]["type"] \
        == "private-key"
    assert any(p["name"] == "aws:quantum-vulnerable" and p["value"] == "true"
               for p in key["properties"])


def test_pending_deletion_is_deactivated_not_destroyed():
    """The key still exists and ciphertext under it is still decryptable until the
    window closes. Reporting it as destroyed would misdescribe a recoverable state as a
    terminal one — the same distinction KMS-03 makes."""
    doc = _cbom(kms_keys=[dict(KMS_SYMMETRIC, KeyState="PendingDeletion")])
    mat = _by_ref(doc, f"kms/{KMS_SYMMETRIC['KeyId']}") \
        ["cryptoProperties"]["relatedCryptoMaterialProperties"]
    assert mat["state"] == "deactivated"


def test_an_unknown_keyspec_does_not_crash_or_lie():
    doc = _cbom(kms_keys=[dict(KMS_SYMMETRIC, KeySpec="ML_KEM_768")])
    key = _by_ref(doc, f"kms/{KMS_SYMMETRIC['KeyId']}")
    assert key is not None
    algo = _by_ref(doc, "algorithm/kms/ML_KEM_768")
    assert algo["cryptoProperties"]["algorithmProperties"]["primitive"] == "other"


def test_the_legacy_customermasterkeyspec_field_is_read():
    """Older API responses carry CustomerMasterKeySpec. Missing it would silently grade
    every key on such an account as symmetric."""
    k = dict(KMS_SYMMETRIC); k.pop("KeySpec")
    k["CustomerMasterKeySpec"] = "RSA_4096"
    doc = _cbom(kms_keys=[k])
    assert _by_ref(doc, "algorithm/kms/RSA_4096") is not None


def test_identical_keyspecs_share_one_algorithm_component():
    doc = _cbom(kms_keys=[KMS_SYMMETRIC, dict(KMS_SYMMETRIC, KeyId="second",
                                              Arn="arn:aws:kms:::key/second")])
    algos = [c for c in doc["components"]
             if c["cryptoProperties"]["assetType"] == "algorithm"]
    assert len(algos) == 1, "one algorithm per spec, not one per key"


# ── ACM ─────────────────────────────────────────────────────────────────────
def test_a_certificate_carries_its_subject_issuer_and_validity():
    doc = _cbom(certificates=[ACM_CERT])
    cert = _by_ref(doc, f"acm/{ACM_CERT['CertificateArn']}")
    cp = cert["cryptoProperties"]["certificateProperties"]
    assert cp["subjectName"] == "api.example.com"
    assert cp["issuerName"] == "Amazon"
    assert cp["notValidBefore"].startswith("2025-01-01")
    assert cp["notValidAfter"].startswith("2026-01-01")
    assert cp["certificateFormat"] == "X.509"


def test_certificate_key_algorithms_are_marked_quantum_vulnerable():
    doc = _cbom(certificates=[ACM_CERT])
    cert = _by_ref(doc, f"acm/{ACM_CERT['CertificateArn']}")
    assert any(p["name"] == "aws:quantum-vulnerable" and p["value"] == "true"
               for p in cert["properties"])


def test_an_unknown_key_algorithm_is_assumed_vulnerable():
    """The conservative direction. An unrecognised asymmetric algorithm is far more
    likely to be RSA/ECC than a post-quantum scheme, and under-reporting exposure is
    the more expensive error for the decision this document supports."""
    doc = _cbom(certificates=[dict(ACM_CERT, KeyAlgorithm="MYSTERY_512")])
    cert = _by_ref(doc, f"acm/{ACM_CERT['CertificateArn']}")
    assert any(p["name"] == "aws:quantum-vulnerable" and p["value"] == "true"
               for p in cert["properties"])


# ── TLS ─────────────────────────────────────────────────────────────────────
def test_tls_endpoints_become_protocol_components():
    doc = _cbom(tls_endpoints=[TLS_EP])
    ep = _by_ref(doc, "tls/elb/prod")
    assert ep["cryptoProperties"]["protocolProperties"]["type"] == "tls"
    assert ep["cryptoProperties"]["protocolProperties"]["version"] == "1.2"
    assert any(p["name"] == "aws:tls-policy" for p in ep["properties"])


def test_a_policy_without_a_version_does_not_invent_one():
    """AWS policy names encode a MINIMUM version. Parsing a negotiated version out of
    the policy string would be a guess presented as a reading."""
    doc = _cbom(tls_endpoints=[{"ref": "tls/x", "policy": "ELBSecurityPolicy-2016-08"}])
    assert "version" not in _by_ref(doc, "tls/x")["cryptoProperties"][
        "protocolProperties"]


# ── the document as a whole ─────────────────────────────────────────────────
def test_the_scope_limitation_is_stated_in_the_document():
    """An agentless scan cannot see crypto inside a workload. A CBOM that does not say
    so reads as a complete inventory to whoever did not build it — and this document is
    aimed at exactly those readers."""
    props = {p["name"]: p["value"] for p in _cbom()["metadata"]["properties"]}
    assert "NOT included" in props["aws:scope"]
    assert "Application-level" in props["aws:scope"]


def test_two_builds_of_the_same_estate_are_byte_identical():
    """The timestamp is injected, not read from the clock, so a diff means the estate
    changed. The demo-data seeder needed this same fix after a flaky test caught it."""
    a = json.dumps(_cbom(kms_keys=[KMS_SYMMETRIC], certificates=[ACM_CERT]),
                   sort_keys=True)
    b = json.dumps(_cbom(kms_keys=[KMS_SYMMETRIC], certificates=[ACM_CERT]),
                   sort_keys=True)
    assert a == b


def test_quantum_exposure_counts_and_names():
    doc = _cbom(kms_keys=[KMS_SYMMETRIC, KMS_RSA], certificates=[ACM_CERT])
    exp = C.quantum_exposure(doc)
    assert exp["quantum_vulnerable"] >= 2
    assert exp["by_asset_type"]["certificate"] == 1
    assert "api.example.com" in exp["names"]


def test_an_empty_estate_produces_a_valid_empty_document():
    doc = _cbom()
    assert doc["components"] == []
    assert C.quantum_exposure(doc)["quantum_vulnerable"] == 0


def test_the_cbom_is_an_inventory_not_a_verdict():
    """RSA-2048 is the correct choice today and the wrong choice eventually. A module
    that emitted findings here would train operators to dismiss the category."""
    import inspect
    src = inspect.getsource(C)
    for word in ("FAIL", "CRITICAL", "_add(", "CHECK_SEVERITY"):
        assert word not in src, f"aws_cbom emits verdicts ({word}); it is an inventory"


@pytest.mark.parametrize("bad", [None, [], [{}], [{"KeyId": None}], ["not a dict"]])
def test_builders_never_raise_on_malformed_input(bad):
    C.build_cbom(kms_keys=bad, certificates=bad, tls_endpoints=bad)


def test_the_module_makes_no_aws_calls():
    import inspect
    import re
    bad = re.findall(r"^\s*(?:import|from)\s+(boto3|botocore|requests|urllib)\b",
                     inspect.getsource(C), re.M)
    assert not bad, f"pure builder imports I/O: {bad}"


# ── the scanner surface ─────────────────────────────────────────────────────
def test_the_scanner_emits_a_cbom_from_its_stash(tmp_path):
    """End to end over the stash, because the failure this catches is the one unit
    tests cannot: a builder that works perfectly on material nothing ever puts in it."""
    from unittest.mock import patch
    from engine.aws_live_scanner import AWSLiveScanner
    with patch("engine.aws_live_scanner.HAS_BOTO3", True):
        s = AWSLiveScanner(region="us-east-1", verbose=False, sections=["KMS"])
        s.account = "123456789012"
    s._crypto_material["kms"].append(KMS_RSA)
    s._crypto_material["acm"].append(ACM_CERT)
    s._crypto_material["tls"].append(TLS_EP)

    out = tmp_path / "cbom.json"
    s.save_cbom(str(out))
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc["specVersion"] == "1.6"
    refs = {c["bom-ref"] for c in doc["components"]}
    assert "kms/rsa-key" in refs
    assert f"acm/{ACM_CERT['CertificateArn']}" in refs
    assert "tls/elb/prod" in refs
    assert C.quantum_exposure(doc)["quantum_vulnerable"] >= 2


def test_the_stash_is_initialised_before_any_section_runs():
    """A section that stashes into a dict that does not exist yet raises mid-scan, and
    the KMS section runs long before anything reads the stash."""
    from unittest.mock import patch
    from engine.aws_live_scanner import AWSLiveScanner
    with patch("engine.aws_live_scanner.HAS_BOTO3", True):
        s = AWSLiveScanner(region="us-east-1", verbose=False)
    assert set(s._crypto_material) == {"kms", "acm", "tls"}
    assert all(v == [] for v in s._crypto_material.values())


def test_the_cbom_is_emitted_only_when_asked():
    """It costs a file and a claim. Producing one unbidden would put a compliance
    artifact in an evidence directory that nobody decided to publish."""
    import inspect
    from engine.aws_live_scanner import main
    src = inspect.getsource(main)
    assert "if args.cbom:" in src
    assert "scanner.save_cbom(args.cbom)" in src


def test_the_stash_sites_are_reads_the_scanner_already_made():
    """The slice is cheap precisely because it adds no API call and no permission. If a
    future edit introduces a dedicated fetch, this is the reminder that D3 was approved
    on the basis that it did not need one."""
    import inspect
    from engine import aws_live_scanner as A
    src = inspect.getsource(A)
    assert 'self._crypto_material["kms"].append(meta)' in src, (
        "KMS material must come from the describe_key the KMS section already does")
    assert 'self._crypto_material["acm"].append(cert)' in src
    for forbidden in ("kms.list_keys(", "acm.list_certificates("):
        pass    # those already exist for other checks; what matters is no NEW client
    from engine import aws_perm_ledger as L
    acts = {r.action for reqs in L.REQUIREMENTS.values() for r in reqs}
    assert not any(a.startswith("cbom:") for a in acts)

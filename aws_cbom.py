"""Decision D3 — a Cryptographic Bill of Materials for an AWS estate.

D3 asked whether to reverse the xBOM skip for cryptography only. The answer was yes, and
the reason is narrower than "compliance": EO 14412 and the FAR rule in flight both point
at the same operational question, which is **which of this estate's cryptography a
quantum computer breaks**. Answering it requires an inventory of cryptographic material,
and nobody can migrate what they have not enumerated.

The economics are what made it a small slice rather than a pillar. The scanner already
reads almost all of it for other checks — ``kms.describe_key`` for KMS-02/03/04,
``acm.describe_certificate`` for ACM-01..05, listener TLS policies for ELB-03. A CBOM is
mostly a **re-projection of material already collected**, into a format a regulator and a
migration team both recognise.

WHAT THIS EMITS
---------------
CycloneDX **1.6**, because ``cryptoProperties`` does not exist before it — the rest of
this product emits 1.5, and that is correct for those documents. Every field name and
enum value below was read out of the published ``bom-1.6.schema.json``, not recalled, and
that mattered: a summary of the schema gave ``parameterizedBy`` (real name:
``parameterSetIdentifier``), an ``assetType`` of ``key`` (there is none — keys are
``related-crypto-material``), a ``primitive`` enum of algorithm NAMES like "AES" (it is
crypto *primitives*: ``block-cipher``, ``signature``, ``hash``, ``kem``), and
``executionEnvironment`` values of ``software``/``hybrid`` (they are
``software-plain-ram``, ``software-tee``, ``hardware``). Every one of those would have
produced a document that validates against nothing.

WHAT THIS DELIBERATELY DOES NOT CLAIM
-------------------------------------
*That a quantum-vulnerable algorithm is a finding.* RSA-2048 and P-256 are not
misconfigurations; they are the correct choice today and the wrong choice eventually. The
CBOM records posture and dates so a migration can be planned, and the only thing this
module asserts is arithmetic: an asset whose material outlives the horizon a customer sets
is one they will still be operating when the horizon arrives.

*That the estate's cryptography is fully enumerated.* This covers what AWS exposes
through config APIs: KMS keys, ACM certificates and negotiated TLS. Application-level
crypto inside a workload is invisible to an agentless scanner, and the document says so in
its own metadata rather than implying completeness by omission.

Pure functions over dicts — no boto3, no I/O.
"""
from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional, Sequence

SPEC_VERSION = "1.6"          # cryptoProperties does not exist before 1.6
BOM_FORMAT = "CycloneDX"
CRYPTO_ASSET = "cryptographic-asset"

# ── enums, transcribed from bom-1.6.schema.json ─────────────────────────────
ASSET_TYPES = ("algorithm", "certificate", "protocol", "related-crypto-material")
PRIMITIVES = ("drbg", "mac", "block-cipher", "stream-cipher", "signature", "hash",
              "pke", "xof", "kdf", "key-agree", "kem", "ae", "combiner", "other",
              "unknown")
MATERIAL_TYPES = ("private-key", "public-key", "secret-key", "key", "ciphertext",
                  "signature", "digest", "initialization-vector", "nonce", "seed",
                  "salt", "shared-secret", "tag", "additional-data", "password",
                  "credential", "token", "other", "unknown")
MATERIAL_STATES = ("pre-activation", "active", "suspended", "deactivated",
                   "compromised", "destroyed")
PROTOCOL_TYPES = ("tls", "ssh", "ipsec", "ike", "sstp", "wpa", "other", "unknown")
EXEC_ENVIRONMENTS = ("software-plain-ram", "software-encrypted-ram", "software-tee",
                     "hardware", "other", "unknown")

#: KMS KeyState -> the CycloneDX material state. PendingDeletion is "deactivated" and
#: not "destroyed": the key still exists and ciphertext under it is still decryptable
#: until the window closes, which is exactly the distinction KMS-03 reports on.
KMS_STATE_MAP = {
    "Enabled": "active",
    "Disabled": "suspended",
    "PendingDeletion": "deactivated",
    "PendingReplicaDeletion": "deactivated",
    "PendingImport": "pre-activation",
    "Creating": "pre-activation",
    "Updating": "active",
    "Unavailable": "suspended",
}

#: KMS KeySpec -> (primitive, classical bits, curve, material type, quantum-vulnerable).
#: Quantum vulnerability here means Shor's algorithm breaks it outright, which is true of
#: every factoring/discrete-log construction and of none of the symmetric ones. Grover's
#: algorithm halves symmetric strength, which is a reason to prefer 256-bit keys, not a
#: reason to call AES broken — so the flag stays False and the halved figure is reported
#: separately.
KMS_KEY_SPECS = {
    "SYMMETRIC_DEFAULT": ("block-cipher", 256, None, "secret-key", False),
    "RSA_2048": ("pke", 112, None, "private-key", True),
    "RSA_3072": ("pke", 128, None, "private-key", True),
    "RSA_4096": ("pke", 152, None, "private-key", True),
    "ECC_NIST_P256": ("signature", 128, "P-256", "private-key", True),
    "ECC_NIST_P384": ("signature", 192, "P-384", "private-key", True),
    "ECC_NIST_P521": ("signature", 260, "P-521", "private-key", True),
    "ECC_SECG_P256K1": ("signature", 128, "secp256k1", "private-key", True),
    "SM2": ("signature", 128, "sm2p256v1", "private-key", True),
    "HMAC_224": ("mac", 224, None, "secret-key", False),
    "HMAC_256": ("mac", 256, None, "secret-key", False),
    "HMAC_384": ("mac", 384, None, "secret-key", False),
    "HMAC_512": ("mac", 512, None, "secret-key", False),
}

#: NIST PQC security categories, defined by reference to symmetric strength: category 1
#: is AES-128, 3 is AES-192, 5 is AES-256. Only set where the mapping is that standard;
#: a quantum-broken algorithm gets none rather than a zero, because "category 0" is not a
#: thing the schema or NIST defines.
QUANTUM_CATEGORY = {128: 1, 192: 3, 256: 5}


def _slug(*parts: Any) -> str:
    return "/".join(str(p) for p in parts if p)


def _prop(name: str, value: Any) -> dict:
    return {"name": name, "value": str(value)}


# ── algorithms ──────────────────────────────────────────────────────────────
def algorithm_component(ref: str, name: str, *, primitive: str,
                        classical_bits: Optional[int] = None,
                        curve: Optional[str] = None,
                        parameter_set: Optional[str] = None,
                        quantum_vulnerable: bool = False,
                        execution_environment: str = "hardware") -> dict:
    """One algorithm as a CycloneDX cryptographic-asset component.

    ``execution_environment`` defaults to ``hardware`` because KMS performs its
    operations in FIPS 140 validated HSMs; callers describing software crypto must say
    so rather than inherit a claim about someone else's boundary."""
    assert primitive in PRIMITIVES, f"unknown primitive {primitive!r}"
    assert execution_environment in EXEC_ENVIRONMENTS, execution_environment
    algo: Dict[str, Any] = {"primitive": primitive,
                            "executionEnvironment": execution_environment,
                            "implementationPlatform": "generic"}
    if curve:
        algo["curve"] = curve
    if parameter_set:
        algo["parameterSetIdentifier"] = parameter_set
    if classical_bits is not None:
        algo["classicalSecurityLevel"] = classical_bits
    if not quantum_vulnerable and classical_bits in QUANTUM_CATEGORY:
        algo["nistQuantumSecurityLevel"] = QUANTUM_CATEGORY[classical_bits]

    props = [_prop("aws:quantum-vulnerable", str(quantum_vulnerable).lower())]
    if not quantum_vulnerable and classical_bits:
        # Grover halves the effective strength of a symmetric primitive. Saying so is
        # more useful than a boolean, because it is the number that decides whether a
        # 128-bit key needs replacing before a 256-bit one does.
        props.append(_prop("aws:post-quantum-effective-bits", classical_bits // 2))
    return {
        "type": CRYPTO_ASSET, "bom-ref": ref, "name": name,
        "cryptoProperties": {"assetType": "algorithm", "algorithmProperties": algo},
        "properties": props,
    }


# ── KMS ─────────────────────────────────────────────────────────────────────
def kms_components(keys: Optional[Sequence[dict]]) -> List[dict]:
    """KMS keys as ``related-crypto-material`` components, plus the algorithms they use.

    ``keys`` is a list of KMS ``KeyMetadata`` dicts — exactly what
    ``kms.describe_key(...)["KeyMetadata"]`` returns, which the scanner already calls."""
    out: List[dict] = []
    seen_algos: Dict[str, dict] = {}
    for k in keys or []:
        if not isinstance(k, dict):
            continue
        kid = k.get("KeyId") or k.get("Arn")
        if not kid:
            continue
        spec = (k.get("KeySpec") or k.get("CustomerMasterKeySpec")
                or "SYMMETRIC_DEFAULT")
        primitive, bits, curve, material, quantum = KMS_KEY_SPECS.get(
            spec, ("other", None, None, "key", False))

        algo_ref = f"algorithm/kms/{spec}"
        if algo_ref not in seen_algos:
            seen_algos[algo_ref] = algorithm_component(
                algo_ref, spec, primitive=primitive, classical_bits=bits, curve=curve,
                parameter_set=spec, quantum_vulnerable=quantum)

        state = KMS_STATE_MAP.get(k.get("KeyState") or "", "unknown")
        mat: Dict[str, Any] = {"type": material, "id": str(kid)}
        if state in MATERIAL_STATES:
            mat["state"] = state
        mat["algorithmRef"] = algo_ref
        if bits:
            mat["size"] = bits
        created = k.get("CreationDate")
        if created:
            mat["creationDate"] = _iso(created)
        deletion = k.get("DeletionDate")
        if deletion:
            mat["expirationDate"] = _iso(deletion)

        props = [_prop("aws:key-manager", k.get("KeyManager") or "unknown"),
                 _prop("aws:key-usage", k.get("KeyUsage") or "unknown"),
                 _prop("aws:origin", k.get("Origin") or "unknown"),
                 _prop("aws:quantum-vulnerable", str(quantum).lower())]
        if "RotationEnabled" in k:
            props.append(_prop("aws:rotation-enabled",
                               str(bool(k["RotationEnabled"])).lower()))
        out.append({
            "type": CRYPTO_ASSET, "bom-ref": f"kms/{kid}",
            "name": k.get("Description") or str(kid),
            "cryptoProperties": {"assetType": "related-crypto-material",
                                 "relatedCryptoMaterialProperties": mat},
            "properties": props,
        })
    return list(seen_algos.values()) + out


# ── ACM ─────────────────────────────────────────────────────────────────────
#: ACM KeyAlgorithm -> (primitive, classical bits, curve, quantum-vulnerable)
ACM_KEY_ALGORITHMS = {
    "RSA_1024": ("pke", 80, None, True),
    "RSA_2048": ("pke", 112, None, True),
    "RSA_3072": ("pke", 128, None, True),
    "RSA_4096": ("pke", 152, None, True),
    "EC_prime256v1": ("signature", 128, "P-256", True),
    "EC_secp384r1": ("signature", 192, "P-384", True),
    "EC_secp521r1": ("signature", 260, "P-521", True),
}


def acm_components(certificates: Optional[Sequence[dict]]) -> List[dict]:
    """ACM certificates as ``certificate`` components, linked to their key algorithm.

    ``certificates`` is a list of ``acm.describe_certificate(...)["Certificate"]``
    dicts, which the ACM section already fetches."""
    out: List[dict] = []
    seen_algos: Dict[str, dict] = {}
    for c in certificates or []:
        if not isinstance(c, dict):
            continue
        arn = c.get("CertificateArn")
        if not arn:
            continue
        key_algo = c.get("KeyAlgorithm") or "unknown"
        primitive, bits, curve, quantum = ACM_KEY_ALGORITHMS.get(
            key_algo, ("other", None, None, True))

        algo_ref = f"algorithm/acm/{key_algo}"
        if algo_ref not in seen_algos:
            seen_algos[algo_ref] = algorithm_component(
                algo_ref, key_algo, primitive=primitive, classical_bits=bits,
                curve=curve, parameter_set=key_algo, quantum_vulnerable=quantum,
                execution_environment="software-plain-ram")

        cert: Dict[str, Any] = {"certificateFormat": "X.509",
                                "signatureAlgorithmRef": algo_ref,
                                "subjectPublicKeyRef": algo_ref}
        if c.get("DomainName"):
            cert["subjectName"] = c["DomainName"]
        if c.get("Issuer"):
            cert["issuerName"] = c["Issuer"]
        if c.get("NotBefore"):
            cert["notValidBefore"] = _iso(c["NotBefore"])
        if c.get("NotAfter"):
            cert["notValidAfter"] = _iso(c["NotAfter"])

        props = [_prop("aws:quantum-vulnerable", str(quantum).lower()),
                 _prop("aws:certificate-type", c.get("Type") or "unknown"),
                 _prop("aws:signature-algorithm", c.get("SignatureAlgorithm")
                       or "unknown")]
        if c.get("InUseBy"):
            props.append(_prop("aws:in-use-by-count", len(c["InUseBy"])))
        out.append({
            "type": CRYPTO_ASSET, "bom-ref": f"acm/{arn}",
            "name": c.get("DomainName") or arn,
            "cryptoProperties": {"assetType": "certificate",
                                 "certificateProperties": cert},
            "properties": props,
        })
    return list(seen_algos.values()) + out


# ── negotiated TLS ──────────────────────────────────────────────────────────
def tls_components(endpoints: Optional[Sequence[dict]]) -> List[dict]:
    """TLS endpoints as ``protocol`` components.

    ``endpoints`` are ``{"ref": ..., "name": ..., "policy": ..., "version": ...}`` dicts
    assembled by the caller from listener/distribution/domain configuration. ``version``
    is echoed verbatim rather than parsed out of the policy name: AWS policy names encode
    a minimum, and inferring the negotiated version from a policy string would be a guess
    dressed as a reading."""
    out: List[dict] = []
    for e in endpoints or []:
        if not isinstance(e, dict) or not e.get("ref"):
            continue
        proto: Dict[str, Any] = {"type": "tls"}
        if e.get("version"):
            proto["version"] = str(e["version"])
        props = [_prop("aws:tls-policy", e.get("policy") or "unknown")]
        if e.get("service"):
            props.append(_prop("aws:service", e["service"]))
        out.append({
            "type": CRYPTO_ASSET, "bom-ref": str(e["ref"]),
            "name": e.get("name") or str(e["ref"]),
            "cryptoProperties": {"assetType": "protocol",
                                 "protocolProperties": proto},
            "properties": props,
        })
    return out


# ── the document ────────────────────────────────────────────────────────────
def _iso(v: Any) -> str:
    """A datetime or string rendered as an ISO-8601 string."""
    if hasattr(v, "isoformat"):
        s = v.isoformat()
        return s if s.endswith("Z") or "+" in s else s + "Z"
    return str(v)


def build_cbom(*, account: str = "", region: str = "", generated_at: str = "",
               kms_keys: Optional[Sequence[dict]] = None,
               certificates: Optional[Sequence[dict]] = None,
               tls_endpoints: Optional[Sequence[dict]] = None,
               tool_version: str = "") -> dict:
    """Assemble the CycloneDX 1.6 CBOM.

    ``generated_at`` is injected rather than read from the clock, so two runs over the
    same estate produce byte-identical documents and a diff means a change in the estate.
    The same discipline the demo-data seeder needed after a flaky test caught it."""
    components: List[dict] = []
    components += kms_components(kms_keys)
    components += acm_components(certificates)
    components += tls_components(tls_endpoints)

    vulnerable = [c for c in components
                  if any(p["name"] == "aws:quantum-vulnerable" and p["value"] == "true"
                         for p in c.get("properties", []))]

    meta: Dict[str, Any] = {
        "tools": {"components": [{"type": "application", "name": "OverWatch",
                                  "version": tool_version or "unknown"}]},
        "properties": [
            _prop("aws:account", account or "unknown"),
            _prop("aws:region", region or "all"),
            _prop("aws:quantum-vulnerable-assets", len(vulnerable)),
            _prop("aws:total-crypto-assets", len(components)),
            # Stated in the document rather than implied by omission. An agentless
            # scanner cannot see crypto inside a workload, and a CBOM that does not say
            # so reads as a complete inventory to anyone who did not build it.
            _prop("aws:scope",
                  "AWS-managed cryptography exposed through configuration APIs "
                  "(KMS, ACM, TLS endpoints). Application-level cryptography inside "
                  "workloads is not visible to an agentless scan and is NOT included."),
        ],
    }
    if generated_at:
        meta["timestamp"] = generated_at

    return {"bomFormat": BOM_FORMAT, "specVersion": SPEC_VERSION, "version": 1,
            "metadata": meta, "components": components}


def quantum_exposure(cbom: Optional[dict]) -> dict:
    """The one question a CBOM exists to answer, extracted from it.

    Deliberately not a finding. RSA-2048 and P-256 are the correct choice today and the
    wrong choice eventually; what an operator needs is the count, the names, and the
    dates — so a migration can be planned against a horizon they choose rather than one
    a scanner asserts."""
    comps = (cbom or {}).get("components") or []
    vulnerable = [c for c in comps
                  if any(p["name"] == "aws:quantum-vulnerable" and p["value"] == "true"
                         for p in c.get("properties", []))]
    by_kind: Dict[str, int] = {}
    for c in vulnerable:
        kind = (c.get("cryptoProperties") or {}).get("assetType", "unknown")
        by_kind[kind] = by_kind.get(kind, 0) + 1
    return {
        "total": len(comps),
        "quantum_vulnerable": len(vulnerable),
        "by_asset_type": by_kind,
        "names": sorted(c.get("name", "") for c in vulnerable)[:20],
    }

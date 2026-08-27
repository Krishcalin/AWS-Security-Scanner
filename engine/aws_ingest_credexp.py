#!/usr/bin/env python3
"""aws_ingest_credexp.py — leaked-credential exposure, ingested and joined to identity.

Breach-corpus services (DeHashed and its peers) know something OverWatch structurally
cannot: that a credential belonging to somebody in this organisation is sitting in a
public compilation. OverWatch knows something they cannot: what that identity can reach
in this AWS estate. Neither half is worth much alone -- an email in a 2019 dump is noise
without knowing it belongs to an account with admin, and an over-privileged identity is a
theoretical risk until you learn its password is in a stealer log. This module is the join.

THREE DESIGN DECISIONS, EACH OF WHICH COULD HAVE GONE WRONG
-----------------------------------------------------------

1. **THIS MODULE MAKES NO NETWORK CALLS, AND THAT IS NOT AN OVERSIGHT.**
   ``tests/test_zero_telemetry.py`` allows egress primitives in exactly three files.
   Adding a fourth to poll a breach API would widen the tripwire that is OverWatch's
   most load-bearing claim, and it would push a decision onto the product that belongs
   to the operator: *querying a breach service for "does anyone at acme.com appear in
   your corpus" sends acme.com's people to a third party.* That is real egress of real
   PII, and it is not the scanner's call to make. So the operator runs the query, and
   hands the result here. If they want it automated, the connector plane already exists,
   is already allowlisted, and is already SSRF-guarded -- that is the place for it, not
   a new hole.

2. **CREDENTIAL MATERIAL NEVER ENTERS THE PRODUCT.** Breach records carry plaintext
   passwords. A security tool that stores them becomes a credential honeypot -- a worse
   outcome than the risk it was reporting, and a far more attractive target. Following
   the ``aws_ingest_pentest`` precedent, this is structural rather than a denylist the
   next field walks past: :func:`normalize` builds a NEW record containing only the
   fields named in :data:`_KEEP`, so a field nobody anticipated cannot arrive by being
   forgotten. Passwords are reduced to a salted digest, which is enough to answer "is
   this the same secret as that one" and useless to anyone who steals the database.

3. **A HIT IS NOT A COMPROMISE, AND THE FINDINGS SAY SO.** A breach record is a third
   party's claim about a corpus, not an observation of this estate. The password may have
   been rotated years ago; the email may belong to somebody who left; the record may be
   recycled filler that appears in every compilation. So every finding here carries
   ``aws_epistemics.OBSERVED`` for the *breach* (somebody genuinely saw it in a corpus)
   and states plainly that whether the credential still works is unknown. Ranking is by
   what the matched identity can REACH, which OverWatch does know, rather than by the
   breach's own drama.

VENDOR-NEUTRAL BY CONSTRUCTION
-------------------------------
DeHashed's API contract could not be verified: their documentation is behind a bot wall,
and the public wrappers do not publish a schema. Rather than key this module to a shape
that might be wrong, :func:`normalize` accepts a *record* and maps whatever recognised
field names are present, ignoring the rest. A DeHashed export works, a Have I Been Pwned
export works, and a CSV somebody assembled by hand works. This is the same choice
``aws_ingest_aidr`` made when it could not depend on a vendor, and for the same reason.

Pure functions over dicts. No boto3, no network, no I/O.
"""
from __future__ import annotations

import hashlib
import re
from typing import Dict, Iterable, List, Mapping, Optional, Sequence

from engine import aws_epistemics

__all__ = [
    "EXPOSURE_KINDS", "CREDENTIAL_FIELDS", "normalize", "normalize_many",
    "digest_secret", "correlate", "coverage",
]

#: What kind of exposure a record represents. Ranked in the checks by what it implies
#: about credential freshness: a stealer log is malware on a live machine TODAY; a
#: combolist entry may be a decade of recycled filler.
STEALER_LOG = "stealer_log"
BREACH = "breach"
COMBOLIST = "combolist"
UNKNOWN_KIND = "unknown"
EXPOSURE_KINDS = (STEALER_LOG, BREACH, COMBOLIST, UNKNOWN_KIND)

#: Field names that carry credential material. Named here so the REDACTION is auditable
#: and testable, but note that the safety does not depend on this list being complete --
#: `normalize` copies only `_KEEP`, so an unlisted secret field is dropped by default
#: rather than by recognition. This list exists to decide what gets DIGESTED, not what
#: gets excluded.
CREDENTIAL_FIELDS = (
    "password", "hashed_password", "hash", "passwd", "pass", "plaintext",
    "cleartext", "secret", "token", "cookie", "session",
)

#: The ONLY fields that survive normalization. Everything else -- including anything a
#: future API version adds -- is dropped. An allowlist is the difference between "we
#: filtered the secrets we thought of" and "secrets cannot get in".
_KEEP = ("email", "username", "domain", "ip_address", "source", "kind",
         "breach_date", "access_key_id", "record_id")

_AKIA = re.compile(r"\b((?:AKIA|ASIA|AIDA|AROA|ANPA|ANVA|APKA)[A-Z0-9]{12,})\b")
_EMAIL = re.compile(r"^[^@\s]+@([^@\s]+\.[^@\s]+)$")

#: Source strings that indicate malware on a live endpoint rather than an old dump.
_STEALER_HINTS = ("stealer", "redline", "raccoon", "vidar", "lumma", "meta stealer",
                  "azorult", "infostealer", "logs")


def digest_secret(secret: Optional[str], *, salt: str = "") -> Optional[str]:
    """A salted digest of credential material, or None.

    Enough to answer "is this the same secret twice"; useless to anyone who exfiltrates
    the database. The salt is the operator's -- an unsalted digest of a common password
    is trivially reversed by rainbow table, which would leave the plaintext effectively
    present after all. An absent salt is therefore recorded in `coverage` as a weakness
    rather than silently accepted."""
    if not secret or not isinstance(secret, str):
        return None
    return "sha256:" + hashlib.sha256((salt + secret).encode("utf-8")).hexdigest()


def _kind_of(rec: Mapping) -> str:
    blob = " ".join(str(rec.get(k) or "") for k in ("kind", "source", "database_name",
                                                    "obtained_from", "breach")).lower()
    if any(h in blob for h in _STEALER_HINTS):
        return STEALER_LOG
    if "combo" in blob:
        return COMBOLIST
    if blob.strip():
        return BREACH
    return UNKNOWN_KIND


def normalize(record: Optional[Mapping], *, salt: str = "") -> Optional[dict]:
    """One vendor record -> one neutral exposure, with credential material removed.

    Builds a NEW dict from `_KEEP` rather than copying and deleting. That ordering is the
    whole safety property: a field this module has never heard of cannot survive by being
    unrecognised, which is exactly how a naive filter leaks the next API version's
    `password_plaintext_v2`.

    Returns None for a record with nothing to join on -- an exposure with no email, no
    username and no key id cannot be attributed to anybody and is not worth storing.
    """
    if not isinstance(record, Mapping):
        return None

    src = {str(k).lower(): v for k, v in record.items()}
    out: Dict[str, object] = {}

    for field in _KEEP:
        v = src.get(field)
        if isinstance(v, (str, int)) and str(v).strip():
            out[field] = str(v).strip()

    # Common aliases across vendors, mapped rather than assumed.
    if "email" not in out:
        for alias in ("email_address", "mail", "user_email"):
            if src.get(alias):
                out["email"] = str(src[alias]).strip()
                break
    if "username" not in out:
        for alias in ("user", "login", "handle", "name"):
            if src.get(alias):
                out["username"] = str(src[alias]).strip()
                break
    if "ip_address" not in out:
        for alias in ("ip", "ipaddress", "client_ip"):
            if src.get(alias):
                out["ip_address"] = str(src[alias]).strip()
                break
    if "source" not in out:
        for alias in ("database_name", "breach", "obtained_from", "origin"):
            if src.get(alias):
                out["source"] = str(src[alias]).strip()
                break

    # Derive the domain from the email rather than trusting a supplied one -- the join
    # to an estate is by domain, and a record whose `domain` disagrees with its `email`
    # would attribute an exposure to the wrong organisation.
    email = str(out.get("email") or "")
    m = _EMAIL.match(email)
    if m:
        out["domain"] = m.group(1).lower()
        out["email"] = email.lower()
    elif "domain" in out:
        out["domain"] = str(out["domain"]).lower()

    # An AWS key id may arrive in its own field or embedded in free text. Scanning the
    # ORIGINAL record for it is safe: a key id is an identifier, not a secret, and it is
    # the single most actionable thing a breach corpus can contain for a cloud estate.
    if "access_key_id" not in out:
        blob = " ".join(str(v) for v in record.values() if isinstance(v, str))
        km = _AKIA.search(blob)
        if km:
            out["access_key_id"] = km.group(1)

    out["kind"] = _kind_of(record)

    # Digest whatever credential material was present, then let the plaintext fall out of
    # scope with `src`. `has_password` is what the findings actually reason about.
    digest = None
    for field in CREDENTIAL_FIELDS:
        if src.get(field):
            digest = digest_secret(str(src[field]), salt=salt)
            break
    out["secret_digest"] = digest
    out["has_password"] = digest is not None
    out["salted"] = bool(salt) if digest else None

    if not (out.get("email") or out.get("username") or out.get("access_key_id")):
        return None
    return out


def normalize_many(records: Optional[Iterable[Mapping]], *, salt: str = "") -> List[dict]:
    """Normalize a feed, dropping unattributable records. Order is preserved."""
    return [n for n in (normalize(r, salt=salt) for r in (records or [])) if n]


def _principal_identifiers(principal: Mapping) -> Dict[str, str]:
    """The identifiers an exposure can be matched against, lowercased."""
    out = {}
    for key, field in (("name", "name"), ("email", "email"), ("user_name", "name")):
        v = principal.get(key)
        if isinstance(v, str) and v.strip():
            out[field] = v.strip().lower()
    return out


def correlate(exposures: Optional[Sequence[Mapping]],
              principals: Optional[Sequence[Mapping]],
              *, estate_domains: Sequence[str] = (),
              known_key_ids: Sequence[str] = ()) -> List[dict]:
    """Join exposures to the identities they name.

    `principals` are the estate's IAM principals; `known_key_ids` are live access key ids
    IF the caller collected them. Matching is exact on lowercased email, username and key
    id -- never fuzzy. A near-match on a name would attribute somebody else's breach to
    this estate, and an attribution nobody can check is worse than a gap somebody can.
    """
    keys = {str(k).strip() for k in known_key_ids if str(k).strip()}
    domains = {str(d).strip().lower().lstrip("@") for d in estate_domains if str(d).strip()}

    index: Dict[str, List[dict]] = {}
    for p in principals or []:
        for ident in _principal_identifiers(p).values():
            index.setdefault(ident, []).append(dict(p))

    out: List[dict] = []
    for e in exposures or []:
        matched: List[dict] = []
        how = None
        kid = e.get("access_key_id")
        if kid and kid in keys:
            matched = [{"kind": "AccessKey", "name": kid}]
            how = "access_key_id"
        if not matched:
            for field in ("email", "username"):
                v = e.get(field)
                if isinstance(v, str) and v.lower() in index:
                    matched = index[v.lower()]
                    how = field
                    break
        in_estate_domain = bool(domains) and str(e.get("domain") or "") in domains
        if not matched and not in_estate_domain:
            continue                                  # not ours; nothing to say about it
        out.append({
            "exposure": dict(e),
            "principals": matched,
            "matched_on": how,
            "domain_match_only": bool(not matched and in_estate_domain),
        })
    return out


def coverage(exposures: Optional[Sequence[Mapping]],
             *, known_key_ids: Sequence[str] = (),
             estate_domains: Sequence[str] = (),
             salt: str = "") -> dict:
    """What this ingest could NOT determine, stated rather than left as silence.

    Three gaps matter enough to name, because each makes an absence of findings mean
    something different from "you are clean":

    * no key inventory -> a leaked AWS key cannot be matched to a live one, which is the
      single most actionable thing in the whole corpus;
    * no estate domains -> exposures can only be matched to principals by exact identifier,
      so an employee's personal-looking address is invisible;
    * no digest salt -> stored digests of common passwords are reversible by rainbow
      table, so the redaction is weaker than it looks.
    """
    notes: List[str] = []
    exp = list(exposures or [])
    leaked_keys = [e for e in exp if e.get("access_key_id")]
    if leaked_keys and not known_key_ids:
        notes.append(
            f"{len(leaked_keys)} exposure(s) carry an AWS access key id, but no live key "
            f"inventory was supplied, so none could be matched against this account. "
            f"That is the highest-value join available here and it did not happen -- it "
            f"is not a finding that the keys are unused.")
    if not estate_domains:
        notes.append(
            "No estate domains were supplied, so exposures were matched only by exact "
            "email or username against known principals. An employee credential under a "
            "different address will not appear.")
    if any(e.get("has_password") for e in exp) and not salt:
        notes.append(
            "Credential digests were computed without a salt. They remain useful for "
            "equality comparison, but a digest of a common password is reversible by "
            "rainbow table, so treat them as pseudonymous rather than as safe.")
    return {
        "total_exposures": len(exp),
        "with_credential": sum(1 for e in exp if e.get("has_password")),
        "with_access_key": len(leaked_keys),
        "not_evaluated": notes,
        "provenance": aws_epistemics.OBSERVED,
        "provenance_note": (
            "A breach record is a third party's OBSERVATION of a corpus -- somebody "
            "genuinely saw this data in a compilation. It is NOT an observation of this "
            "estate, and it does not establish that the credential still works, that the "
            "person still holds the account, or that anyone has used it. Rank these by "
            "what the matched identity can reach, which this product does know."),
    }

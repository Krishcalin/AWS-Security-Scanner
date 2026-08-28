"""The three things that stood between this build and a production rollout.

Each was safe-but-unusable or safe-but-silent, and none of them was visible from
a green test suite:

  1. build_service() wired the secret seams to a function that RAISES, so a real
     deployment could not onboard an account or create a connector at all.
  2. The image's CMD was create_app_from_env, whose current_principal is None =>
     every route 403. Correct, and indistinguishable from a broken deployment.
  3. The session cookie's Secure flag followed request.url.scheme, which behind a
     TLS-terminating proxy is "http".

They are pinned here because all three are CONFIGURATION, and configuration is
exactly what a unit test usually cannot see.
"""
from __future__ import annotations

import os

import pytest

from hub import cnapp_authn_api, cnapp_secrets, cnapp_server


# ── a Secrets Manager double ───────────────────────────────────────────────

class ResourceExistsException(Exception):
    pass


class FakeSecretsManager:
    """Enough of the API surface to exercise create / rotate / read / ownership."""

    def __init__(self, existing=None):
        self.secrets = dict(existing or {})     # name -> {"value","tags"}
        self.calls = []

    def create_secret(self, **kw):
        self.calls.append(("create", kw.get("Name")))
        if kw["Name"] in self.secrets:
            raise ResourceExistsException(kw["Name"])
        self.secrets[kw["Name"]] = {
            "value": kw["SecretString"],
            "tags": list(kw.get("Tags") or []),
            "kms": kw.get("KmsKeyId"),
        }
        return {"ARN": "arn:aws:secretsmanager:::secret:" + kw["Name"]}

    def describe_secret(self, SecretId):
        self.calls.append(("describe", SecretId))
        if SecretId not in self.secrets:
            raise KeyError(SecretId)
        return {"Tags": self.secrets[SecretId]["tags"]}

    def put_secret_value(self, SecretId, SecretString):
        self.calls.append(("put", SecretId))
        self.secrets[SecretId]["value"] = SecretString
        return {}

    def get_secret_value(self, SecretId):
        self.calls.append(("get", SecretId))
        if SecretId not in self.secrets:
            raise KeyError(SecretId)
        return {"SecretString": self.secrets[SecretId]["value"]}


def _seams(fake, **kw):
    return (cnapp_secrets.make_writer(lambda: fake, **kw),
            cnapp_secrets.make_reader(lambda: fake))


# ── 1. the secret store ────────────────────────────────────────────────────

def test_a_written_secret_round_trips_through_its_reference():
    fake = FakeSecretsManager()
    write, read = _seams(fake)
    ref = write("123456789012", "an-external-id-value")
    assert ref.startswith("secretsmanager://")
    assert read(ref) == "an-external-id-value"


def test_the_reference_never_contains_the_secret():
    """The whole point of a ref: it is what gets persisted in the hub DB."""
    fake = FakeSecretsManager()
    write, _ = _seams(fake)
    ref = write("conn-abc123", "a-very-secret-token-value")
    assert "a-very-secret-token-value" not in ref


def test_rotation_updates_in_place_rather_than_failing():
    """cnapp_connectors' rotate-secret re-writes the SAME scope id."""
    fake = FakeSecretsManager()
    write, read = _seams(fake)
    first = write("conn-abc123", "token-one-original")
    second = write("conn-abc123", "token-two-rotated")
    assert first == second
    assert read(second) == "token-two-rotated"
    assert ("put", "overwatch/conn-abc123") in fake.calls


def test_it_refuses_to_overwrite_a_secret_it_did_not_create():
    """The provenance guard. A name collision with an operator's OWN secret must
    not silently replace their value -- the rule is "OverWatch mutates only
    resources it created", the same one aws_sidescan_ebs.is_owned() enforces."""
    fake = FakeSecretsManager(existing={
        "overwatch/conn-abc123": {"value": "someone-elses", "tags": [], "kms": None}})
    write, _ = _seams(fake)
    with pytest.raises(cnapp_secrets.SecretStoreError) as exc:
        write("conn-abc123", "our-new-token-value")
    assert "not tagged" in str(exc.value)
    assert fake.secrets["overwatch/conn-abc123"]["value"] == "someone-elses"


def test_a_secret_we_created_carries_the_ownership_tag():
    fake = FakeSecretsManager()
    write, _ = _seams(fake)
    write("conn-abc123", "a-token-value-here")
    tags = fake.secrets["overwatch/conn-abc123"]["tags"]
    assert {"Key": cnapp_secrets.OWNER_TAG_KEY,
            "Value": cnapp_secrets.OWNER_TAG_VALUE} in tags


def test_an_unverifiable_owner_refuses_rather_than_overwrites():
    """If DescribeSecret fails (AccessDenied, throttling), the safe answer is to
    refuse. An ownership check that fails OPEN is not a check."""
    class Blind(FakeSecretsManager):
        def describe_secret(self, SecretId):
            raise RuntimeError("AccessDeniedException")

    fake = Blind(existing={"overwatch/conn-x": {"value": "theirs", "tags": [],
                                                "kms": None}})
    write, _ = _seams(fake)
    with pytest.raises(cnapp_secrets.SecretStoreError) as exc:
        write("conn-x", "our-token-value")
    assert "refusing to overwrite" in str(exc.value)


def test_a_botocore_error_never_carries_the_secret_into_the_message():
    """The create request body IS the secret, so a raw driver error is not safe
    to surface."""
    class Boom(FakeSecretsManager):
        def create_secret(self, **kw):
            raise RuntimeError("ValidationError: request was %s" % kw["SecretString"])

    write, _ = _seams(Boom())
    with pytest.raises(cnapp_secrets.SecretStoreError) as exc:
        write("conn-y", "super-secret-token")
    assert "super-secret-token" not in str(exc.value)


def test_an_ssm_reference_is_refused_with_the_configured_backend_named():
    _, read = _seams(FakeSecretsManager())
    with pytest.raises(cnapp_secrets.SecretStoreError) as exc:
        read("ssm://some/param")
    assert "Secrets Manager" in str(exc.value)


def test_a_schemeless_reference_is_never_echoed_back():
    """A ref with no scheme would BE the raw secret; the message must not repeat
    it. Same rule as cnapp_onboarding.resolve_external_id."""
    _, read = _seams(FakeSecretsManager())
    with pytest.raises(cnapp_secrets.SecretStoreError) as exc:
        read("this-is-actually-the-raw-secret")
    assert "this-is-actually-the-raw-secret" not in str(exc.value)


def test_a_hostile_scope_id_cannot_escape_the_prefix():
    fake = FakeSecretsManager()
    write, _ = _seams(fake)
    for bad in ("../other/secret", "a/b", "", "x" * 400):
        with pytest.raises(cnapp_secrets.SecretStoreError):
            write(bad, "a-token-value-here")


def test_unconfigured_means_no_store_rather_than_a_fallback():
    assert cnapp_secrets.build_from_env({}) is None
    assert cnapp_secrets.build_from_env({"CNAPP_SECRETS_BACKEND": ""}) is None


def test_configured_yields_a_writer_and_reader():
    seams = cnapp_secrets.build_from_env(
        {"CNAPP_SECRETS_BACKEND": "aws-secrets-manager"},
        client_factory=lambda: FakeSecretsManager())
    assert seams is not None and len(seams) == 2


def test_build_service_still_refuses_when_no_backend_is_configured():
    """Safe default preserved: an unconfigured hub does not quietly acquire a
    store, and does not store plaintext. It refuses at the point of use."""
    env_backup = os.environ.pop("CNAPP_SECRETS_BACKEND", None)
    try:
        writer, reader = cnapp_server._secret_seams()
        with pytest.raises(RuntimeError) as exc:
            writer("123456789012", "value")
        assert "configure a secret store" in str(exc.value)
        with pytest.raises(RuntimeError):
            reader("secretsmanager://x")
    finally:
        if env_backup is not None:
            os.environ["CNAPP_SECRETS_BACKEND"] = env_backup


# ── 2. the entry point ─────────────────────────────────────────────────────

def test_an_unset_auth_mode_stops_the_process_instead_of_serving_403():
    """The old CMD served a 403 wall, which reads like a permissions bug rather
    than an unconfigured one."""
    backup = os.environ.pop("CNAPP_AUTH_MODE", None)
    try:
        with pytest.raises(SystemExit) as exc:
            cnapp_server.create_app()
        message = str(exc.value)
        assert "CNAPP_AUTH_MODE" in message
        assert "local" in message and "idp" in message
    finally:
        if backup is not None:
            os.environ["CNAPP_AUTH_MODE"] = backup


def test_the_image_entry_point_is_the_selecting_factory():
    """A Dockerfile CMD naming create_app_from_env is a 403 wall out of the box."""
    import io
    with io.open("Dockerfile", encoding="utf-8") as fh:
        dockerfile = fh.read()
    assert "hub.cnapp_server:create_app" in dockerfile
    assert "hub.cnapp_server:create_app_from_env" not in dockerfile


def test_both_original_factories_are_untouched_and_still_exported():
    """create_app only CHOOSES. An operator fronting the hub with their own IdP
    keeps using create_app_from_env exactly as before."""
    assert callable(cnapp_server.create_app_from_env)
    assert callable(cnapp_server.create_app_with_local_auth)


# ── 3. the session cookie ──────────────────────────────────────────────────

class _Req:
    def __init__(self, scheme):
        self.url = type("U", (), {"scheme": scheme})()


@pytest.mark.parametrize("mode,scheme,expected", [
    (None, "https", True),        # auto: TLS terminated at the app
    (None, "http", False),        # auto: the local dev stack
    ("auto", "http", False),
    ("always", "http", True),     # the production case: TLS ends at the proxy
    ("always", "https", True),
    ("never", "https", False),
])
def test_the_secure_flag_follows_the_configured_mode(mode, scheme, expected):
    backup = os.environ.pop("CNAPP_COOKIE_SECURE", None)
    try:
        if mode is not None:
            os.environ["CNAPP_COOKIE_SECURE"] = mode
        assert cnapp_authn_api._cookie_secure(_Req(scheme)) is expected
    finally:
        os.environ.pop("CNAPP_COOKIE_SECURE", None)
        if backup is not None:
            os.environ["CNAPP_COOKIE_SECURE"] = backup


def test_the_cookie_is_still_httponly_and_samesite():
    """The other two flags were already right; changing the Secure logic must not
    disturb them."""
    import io

    from _layout import module_path
    with io.open(module_path("cnapp_authn_api.py"), encoding="utf-8") as fh:
        src = fh.read()
    assert "httponly=True" in src
    assert 'samesite="lax"' in src
    assert "secure=_cookie_secure(request)" in src

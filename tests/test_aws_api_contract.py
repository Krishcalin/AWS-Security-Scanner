"""The AWS API contract, checked against the only description of it nobody here wrote.

THE GAP THIS FILLS. `docs/CHECK_FIRING.md` proves a check can produce a finding. It
cannot prove the finding is about anything real, because every AWS response in the suite
is a mock — written by whoever wrote the check, and therefore encoding the same
understanding of the API. If that understanding is wrong, the check and its test agree
with each other and both are wrong together. No amount of test coverage of that shape
detects it.

botocore ships AWS's own service models: for every operation, the exact name and the
exact members of its output shape. They are already on disk (botocore is a pinned
dependency), they need no credentials, and they are authored by AWS. That makes them the
one available oracle.

WHAT IT FOUND ON ITS FIRST RUN. `_check_wickr` read `networkSettings` from
`wickr:GetNetworkSettings`. The operation has no such member — it returns `settings`, and
returns it as a LIST of `{optionName, value, type}` pairs rather than the nested object
the code and its fixture both assumed. So WKR-01 received `{}` on every real scan and
could never fire, while its unit tests passed against a shape AWS has never sent.

WHAT IT DOES NOT CLAIM. This checks names and top-level response members. It cannot
check semantics, nested shapes below the first level, values, or whether a field is
populated in practice — that needs a real account, which is what
`scripts/validate_live.py` is for. It is the cheap half, and the cheap half found a bug.
"""
from __future__ import annotations

import ast
import io
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCANNER = os.path.join(ROOT, "engine", "aws_live_scanner.py")

botocore = pytest.importorskip(
    "botocore", reason="botocore ships the AWS service models this file checks against")
from botocore import xform_name                                       # noqa: E402
import botocore.session                                               # noqa: E402

_SESSION = botocore.session.get_session()
_MODELS: dict = {}
_METHODS: dict = {}


def _method_table(service: str):
    """python method name -> operation name, using botocore's OWN transform.

    Deriving it by hand is where a naive version of this test goes wrong: a
    snake_case→PascalCase guess turns `describe_db_clusters` into `DescribeDbClusters`
    and misses the real `DescribeDBClusters`, producing dozens of false positives on
    every acronym in AWS. `xform_name` is the function botocore itself uses to build
    client methods, so the mapping is exact by construction."""
    if service not in _METHODS:
        try:
            model = _SESSION.get_service_model(service)
        except Exception:
            _MODELS[service] = None
            _METHODS[service] = None
        else:
            _MODELS[service] = model
            _METHODS[service] = {xform_name(op): op for op in model.operation_names}
    return _METHODS[service]


def _output_members(service: str, method: str):
    table = _method_table(service)
    if not table or method not in table:
        return None
    shape = _MODELS[service].operation_model(table[method]).output_shape
    return set(shape.members) if shape is not None else set()


#: Attributes that are not AWS operations.
_NOT_OPERATIONS = {"get_paginator", "can_paginate", "exceptions", "meta"}


def _unwrap(node):
    """Peel `(X or {})` down to X — the codebase's standard defensive idiom."""
    while isinstance(node, ast.BoolOp) and isinstance(node.op, ast.Or):
        node = node.values[0]
    return node


def _client_vars(fn):
    """var -> service for `x = self._client("svc")`, scoped to ONE function.

    Scoping matters: `elb` is bound to the `elbv2` client in one method and to the
    classic `elb` client in another. Unioning them across the module makes every
    elbv2 call look like an invalid classic-ELB call and vice versa."""
    local = {}
    for n in ast.walk(fn):
        if not (isinstance(n, ast.Assign) and len(n.targets) == 1
                and isinstance(n.targets[0], ast.Name)):
            continue
        v = n.value
        if (isinstance(v, ast.Call) and isinstance(v.func, ast.Attribute)
                and v.func.attr == "_client" and v.args
                and isinstance(v.args[0], ast.Constant)):
            local[n.targets[0].id] = v.args[0].value
    return local


def _functions():
    tree = ast.parse(io.open(SCANNER, encoding="utf-8").read())
    for fn in ast.walk(tree):
        if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            local = _client_vars(fn)
            if local:
                yield fn, local


def _resolve(call, local):
    """(service, method) if `call` is an AWS client call in this scope, else None."""
    call = _unwrap(call)
    if not (isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute)
            and isinstance(call.func.value, ast.Name)):
        return None
    service = local.get(call.func.value.id)
    if service is None or call.func.attr in _NOT_OPERATIONS:
        return None
    return service, call.func.attr


def test_every_service_the_scanner_asks_for_exists():
    """A typo in a service name is an ImportError-shaped failure that only appears in
    production, because nothing in the suite ever builds a real client."""
    unknown = set()
    for _fn, local in _functions():
        for service in local.values():
            if _method_table(service) is None:
                unknown.add(service)
    assert not unknown, (
        "these service names have no botocore model, so `self._client(...)` will raise "
        "against real AWS: %s" % sorted(unknown))


def test_every_operation_the_scanner_calls_is_a_real_operation():
    offenders = []
    checked = 0
    for fn, local in _functions():
        for n in ast.walk(fn):
            if not (isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                    and isinstance(n.func.value, ast.Name)):
                continue
            got = _resolve(n, local)
            if got is None:
                continue
            service, method = got
            table = _method_table(service)
            if table is None:
                continue
            checked += 1
            if method not in table:
                offenders.append(f"{fn.name}: {service}.{method}()")
    assert checked > 200, (
        "only %d client calls were resolved — the analysis stopped seeing the code it "
        "is meant to check, which would make this test pass vacuously" % checked)
    assert not offenders, (
        "these are not operations of the service they are called on, so they raise "
        "against real AWS: %s" % sorted(offenders))


def test_every_response_key_read_exists_in_the_output_shape():
    """The half that mocks structurally cannot catch.

    A mock returns whatever the test author typed, so a key that AWS never sends looks
    identical to one it does. This compares each key against the operation's declared
    output members."""
    offenders = []
    checked = 0
    for fn, local in _functions():
        for n in ast.walk(fn):
            key = target = None
            if (isinstance(n, ast.Subscript) and isinstance(n.slice, ast.Constant)
                    and isinstance(n.slice.value, str)):
                key, target = n.slice.value, n.value
            elif (isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                  and n.func.attr == "get" and n.args
                  and isinstance(n.args[0], ast.Constant)
                  and isinstance(n.args[0].value, str)):
                key, target = n.args[0].value, n.func.value
            if key is None:
                continue
            got = _resolve(target, local)
            if got is None:
                continue
            members = _output_members(*got)
            if members is None:
                continue
            checked += 1
            if key not in members:
                offenders.append(
                    "%s: %s.%s() has no %r (members: %s)"
                    % (fn.name, got[0], got[1], key,
                       ", ".join(sorted(members)) or "none"))
    assert checked > 150, (
        "only %d response-key reads were resolved; the analysis has drifted off the "
        "code" % checked)
    assert not offenders, (
        "these keys are read from AWS responses that do not contain them, so the value "
        "is always absent and the check silently sees nothing: %s" % sorted(offenders))


def test_paginator_result_keys_exist_in_the_output_shape():
    """`get_paginator("op")` pages carry the same members as the operation's output, so
    a key read off a page is checkable the same way."""
    offenders = []
    checked = 0
    for fn, local in _functions():
        # BOTH forms matter. Most of the codebase writes the inline
        # `for page in client.get_paginator("op").paginate():`, and only some bind it to
        # a name first — looking for the assignment alone saw a third of them.
        for n in ast.walk(fn):
            if not (isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                    and n.func.attr == "get_paginator" and n.args
                    and isinstance(n.args[0], ast.Constant)
                    and isinstance(n.func.value, ast.Name)):
                continue
            service = local.get(n.func.value.id)
            if not service:
                continue
            method = n.args[0].value
            table = _method_table(service)
            if table is None:
                continue
            checked += 1
            if method not in table:
                offenders.append(
                    f"{fn.name}: {service}.get_paginator({method!r}) — not an "
                    f"operation of {service}")
                continue
            # Paginability lives in the service's paginator config, not the operation
            # model; `get_paginator` raises PaginationError for an unpaginated op,
            # which is exactly what boto3 does at runtime.
            try:
                _SESSION.get_paginator_model(service).get_paginator(table[method])
            except Exception:
                offenders.append(
                    f"{fn.name}: {service}.{method} is not paginable, so "
                    f"client.get_paginator({method!r}) raises against real AWS")
    assert checked >= 30, (
        "only %d paginator constructions resolved; the analysis has drifted off the "
        "code" % checked)
    assert not offenders, sorted(offenders)


def test_boto3_is_installed_so_the_client_factory_is_actually_exercised():
    """WHY THIS IS AN ASSERTION AND NOT A SKIP. `HAS_BOTO3` gates `_client()` entirely.
    With boto3 absent the suite still passes ~6000 tests, but every AWS client is a
    MagicMock injected straight into `_clients` and the factory — session handling,
    region plumbing, the retry config — is never executed. The suite silently tests a
    different program. boto3 is a pinned dependency in requirements.txt; a run without
    it is a weaker run and should say so rather than quietly proceed."""
    from engine.aws_live_scanner import HAS_BOTO3
    assert HAS_BOTO3, (
        "boto3 is not installed, so `_client()` is unreachable and the client factory "
        "has no coverage in this run. Install the pinned version: "
        "pip install -r requirements.txt")

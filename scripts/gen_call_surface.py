#!/usr/bin/env python3
"""Derive every AWS API the engine can call, and the IAM action each one needs.

    python scripts/gen_call_surface.py --update   # rewrite tests/call_surface_baseline.py
    python scripts/gen_call_surface.py --check    # CI: fail if stale
    python scripts/gen_call_surface.py --missing  # actions the shipped role does not name

WHY THIS EXISTS
---------------
`deploy/cnapp-scanner-role.yaml` says it plainly: *"a check that silently degrades
to a coverage note in every real deployment is worse than one that asks for the
grant it needs."* Acting on that requires knowing what the scanner actually calls,
and until now nobody did — the role named 124 actions while the engine called 295,
and the difference was an assumption about what the SecurityAudit and
ViewOnlyAccess managed policies happen to cover. Six DRS and AWS Backup actions
shipped with no grant anywhere, which is how the gap was found.

The inventory is DERIVED, never typed. Two facts make that trustworthy:

* **The IAM prefix comes from botocore**, `metadata.signingName` falling back to
  `endpointPrefix` — never from the boto3 client name. That mistake has been made
  six times in this repository (`sso-admin` vs `sso`, `amp` vs `aps`,
  `bedrock-agentcore-control` vs `bedrock-agentcore`, `emr` vs `elasticmapreduce`,
  `cloudhsmv2` vs `cloudhsm`, CodeGuru Profiler's hyphen) and each one produces a
  policy that grants nothing while reading correctly in review. Resolving it from
  the shipped model catches the seventh for all 105 services at once.
* **The operation name comes from botocore too**, so a call this file cannot match
  to a real operation is dropped rather than guessed at.

WHAT IT DOES NOT CLAIM
----------------------
This answers "may the role make this call", not "which check needs it". Per-check
attribution lives in `engine/aws_perm_ledger.py`, is hand-authored against call
sites, and covers the AI pillar. The two are complementary: the ledger is what a
reviewer reads to decline a single grant on the merits; this is what stops a call
from having no grant at all.
"""
from __future__ import annotations

import argparse
import ast
import glob
import gzip
import io
import json
import os
import re
import sys
from collections import defaultdict

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

ENGINE = os.path.join(ROOT, "engine")
CFN = os.path.join(ROOT, "deploy", "cnapp-scanner-role.yaml")

#: Committed under tests/ rather than engine/, alongside `perm_ledger_baseline.py`
#: and for the same reason: it is generated build data, not something production
#: imports. Putting it in engine/ would make it a module nothing reaches, which
#: `test_unreached_modules` correctly refuses -- and the honest answer to that test
#: is that this IS a baseline, not a library.
OUT = os.path.join(ROOT, "tests", "call_surface_baseline.py")

#: Read verbs. The charter is read-only-of-CONFIG; anything else is a violation and
#: is reported rather than written out.
READ_VERBS = ("Describe", "Get", "List", "BatchGet", "Lookup", "Select", "Search",
              "Simulate", "Generate", "Head")


# ── botocore, read rather than recalled ─────────────────────────────────────
def _snake(name: str) -> str:
    out = []
    for i, ch in enumerate(name):
        if ch.isupper() and i and not (name[i - 1].isupper()
                                       and (i + 1 >= len(name) or name[i + 1].isupper())):
            out.append("_")
        out.append(ch.lower())
    return "".join(out)


def load_models():
    """client dir -> IAM prefix, and client dir -> {snake_method: OperationName}."""
    import botocore
    base = os.path.join(os.path.dirname(botocore.__file__), "data")
    prefix, ops = {}, {}
    for svc in sorted(os.listdir(base)):
        d = os.path.join(base, svc)
        if not os.path.isdir(d):
            continue
        try:
            versions = sorted(v for v in os.listdir(d)
                              if os.path.isdir(os.path.join(d, v)))
            f = glob.glob(os.path.join(d, versions[-1], "service-2.json*"))[0]
            opener = gzip.open if f.endswith(".gz") else open
            with opener(f, "rt", encoding="utf-8") as fh:
                model = json.load(fh)
        except Exception:
            continue
        meta = model.get("metadata", {})
        p = meta.get("signingName") or meta.get("endpointPrefix")
        if p:
            prefix[svc] = p
        ops[svc] = {_snake(o): o for o in model.get("operations", {})}
    return prefix, ops


PREFIX, OPS = load_models()


# ── the call finder ─────────────────────────────────────────────────────────
class CallFinder(ast.NodeVisitor):
    """Every `<client>.<operation>()` where the client came from `self._client(...)`.

    FIVE call shapes appear in this codebase, and missing any of them means missing
    a grant -- an under-detected surface is worse than no surface at all, because
    the test built on it passes while a customer gets AccessDenied:

    1. a bound variable -- `bk = self._client("backup")`, then `bk.list_backup_vaults()`
    2. inline -- `self._client("s3").get_bucket_policy(...)`
    3. a bare method reference handed to the pagination helpers --
       `self._tokens(drs.describe_source_servers, ...)`, a call with no parentheses
    4. a client passed to a helper -- `self._audit_agentcore_gateways(ac, ...)`, where
       every AgentCore read happens one frame down. Fifteen `bedrock-agentcore:`
       actions live only here.
    5. `getattr(ac, "get_gateway", None)` -- the optional-API idiom used for services
       whose botocore version may predate an operation.

    Shapes 4 and 5 were found by asserting the converse of the main test: that every
    action the role grants is one the engine can call. Twenty-two grants had no
    visible caller, and all twenty-two turned out to be this blind spot rather than
    unused privilege.
    """

    #: Helper parameters are resolved to a fixpoint; a client can be handed on twice
    #: (_check_agentcore -> _audit_agentcore_gateways -> a grader). Bounded because a
    #: cycle in the call graph would otherwise spin.
    MAX_ROUNDS = 8

    def __init__(self, tree):
        self.tree = tree
        self.par = {c: p for p in ast.walk(tree) for c in ast.iter_child_nodes(p)}
        self.funcs = {n.name: n for n in ast.walk(tree)
                      if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
        self.clients = {}
        self.found = set()

    def _func_of(self, node):
        n = node
        while n in self.par:
            n = self.par[n]
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
                return n
        return None

    def run(self):
        self._seed()
        for _ in range(self.MAX_ROUNDS):
            if not self._propagate():
                break
        self._collect()
        return self.found

    def _seed(self):
        """Direct `x = self._client("svc")` bindings."""
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
                c = node.value
                if (isinstance(c.func, ast.Attribute) and c.func.attr == "_client"
                        and c.args and isinstance(c.args[0], ast.Constant)):
                    fn = self._func_of(node)
                    for t in node.targets:
                        if isinstance(t, ast.Name):
                            self.clients[(fn, t.id)] = c.args[0].value

    def _propagate(self):
        """Bind helper parameters from the clients their callers hand them."""
        added = False
        for node in ast.walk(self.tree):
            if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and isinstance(node.func.value, ast.Name)
                    and node.func.value.id == "self"):
                continue
            target = self.funcs.get(node.func.attr)
            if target is None:
                continue
            caller = self._func_of(node)
            params = [a.arg for a in target.args.args]
            positional = params[1:] if params and params[0] == "self" else params
            pairs = list(zip(positional, node.args))
            pairs += [(kw.arg, kw.value) for kw in node.keywords if kw.arg]
            for param, arg in pairs:
                if not isinstance(arg, ast.Name):
                    continue
                svc = self.clients.get((caller, arg.id))
                if svc and self.clients.get((target, param)) != svc:
                    if (target, param) not in self.clients:
                        self.clients[(target, param)] = svc
                        added = True
        return added

    def _collect(self):
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                svc, meth = self._resolve(node, node.func)
                if svc and meth == "get_paginator" and node.args and \
                        isinstance(node.args[0], ast.Constant):
                    self._record(svc, node.args[0].value)
                elif svc and meth:
                    self._record(svc, meth)
            elif (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                  and node.func.id == "getattr" and len(node.args) >= 2
                  and isinstance(node.args[0], ast.Name)
                  and isinstance(node.args[1], ast.Constant)):
                svc = self.clients.get((self._func_of(node), node.args[0].id))
                if svc:
                    self._record(svc, node.args[1].value)
            elif isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
                svc = self.clients.get((self._func_of(node), node.value.id))
                if svc:
                    self._record(svc, node.attr)

    def _resolve(self, node, f):
        if isinstance(f.value, ast.Name):
            return self.clients.get((self._func_of(node), f.value.id)), f.attr
        if (isinstance(f.value, ast.Call) and isinstance(f.value.func, ast.Attribute)
                and f.value.func.attr == "_client" and f.value.args
                and isinstance(f.value.args[0], ast.Constant)):
            return f.value.args[0].value, f.attr
        return None, None

    def _record(self, svc, meth):
        op = OPS.get(svc, {}).get(meth)
        pre = PREFIX.get(svc)
        if op and pre:
            self.found.add(f"{pre}:{op}")


#: A module may declare calls it makes by NAME rather than by attribute access --
#: `getattr(client, op)` over a table of operations. No AST walk can see those, so
#: the module declares them in `CALL_SURFACE_EXTRA` as "<client>:<snake_operation>"
#: and they are merged here. The seam is deliberately narrow and greppable: an
#: undeclared dynamic call is a missing grant, which is the failure this whole file
#: exists to prevent, and a silent one.
EXTRA_ATTR = "CALL_SURFACE_EXTRA"


def _declared_extras(module_name: str):
    """Import a module ONLY to read its CALL_SURFACE_EXTRA declaration."""
    import importlib
    mod = importlib.import_module(f"engine.{module_name[:-3]}")
    out = set()
    for spec in getattr(mod, EXTRA_ATTR, ()):
        client, _, meth = spec.partition(":")
        op, pre = OPS.get(client, {}).get(meth), PREFIX.get(client)
        if not (op and pre):
            raise SystemExit(
                f"{module_name}: {EXTRA_ATTR} names {spec!r}, which botocore does not "
                f"resolve to an operation on client {client!r}")
        out.add(f"{pre}:{op}")
    return out


def compute():
    """action -> the engine modules that can issue it."""
    surface = defaultdict(set)
    for name in sorted(os.listdir(ENGINE)):
        if not name.endswith(".py") or name == os.path.basename(OUT):
            continue
        src = io.open(os.path.join(ENGINE, name), encoding="utf-8").read()
        try:
            tree = ast.parse(src)
        except SyntaxError:
            continue
        actions = CallFinder(tree).run()
        if EXTRA_ATTR in src:
            actions |= _declared_extras(name)
        for action in actions:
            surface[action].add(name)
    return {a: tuple(sorted(m)) for a, m in sorted(surface.items())}


# ── what the shipped role names ─────────────────────────────────────────────
def role_actions():
    """Every action the CFN names, always-on and opt-in (the latter commented)."""
    raw = io.open(CFN, encoding="utf-8").read()
    active, optin = set(), set()
    for line in raw.splitlines():
        stripped = line.lstrip()
        target = optin if stripped.startswith("#") else active
        for m in re.finditer(r"\b([a-z][a-z0-9-]*:[A-Z][A-Za-z0-9]*)\b", line):
            target.add(m.group(1))
        # inline YAML flow lists in the opt-in comments are unquoted
        for m in re.finditer(r"\b([a-z][a-z0-9-]*:[A-Z][A-Za-z0-9]*)\b", stripped):
            target.add(m.group(1))
    return active, optin


def render(surface) -> str:
    total = len(surface)
    out = [
        '"""Every AWS API the engine can call, and the IAM action each one needs.',
        "",
        "GENERATED by scripts/gen_call_surface.py. Do not hand-edit -- run",
        "``python scripts/gen_call_surface.py --update`` and review the diff.",
        "",
        "The IAM prefix on the left of each colon is botocore's ``signingName`` for the",
        "client the engine opens, NOT the boto3 client name. Those differ for a dozen",
        "services and the difference is invisible in review: a policy naming",
        "``sso-admin:`` or ``amp:`` grants precisely nothing while looking correct. This",
        "repository has made that mistake six times, which is why the table is derived",
        "from the shipped model rather than written down.",
        "",
        "``tests/test_call_surface.py`` holds the ratchet: this file must be current, and",
        "every action in it must be granted by deploy/cnapp-scanner-role.yaml or named in",
        "one of its opt-in blocks. A new API call therefore cannot reach a customer",
        "without a grant -- the failure that put six DRS and AWS Backup reads into a",
        "release with no permission anywhere.",
        '"""',
        "from __future__ import annotations",
        "",
        "from typing import Dict, Tuple",
        "",
        f"#: {total} IAM actions, each mapped to the engine modules that can issue it.",
        "CALL_SURFACE: Dict[str, Tuple[str, ...]] = {",
    ]
    for action, mods in surface.items():
        mod_txt = ", ".join(f'"{m}"' for m in mods)
        out.append(f'    "{action}": ({mod_txt},),' if len(mods) == 1
                   else f'    "{action}": ({mod_txt}),')
    out += [
        "}",
        "",
        "",
        "def modules_for(action: str) -> Tuple[str, ...]:",
        '    """Which engine modules issue this call, or () if none does."""',
        "    return CALL_SURFACE.get(action, ())",
        "",
        "",
        "def actions() -> Tuple[str, ...]:",
        '    """Every action, sorted."""',
        "    return tuple(CALL_SURFACE)",
        "",
    ]
    return "\n".join(out)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--update", action="store_true", help="rewrite the module")
    ap.add_argument("--check", action="store_true", help="exit 1 if stale")
    ap.add_argument("--missing", action="store_true",
                    help="list actions the shipped role names nowhere")
    args = ap.parse_args()

    surface = compute()

    bad = sorted(a for a in surface if not a.split(":", 1)[1].startswith(READ_VERBS))
    if bad:
        print("CHARTER VIOLATION -- non-read actions reachable:", file=sys.stderr)
        for a in bad:
            print(f"  {a}  <- {', '.join(surface[a])}", file=sys.stderr)
        return 2

    if args.missing:
        active, optin = role_actions()
        named = active | optin
        gap = sorted(a for a in surface if a not in named)
        by = defaultdict(list)
        for a in gap:
            by[a.split(":", 1)[0]].append(a.split(":", 1)[1])
        print(f"{len(surface)} actions reachable; {len(gap)} named nowhere in the role")
        for svc in sorted(by):
            print(f"  {svc}:")
            for op in by[svc]:
                print(f"    - {svc}:{op}")
        return 1 if gap else 0

    rendered = render(surface)
    if args.check:
        existing = io.open(OUT, encoding="utf-8").read() if os.path.isfile(OUT) else None
        if existing != rendered:
            print("STALE: run python scripts/gen_call_surface.py --update",
                  file=sys.stderr)
            return 1
        print(f"tests/call_surface_baseline.py is up to date ({len(surface)} actions)")
        return 0

    if args.update:
        io.open(OUT, "w", encoding="utf-8", newline="\n").write(rendered)
        print(f"wrote {os.path.relpath(OUT, ROOT)} ({len(surface)} actions)")
        return 0

    ap.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Phase 4 Batch C: ECR hygiene CNT-03 (repo policy public/cross-account),
CNT-04 (tag immutability), CNT-05 (lifecycle), and RUNS_IMAGE dual-emit
(ECS task-def -> ECRImage) so image CVEs drive attack paths."""
import json
import os
import sys
from unittest.mock import MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import aws_live_scanner as A
import aws_graph
from test_live_scanner import MockPaginator, make_scanner

OWN = "123456789012"
EXT = "999999999999"


# ── parse_ecr_image_ref + node-id builder (pure) ─────────────────────────────
def test_parse_ecr_image_ref():
    p = A.parse_ecr_image_ref(f"{OWN}.dkr.ecr.us-east-1.amazonaws.com/team/app:v1")
    assert p == {"account": OWN, "region": "us-east-1", "repo": "team/app",
                 "tag": "v1", "digest": None}
    d = A.parse_ecr_image_ref(f"{OWN}.dkr.ecr.us-east-1.amazonaws.com/app@sha256:abc")
    assert d["digest"] == "sha256:abc" and d["tag"] is None and d["repo"] == "app"
    both = A.parse_ecr_image_ref(f"{OWN}.dkr.ecr.eu-west-1.amazonaws.com/app:v2@sha256:xy")
    assert both["digest"] == "sha256:xy" and both["region"] == "eu-west-1"
    # non-ECR references -> None (no bogus ECRImage node)
    assert A.parse_ecr_image_ref("nginx:latest") is None
    assert A.parse_ecr_image_ref("public.ecr.aws/foo/bar:1") is None
    assert A.parse_ecr_image_ref("gcr.io/proj/img:1") is None


def test_ecr_image_node_ids_both_conventions():
    cnt02, inspector = A.ecr_image_node_ids(OWN, "us-east-1", "app", "sha256:abc")
    assert cnt02 == f"{OWN}.dkr.ecr.us-east-1.amazonaws.com/app@sha256:abc"
    assert inspector == f"arn:aws:ecr:us-east-1:{OWN}:repository/app/sha256:abc"


# ── CNT-03/04/05 via _check_ecr ──────────────────────────────────────────────
def _ecr_scanner(repos, policy=None, lifecycle=True):
    s = make_scanner(["ECR"])
    s.graph = aws_graph.SecurityGraph()
    ecr = MagicMock()
    ecr.describe_repositories.return_value = {"repositories": repos}
    ecr.get_paginator.return_value = MockPaginator("imageDetails", [])   # _ingest_ecr_scan
    if policy is not None:
        ecr.get_repository_policy.return_value = {"policyText": policy}
    else:
        ecr.get_repository_policy.side_effect = RuntimeError("RepositoryPolicyNotFoundException")
    if lifecycle:
        ecr.get_lifecycle_policy.return_value = {"lifecyclePolicyText": "{}"}
    else:
        ecr.get_lifecycle_policy.side_effect = RuntimeError("LifecyclePolicyNotFoundException")
    s._clients["ecr:us-east-1"] = ecr
    return s


def _repo(name, mut=None):
    d = {"repositoryName": name, "repositoryArn": f"arn:aws:ecr:us-east-1:{OWN}:repository/{name}",
         "repositoryUri": f"{OWN}.dkr.ecr.us-east-1.amazonaws.com/{name}"}
    if mut:
        d["imageTagMutability"] = mut
    return d


def test_cnt_04_tag_immutability():
    s = _ecr_scanner([_repo("a", "IMMUTABLE"), _repo("b", "MUTABLE"),
                      _repo("c", "IMMUTABLE_WITH_EXCLUSION")])
    s._check_ecr()
    assert any(r.check_id == "CNT-04" and r.status == "PASS" and r.resource == "a" for r in s.results)
    warns = {r.resource for r in s.results if r.check_id == "CNT-04" and r.status == "WARN"}
    assert warns == {"b", "c"}                       # MUTABLE + *_WITH_EXCLUSION -> WARN


def test_cnt_03_public_and_crossaccount_repo_policy():
    pub = json.dumps({"Statement": [{"Effect": "Allow", "Principal": "*",
                                     "Action": "ecr:GetDownloadUrlForLayer"}]})
    s = _ecr_scanner([_repo("pub")], policy=pub)
    s._check_ecr()
    assert any(r.check_id == "CNT-03" and r.status == "FAIL" and "PUBLIC" in r.message for r in s.results)
    assert "SHARED_IMAGE" in s.graph.stats()["edge_kinds"]
    cross = json.dumps({"Statement": [{"Effect": "Allow",
                                       "Principal": {"AWS": f"arn:aws:iam::{EXT}:root"},
                                       "Action": "ecr:BatchGetImage"}]})
    s2 = _ecr_scanner([_repo("shared")], policy=cross)
    s2._check_ecr()
    assert any(r.check_id == "CNT-03" and r.status == "FAIL" and EXT in r.message for r in s2.results)


def test_cnt_03_no_policy_is_silent():
    s = _ecr_scanner([_repo("a")], policy=None)   # RepositoryPolicyNotFoundException
    s._check_ecr()
    assert not any(r.check_id == "CNT-03" for r in s.results)


def test_cnt_05_lifecycle_present_and_absent():
    s = _ecr_scanner([_repo("a")], lifecycle=True)
    s._check_ecr()
    assert any(r.check_id == "CNT-05" and r.status == "PASS" for r in s.results)
    s2 = _ecr_scanner([_repo("b")], lifecycle=False)
    s2._check_ecr()
    assert any(r.check_id == "CNT-05" and r.status == "WARN" for r in s2.results)


def test_cnt_03_04_05_maps_complete():
    for cid in ("CNT-03", "CNT-04", "CNT-05"):
        assert cid in A.CHECK_SEVERITY and cid in A.COMPLIANCE_MAP
        assert "aws " in A.REMEDIATION_MAP.get(cid, "").lower()


# ── RUNS_IMAGE dual-emit ─────────────────────────────────────────────────────
def _ecs_scanner():
    s = make_scanner(["ECS"])
    s.graph = aws_graph.SecurityGraph()
    return s


def test_runs_image_dual_emit_for_digest_ref():
    s = _ecs_scanner()
    td = {"taskDefinitionArn": f"arn:aws:ecs:us-east-1:{OWN}:task-definition/app:1", "family": "app"}
    cd = {"name": "c", "image": f"{OWN}.dkr.ecr.us-east-1.amazonaws.com/app@sha256:abc"}
    s._emit_runs_image(td, cd)
    ri = [e for e in s.graph.to_dict()["edges"] if e["kind"] == "RUNS_IMAGE"]
    targets = {e["target"] for e in ri}
    assert len(ri) == 2                              # dual-emit to BOTH id conventions
    assert f"{OWN}.dkr.ecr.us-east-1.amazonaws.com/app@sha256:abc" in targets   # CNT-02 id
    assert f"arn:aws:ecr:us-east-1:{OWN}:repository/app/sha256:abc" in targets  # Inspector id


def test_runs_image_resolves_tag_to_digest():
    s = _ecs_scanner()
    ecr = MagicMock()
    ecr.describe_images.return_value = {"imageDetails": [{"imageDigest": "sha256:zzz"}]}
    s._clients["ecr:us-east-1"] = ecr
    td = {"taskDefinitionArn": "arn:x/app:1", "family": "app"}
    cd = {"name": "c", "image": f"{OWN}.dkr.ecr.us-east-1.amazonaws.com/app:prod"}
    s._emit_runs_image(td, cd)
    targets = {e["target"] for e in s.graph.to_dict()["edges"] if e["kind"] == "RUNS_IMAGE"}
    assert any("sha256:zzz" in t for t in targets)  # tag resolved via describe_images


def test_runs_image_uses_ref_region_not_scanner_region():
    s = _ecs_scanner()
    cd = {"name": "c", "image": f"{OWN}.dkr.ecr.eu-central-1.amazonaws.com/app@sha256:d"}
    s._emit_runs_image({"family": "x", "taskDefinitionArn": "arn:x"}, cd)
    targets = {e["target"] for e in s.graph.to_dict()["edges"] if e["kind"] == "RUNS_IMAGE"}
    assert all("eu-central-1" in t for t in targets)  # region from the image ref, not us-east-1


def test_runs_image_skips_non_ecr():
    s = _ecs_scanner()
    s._emit_runs_image({"family": "x"}, {"name": "c", "image": "nginx:latest"})
    assert not any(e["kind"] == "RUNS_IMAGE" for e in s.graph.to_dict()["edges"])

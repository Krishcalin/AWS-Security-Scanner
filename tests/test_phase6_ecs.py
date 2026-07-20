"""Phase 6 Batch B5 — ECS container-escape primitives: ECS-06 host namespace share
(task-level), ECS-07 sensitive host-path bind mount (task-level), ECS-08 dangerous Linux
capabilities (container-level). Offline: MagicMock ecs."""
import os
import sys
from unittest.mock import MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from test_live_scanner import make_scanner


def _ecs_scanner(task_def):
    s = make_scanner(sections=["ECS"])
    ecs = MagicMock()
    ecs.list_clusters.return_value = {"clusterArns": ["arn:aws:ecs:us-east-1:1:cluster/c"]}
    ecs.list_task_definitions.return_value = {"taskDefinitionArns": ["arn:.../td:1"]}
    ecs.describe_task_definition.return_value = {"taskDefinition": task_def}
    s._clients["ecs:us-east-1"] = ecs
    s.graph = None   # skip _emit_runs_image graph work (image is non-ECR anyway)
    return s


def _td(containers=None, **kw):
    d = {"family": "app", "containerDefinitions": containers or [{"name": "c1", "image": "nginx"}]}
    d.update(kw)
    return d


def _status(s, cid):
    return {r.status for r in s.results if r.check_id == cid}


# ── ECS-06 host namespace ─────────────────────────────────────────────────────
def test_ecs06_host_network_fails():
    s = _ecs_scanner(_td(networkMode="host"))
    s._check_ecs()
    assert "FAIL" in _status(s, "ECS-06")


def test_ecs06_host_pid_fails():
    s = _ecs_scanner(_td(pidMode="host"))
    s._check_ecs()
    assert "FAIL" in _status(s, "ECS-06")


def test_ecs06_awsvpc_no_finding():
    s = _ecs_scanner(_td(networkMode="awsvpc", pidMode="task"))
    s._check_ecs()
    assert not _status(s, "ECS-06")


def test_ecs06_evaluated_once_per_task_not_per_container():
    s = _ecs_scanner(_td(networkMode="host",
                         containers=[{"name": "a"}, {"name": "b"}, {"name": "c"}]))
    s._check_ecs()
    # task-level: exactly ONE ECS-06 finding despite 3 containers
    assert len([r for r in s.results if r.check_id == "ECS-06"]) == 1


# ── ECS-07 host-path bind mount ───────────────────────────────────────────────
def test_ecs07_docker_socket_critical_fail():
    s = _ecs_scanner(_td(volumes=[{"name": "dsock",
                                   "host": {"sourcePath": "/var/run/docker.sock"}}]))
    s._check_ecs()
    assert "FAIL" in _status(s, "ECS-07")


def test_ecs07_root_fs_fails():
    s = _ecs_scanner(_td(volumes=[{"name": "root", "host": {"sourcePath": "/"}}]))
    s._check_ecs()
    assert "FAIL" in _status(s, "ECS-07")


def test_ecs07_generic_hostpath_warns():
    s = _ecs_scanner(_td(volumes=[{"name": "data", "host": {"sourcePath": "/opt/appdata"}}]))
    s._check_ecs()
    assert "WARN" in _status(s, "ECS-07") and "FAIL" not in _status(s, "ECS-07")


def test_ecs07_ephemeral_host_volume_no_sourcepath_benign():
    s = _ecs_scanner(_td(volumes=[{"name": "scratch", "host": {}}]))
    s._check_ecs()
    assert not _status(s, "ECS-07")


def test_ecs07_etc_prefix_does_not_flag_etcd():
    # '/etcd-data' must NOT match the '/etc' sensitive path (prefix-match care)
    s = _ecs_scanner(_td(volumes=[{"name": "etcd", "host": {"sourcePath": "/etcd-data"}}]))
    s._check_ecs()
    assert "FAIL" not in _status(s, "ECS-07") and "WARN" in _status(s, "ECS-07")


# ── ECS-08 dangerous capabilities ─────────────────────────────────────────────
def test_ecs08_sys_admin_fails():
    s = _ecs_scanner(_td(containers=[{"name": "c1",
        "linuxParameters": {"capabilities": {"add": ["SYS_ADMIN"]}}}]))
    s._check_ecs()
    assert "FAIL" in _status(s, "ECS-08")


def test_ecs08_benign_caps_no_finding():
    s = _ecs_scanner(_td(containers=[{"name": "c1",
        "linuxParameters": {"capabilities": {"add": ["CHOWN"], "drop": ["ALL"]}}}]))
    s._check_ecs()
    assert not _status(s, "ECS-08")


def test_ecs08_no_linux_parameters_no_crash():
    s = _ecs_scanner(_td(containers=[{"name": "c1"}]))  # no linuxParameters
    s._check_ecs()   # chain-guard must not raise
    assert not _status(s, "ECS-08")


def test_maps_lockstep():
    import aws_live_scanner as A
    for cid in ("ECS-06", "ECS-07", "ECS-08"):
        assert cid in A.CHECK_SEVERITY and cid in A.COMPLIANCE_MAP and cid in A.REMEDIATION_MAP
        assert "aws " in A.REMEDIATION_MAP[cid].lower()

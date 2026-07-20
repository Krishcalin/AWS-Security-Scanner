"""Phase 6 Batch B1 — compute depth: SSM patch posture (SSM-01/02) + launch-template
(LT-01) + Auto Scaling group (ASG-01) IMDSv2 scale-out drift. Offline: MagicMock clients."""
import os
import sys
from unittest.mock import MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from test_live_scanner import make_scanner, MockPaginator


def _status(s, cid):
    return {r.status for r in s.results if r.check_id == cid}


def _pag(mapping):
    """Return a get_paginator side_effect from {op_name: (result_key, items)}."""
    return lambda name: MockPaginator(*mapping[name])


# ── SSM-01 unmanaged instances ────────────────────────────────────────────────
def _ssm_scanner(ec2_instances, info_list=None, info_error=False, patch_states=None,
                 patch_error=False):
    s = make_scanner(sections=["EC2"])
    ec2 = MagicMock()
    ec2.get_paginator.side_effect = _pag({
        "describe_instances": ("Reservations", [{"Instances": ec2_instances}])})
    ssm = MagicMock()
    if info_error:
        ssm.get_paginator.side_effect = RuntimeError("AccessDenied")
    else:
        ssm.get_paginator.side_effect = _pag({
            "describe_instance_information": ("InstanceInformationList", info_list or [])})
    if patch_error:
        ssm.describe_instance_patch_states.side_effect = RuntimeError("AccessDenied")
    else:
        ssm.describe_instance_patch_states.return_value = {
            "InstancePatchStates": patch_states or []}
    s._clients["ec2:us-east-1"] = ec2
    s._clients["ssm:us-east-1"] = ssm
    return s


def test_ssm01_unmanaged_instance_fails():
    s = _ssm_scanner([{"InstanceId": "i-managed"}, {"InstanceId": "i-orphan"}],
                     info_list=[{"InstanceId": "i-managed", "ResourceType": "EC2Instance",
                                 "PingStatus": "Online"}])
    s._check_ssm()
    fails = [r.resource for r in s.results if r.check_id == "SSM-01" and r.status == "FAIL"]
    assert fails == ["i-orphan"]


def test_ssm01_all_managed_passes():
    s = _ssm_scanner([{"InstanceId": "i-1"}],
                     info_list=[{"InstanceId": "i-1", "ResourceType": "EC2Instance",
                                 "PingStatus": "Online"}])
    s._check_ssm()
    assert "PASS" in _status(s, "SSM-01")


def test_ssm01_onprem_and_connectionlost_not_counted_managed():
    # hybrid mi-* node + a ConnectionLost EC2 node must NOT count as managed
    s = _ssm_scanner([{"InstanceId": "i-1"}],
                     info_list=[{"InstanceId": "mi-abc", "ResourceType": "ManagedInstance",
                                 "PingStatus": "Online"},
                                {"InstanceId": "i-1", "ResourceType": "EC2Instance",
                                 "PingStatus": "ConnectionLost"}])
    s._check_ssm()
    assert "FAIL" in _status(s, "SSM-01")   # i-1 stale agent -> unmanaged


def test_ssm01_ssm_read_denied_warns_not_pass():
    s = _ssm_scanner([{"InstanceId": "i-1"}], info_error=True)
    s._check_ssm()
    assert "WARN" in _status(s, "SSM-01") and "PASS" not in _status(s, "SSM-01")


def test_ssm01_no_instances_info():
    s = _ssm_scanner([])
    s._check_ssm()
    assert _status(s, "SSM-01") == {"INFO"}


# ── SSM-02 patch compliance ───────────────────────────────────────────────────
def test_ssm02_critical_noncompliant_fails():
    s = _ssm_scanner([{"InstanceId": "i-1"}],
                     info_list=[{"InstanceId": "i-1", "ResourceType": "EC2Instance",
                                 "PingStatus": "Online"}],
                     patch_states=[{"InstanceId": "i-1", "CriticalNonCompliantCount": 3,
                                    "SecurityNonCompliantCount": 0}])
    s._check_ssm()
    assert "FAIL" in _status(s, "SSM-02")


def test_ssm02_never_scanned_is_info_and_blocks_pass():
    # managed but no patch state -> INFO unknown, aggregate must be WARN not PASS
    s = _ssm_scanner([{"InstanceId": "i-1"}],
                     info_list=[{"InstanceId": "i-1", "ResourceType": "EC2Instance",
                                 "PingStatus": "Online"}],
                     patch_states=[])
    s._check_ssm()
    assert "INFO" in _status(s, "SSM-02")
    assert "PASS" not in _status(s, "SSM-02")
    assert "WARN" in _status(s, "SSM-02")


def test_ssm02_all_compliant_passes():
    s = _ssm_scanner([{"InstanceId": "i-1"}],
                     info_list=[{"InstanceId": "i-1", "ResourceType": "EC2Instance",
                                 "PingStatus": "Online"}],
                     patch_states=[{"InstanceId": "i-1", "CriticalNonCompliantCount": 0,
                                    "SecurityNonCompliantCount": 0, "MissingCount": 0}])
    s._check_ssm()
    assert "PASS" in _status(s, "SSM-02")


# ── LT-01 launch template ─────────────────────────────────────────────────────
def _lt_scanner(templates, versions_by_id):
    s = make_scanner(sections=["EC2"])
    ec2 = MagicMock()
    ec2.get_paginator.side_effect = _pag({
        "describe_launch_templates": ("LaunchTemplates", templates)})

    def _dltv(LaunchTemplateId, Versions):
        return {"LaunchTemplateVersions": versions_by_id.get(LaunchTemplateId, [])}
    ec2.describe_launch_template_versions.side_effect = _dltv
    s._clients["ec2:us-east-1"] = ec2
    return s


def test_lt01_imdsv1_template_fails():
    s = _lt_scanner([{"LaunchTemplateId": "lt-1", "LaunchTemplateName": "web"}],
                    {"lt-1": [{"LaunchTemplateData": {"MetadataOptions": {"HttpTokens": "optional"}}}]})
    s._check_launch_templates()
    assert "FAIL" in _status(s, "LT-01")


def test_lt01_absent_metadata_options_is_imdsv1_fail():
    # the killer miss: no MetadataOptions block == IMDSv1
    s = _lt_scanner([{"LaunchTemplateId": "lt-2", "LaunchTemplateName": "bare"}],
                    {"lt-2": [{"LaunchTemplateData": {}}]})
    s._check_launch_templates()
    assert "FAIL" in _status(s, "LT-01")


def test_lt01_required_passes():
    s = _lt_scanner([{"LaunchTemplateId": "lt-3", "LaunchTemplateName": "hardened"}],
                    {"lt-3": [{"LaunchTemplateData": {"MetadataOptions": {"HttpTokens": "required"}}}]})
    s._check_launch_templates()
    assert _status(s, "LT-01") == {"PASS"}


def test_lt01_unresolved_version_warns_no_pass():
    s = _lt_scanner([{"LaunchTemplateId": "lt-4", "LaunchTemplateName": "ghost"}], {"lt-4": []})
    s._check_launch_templates()
    assert "WARN" in _status(s, "LT-01") and "PASS" not in _status(s, "LT-01")


# ── ASG-01 scale-out drift ────────────────────────────────────────────────────
def _asg_scanner(groups, versions_by_id=None, launch_configs=None):
    s = make_scanner(sections=["EC2"])
    asg = MagicMock()
    asg.get_paginator.side_effect = _pag({
        "describe_auto_scaling_groups": ("AutoScalingGroups", groups)})
    asg.describe_launch_configurations.return_value = {
        "LaunchConfigurations": launch_configs or []}
    ec2 = MagicMock()

    def _dltv(LaunchTemplateId, Versions):
        return {"LaunchTemplateVersions": (versions_by_id or {}).get(LaunchTemplateId, [])}
    ec2.describe_launch_template_versions.side_effect = _dltv
    s._clients["autoscaling:us-east-1"] = asg
    s._clients["ec2:us-east-1"] = ec2
    return s


def test_asg01_launch_template_imdsv1_fails():
    s = _asg_scanner([{"AutoScalingGroupName": "asg-web",
                       "LaunchTemplate": {"LaunchTemplateId": "lt-1", "Version": "$Latest"}}],
                     versions_by_id={"lt-1": [{"LaunchTemplateData": {"MetadataOptions": {"HttpTokens": "optional"}}}]})
    s._check_asg()
    assert "FAIL" in _status(s, "ASG-01")


def test_asg01_mixed_instances_policy_resolved():
    s = _asg_scanner([{"AutoScalingGroupName": "asg-mix",
                       "MixedInstancesPolicy": {"LaunchTemplate": {"LaunchTemplateSpecification":
                           {"LaunchTemplateId": "lt-2", "Version": "1"}}}}],
                     versions_by_id={"lt-2": [{"LaunchTemplateData": {"MetadataOptions": {"HttpTokens": "required"}}}]})
    s._check_asg()
    assert _status(s, "ASG-01") == {"PASS"}


def test_asg01_legacy_launch_config_no_metadata_is_imdsv1():
    s = _asg_scanner([{"AutoScalingGroupName": "asg-legacy", "LaunchConfigurationName": "lc-old"}],
                     launch_configs=[{"LaunchConfigurationName": "lc-old"}])  # no MetadataOptions
    s._check_asg()
    assert "FAIL" in _status(s, "ASG-01")


def test_asg01_no_groups_info():
    s = _asg_scanner([])
    s._check_asg()
    assert _status(s, "ASG-01") == {"INFO"}


def test_maps_lockstep():
    import aws_live_scanner as A
    for cid in ("SSM-01", "SSM-02", "LT-01", "ASG-01"):
        assert cid in A.CHECK_SEVERITY and cid in A.COMPLIANCE_MAP and cid in A.REMEDIATION_MAP
        assert "aws " in A.REMEDIATION_MAP[cid].lower()

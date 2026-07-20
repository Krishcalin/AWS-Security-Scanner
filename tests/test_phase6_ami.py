"""Phase 6 Batch B2 — AMI supply-chain depth: AMI-02 unencrypted backing snapshot,
AMI-03 stale/past-deprecation. Reuses the existing describe_images(Owners=['self'])
result (0 new API). Offline: MagicMock ec2."""
import os
import sys
from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from test_live_scanner import make_scanner


def _ami_scanner(images):
    s = make_scanner(sections=["AMI"])
    ec2 = MagicMock()
    ec2.describe_images.return_value = {"Images": images}
    ec2.describe_image_attribute.return_value = {"LaunchPermissions": []}
    s._clients["ec2:us-east-1"] = ec2
    return s


def _status(s, cid):
    return {r.status for r in s.results if r.check_id == cid}


def _iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")


RECENT = _iso(datetime.now(timezone.utc) - timedelta(days=30))
OLD = _iso(datetime.now(timezone.utc) - timedelta(days=900))
PAST_DEP = _iso(datetime.now(timezone.utc) - timedelta(days=5))
FUTURE_DEP = _iso(datetime.now(timezone.utc) + timedelta(days=100))


def _img(aid, encrypted=True, created=RECENT, deprecation=None):
    m = {"ImageId": aid, "Name": aid,
         "BlockDeviceMappings": [{"Ebs": {"Encrypted": encrypted, "SnapshotId": "snap-1"}}],
         "CreationDate": created}
    if deprecation:
        m["DeprecationTime"] = deprecation
    return m


# ── AMI-02 unencrypted snapshot ───────────────────────────────────────────────
def test_ami02_unencrypted_snapshot_fails():
    s = _ami_scanner([_img("ami-plain", encrypted=False)])
    s._check_ami()
    assert "FAIL" in _status(s, "AMI-02")


def test_ami02_absent_encrypted_flag_is_unencrypted():
    img = {"ImageId": "ami-x", "Name": "ami-x", "CreationDate": RECENT,
           "BlockDeviceMappings": [{"Ebs": {"SnapshotId": "snap-1"}}]}  # no Encrypted key
    s = _ami_scanner([img])
    s._check_ami()
    assert "FAIL" in _status(s, "AMI-02")


def test_ami02_encrypted_passes():
    s = _ami_scanner([_img("ami-enc", encrypted=True)])
    s._check_ami()
    assert "PASS" in _status(s, "AMI-02")


def test_ami02_instance_store_mapping_ignored():
    # a mapping with no 'Ebs' (instance-store) must not trip AMI-02
    img = {"ImageId": "ami-is", "Name": "ami-is", "CreationDate": RECENT,
           "BlockDeviceMappings": [{"VirtualName": "ephemeral0"},
                                   {"Ebs": {"Encrypted": True}}]}
    s = _ami_scanner([img])
    s._check_ami()
    assert "PASS" in _status(s, "AMI-02") and "FAIL" not in _status(s, "AMI-02")


# ── AMI-03 stale / deprecated ─────────────────────────────────────────────────
def test_ami03_past_deprecation_fails():
    s = _ami_scanner([_img("ami-dep", deprecation=PAST_DEP)])
    s._check_ami()
    assert "FAIL" in _status(s, "AMI-03")


def test_ami03_future_deprecation_recent_ok():
    s = _ami_scanner([_img("ami-ok", deprecation=FUTURE_DEP, created=RECENT)])
    s._check_ami()
    assert "FAIL" not in _status(s, "AMI-03") and "WARN" not in _status(s, "AMI-03")


def test_ami03_very_old_warns():
    s = _ami_scanner([_img("ami-old", created=OLD)])
    s._check_ami()
    assert "WARN" in _status(s, "AMI-03")


def test_ami03_unparseable_timestamp_is_info_not_crash():
    img = {"ImageId": "ami-bad", "Name": "ami-bad", "CreationDate": "not-a-date",
           "BlockDeviceMappings": [{"Ebs": {"Encrypted": True}}]}
    s = _ami_scanner([img])
    s._check_ami()   # must not raise
    assert "INFO" in _status(s, "AMI-03")


def test_maps_lockstep():
    import aws_live_scanner as A
    for cid in ("AMI-02", "AMI-03"):
        assert cid in A.CHECK_SEVERITY and cid in A.COMPLIANCE_MAP and cid in A.REMEDIATION_MAP
        assert "aws " in A.REMEDIATION_MAP[cid].lower()

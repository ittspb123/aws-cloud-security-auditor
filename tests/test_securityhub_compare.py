from datetime import datetime, timezone

from securityhub import CONTROL_MAP, compare, resource_matches

from cloudaudit.base import Check

ACCT = "111122223333"


def sh(control, resource_id, first="2026-10-20T02:00:00Z"):
    return {"Compliance": {"SecurityControlId": control, "Status": "FAILED"},
            "Resources": [{"Id": resource_id}], "FirstObservedAt": first}


def test_every_check_is_mapped_to_security_hub():
    assert {c.id for c in Check.registry} == set(CONTROL_MAP)


def test_resource_matching():
    assert resource_matches("my-bucket", "arn:aws:s3:::my-bucket", ACCT)
    assert not resource_matches("bucket", "arn:aws:s3:::my-bucket", ACCT)  # suffix must be a whole name
    assert resource_matches("sg-123", f"arn:aws:ec2:us-east-2:{ACCT}:security-group/sg-123", ACCT)
    assert resource_matches("alice", f"arn:aws:iam::{ACCT}:user/alice", ACCT)
    assert resource_matches("account-password-policy", f"AWS::::Account:{ACCT}", ACCT)
    assert resource_matches("ebs-default-encryption/us-east-2", f"AWS::::Account:{ACCT}", ACCT)
    assert not resource_matches("sg-123", f"AWS::::Account:{ACCT}", ACCT)


def test_compare_counts_latency_and_gaps():
    expected = [{"check_id": "S3_PUBLIC_ACL", "resource": "pub"},
                {"check_id": "EC2_OPEN_SSH", "resource": "sg-1"},
                {"check_id": "IAM_WEAK_PASSWORD_POLICY", "resource": "account-password-policy"}]
    ours = [{"check_id": "S3_PUBLIC_ACL", "resource": "pub"}, {"check_id": "EC2_OPEN_SSH", "resource": "sg-1"},
            {"check_id": "IAM_WEAK_PASSWORD_POLICY", "resource": "account-password-policy"}]
    findings = [sh("S3.2", "arn:aws:s3:::pub", "2026-10-20T01:30:00Z"),
                sh("IAM.15", f"AWS::::Account:{ACCT}", "2026-10-20T13:00:00Z"),
                sh("EC2.13", "arn:aws:ec2:us-east-2:1:security-group/sg-OTHER"),  # wrong resource
                sh("Lambda.1", "arn:aws:lambda:x")]
    r = compare(expected, ours, findings, ACCT, baseline=datetime(2026, 10, 20, 1, 0, tzinfo=timezone.utc))
    assert r["cloudaudit_detected"] == 3 and r["security_hub_detected"] == 2
    by = {x["check_id"]: x for x in r["rows"]}
    assert by["S3_PUBLIC_ACL"]["security_hub_minutes_after_baseline"] == 30.0
    assert by["IAM_WEAK_PASSWORD_POLICY"]["security_hub_minutes_after_baseline"] == 720.0
    assert not by["EC2_OPEN_SSH"]["security_hub"]
    assert r["security_hub_controls_we_do_not_cover"] == {"Lambda.1": 1}

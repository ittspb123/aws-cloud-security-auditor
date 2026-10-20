import json

from conftest import REGION
from seed import Seeder

from cloudaudit.base import Check, Severity
from cloudaudit.report import render_html
from cloudaudit.runner import run_checks, select_checks
from evaluate import score


class Boom(Check):
    id = ""  # not registered; instantiated manually
    title = "always fails"

    def run(self, ctx):
        yield self.finding("x", "partial result before the crash")
        raise RuntimeError("AccessDenied simulated")


def test_failing_check_does_not_stop_scan(ctx):
    boom = Boom()
    boom.id = "BOOM"
    checks = [boom] + select_checks(only=["EC2_EBS_DEFAULT_ENCRYPTION_OFF"])
    report = run_checks(ctx, checks)
    assert report["summary"]["checks_failed"] == 1
    assert report["errors"][0]["check_id"] == "BOOM"
    assert [f["check_id"] for f in report["findings"]] == ["EC2_EBS_DEFAULT_ENCRYPTION_OFF"]


def test_findings_sorted_by_severity_and_json_serialisable(ctx):
    report = run_checks(ctx)
    ranks = [Severity[f["severity"]] for f in report["findings"]]
    assert ranks == sorted(ranks, reverse=True)
    assert all(f["remediation"] for f in report["findings"])
    json.dumps(report)
    assert "<table>" in render_html(report)


def test_every_check_has_metadata():
    ids = [c.id for c in Check.registry]
    assert len(ids) == len(set(ids)) >= 12
    for cls in Check.registry:
        assert cls.title and cls.cis_ref and cls.service and cls.remediation, cls.id


def test_select_by_service():
    assert {c.service for c in select_checks(services=["iam"])} == {"iam"}


def test_seeded_sandbox_full_detection(session, ctx):
    """End-to-end: plant the answer key, scan, require 100% recall and no false positives."""
    expected = Seeder(session, REGION, moto=True, suffix="t").seed_all()
    report = run_checks(ctx)
    result = score(expected, report["findings"])
    assert result["missed"] == [], result["missed"]
    assert result["unexpected"] == [], result["unexpected"]
    assert report["errors"] == []
    assert result["planted"] >= 15


def test_seed_survives_guardrail_denials(session, ctx):
    """Simulate an org SCP blocking some planting steps: the seed must skip them cleanly,
    keep them out of the answer key, and not leave half-planted resources that cause noise."""
    from botocore.exceptions import ClientError

    seeder = Seeder(session, REGION, moto=True, suffix="scp")
    s3control = session.client("s3control", region_name=REGION)

    def deny(*_a, **_kw):
        raise ClientError({"Error": {"Code": "AccessDenied", "Message": "explicit deny in a service control policy"}},
                          "Op")

    seeder.iam.create_login_profile = deny
    seeder.iam.create_group = deny
    seeder.s3.put_bucket_acl = deny
    seeder.ec2.disable_ebs_encryption_by_default = deny
    session.client = (lambda orig: lambda svc, **kw: s3control if svc == "s3control" else orig(svc, **kw))(session.client)
    s3control.delete_public_access_block = deny
    seeder.s = session

    expected = seeder.seed_all()
    blocked = {s["step"] for s in seeder.skipped}
    assert {"IAM_USER_NO_MFA", "S3_ACCOUNT_BPA_DISABLED", "S3_PUBLIC_ACL",
            "EC2_EBS_DEFAULT_ENCRYPTION_OFF", "attach *:* policy to a group"} <= blocked
    result = score(expected, run_checks(ctx)["findings"])
    assert result["missed"] == []
    # with guardrails the account starts hardened, so the only extras are genuinely pre-existing state
    assert {u["check_id"] for u in result["unexpected"]} <= {"S3_ACCOUNT_BPA_DISABLED", "EC2_EBS_DEFAULT_ENCRYPTION_OFF"}

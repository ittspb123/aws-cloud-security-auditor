"""Benchmark cloudaudit against AWS Security Hub CSPM (AWS's managed CIS checker).

  python scripts/securityhub.py enable  --profile sandbox-admin --region us-east-2
  ... seed, run our scan, then wait for Security Hub (hours) ...
  python scripts/securityhub.py compare --profile scanner --region us-east-2 \
         --answer-key answer_key.json --report report.json
  python scripts/securityhub.py disable --profile sandbox-admin --region us-east-2

`enable` turns on AWS Config (Security Hub's control checks are mostly Config rules) and Security Hub
with the CIS v3.0 and AWS Foundational Security Best Practices standards. It records what it created in
securityhub_state.json so `disable` removes exactly that and nothing pre-existing.

Cost: Security Hub CSPM and Config both have per-check/per-item pricing (Security Hub has a 30-day trial).
For a near-empty sandbox this is cents, but run `disable` as soon as you have your numbers.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError

sys.path.insert(0, os.path.dirname(__file__))
from seed import BPA_ON, _ssl_deny  # noqa: E402

STATE_FILE = "securityhub_state.json"

# Our check -> Security Hub consolidated control IDs that cover the same misconfiguration.
CONTROL_MAP: dict[str, list[str]] = {
    "S3_ACCOUNT_BPA_DISABLED": ["S3.1"],
    "S3_BUCKET_BPA_DISABLED": ["S3.8"],
    "S3_PUBLIC_ACL": ["S3.2", "S3.3"],
    "S3_PUBLIC_POLICY": ["S3.2", "S3.3"],
    "S3_SSL_NOT_ENFORCED": ["S3.5"],
    "S3_NO_VERSIONING": ["S3.14"],
    "S3_NO_DEFAULT_ENCRYPTION": ["S3.4"],
    "EC2_OPEN_SSH": ["EC2.13", "EC2.53", "EC2.54", "EC2.19"],
    "EC2_OPEN_RDP": ["EC2.14", "EC2.53", "EC2.54", "EC2.19"],
    "EC2_DEFAULT_SG_IN_USE": ["EC2.2"],
    "EC2_EBS_UNENCRYPTED": ["EC2.3"],
    "EC2_EBS_DEFAULT_ENCRYPTION_OFF": ["EC2.7"],
    "IAM_ROOT_ACCESS_KEYS": ["IAM.4"],
    "IAM_ROOT_NO_MFA": ["IAM.9", "IAM.6"],
    "IAM_USER_NO_MFA": ["IAM.5"],
    "IAM_STALE_ACCESS_KEY": ["IAM.3"],
    "IAM_WEAK_PASSWORD_POLICY": ["IAM.7", "IAM.15", "IAM.16"],
    "IAM_WILDCARD_ADMIN_POLICY": ["IAM.1"],
    "IAM_USER_DIRECT_POLICY": ["IAM.2"],
    "CT_NOT_ENABLED": ["CloudTrail.1", "CloudTrail.3"],
    "CT_LOG_VALIDATION_DISABLED": ["CloudTrail.4"],
}


# ------------------------------------------------------------------ comparison (pure functions)

def is_account_level(resource: str, account_id: str) -> bool:
    return (resource in (account_id, "account-password-policy", "root")
            or resource.startswith("ebs-default-encryption/"))


def resource_matches(ours: str, sh_resource_id: str, account_id: str) -> bool:
    """Does a Security Hub resource ID (usually an ARN) refer to our resource identifier?"""
    if is_account_level(ours, account_id):
        return sh_resource_id.startswith("AWS::::Account") or sh_resource_id == f"arn:aws::{account_id}"
    if not sh_resource_id.endswith(ours):
        return False
    before = sh_resource_id[: -len(ours)]
    return before == "" or before[-1] in "/:"


def control_id(finding: dict) -> str | None:
    return (finding.get("Compliance", {}).get("SecurityControlId")
            or finding.get("ProductFields", {}).get("ControlId"))


def _parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def compare(expected: list[dict], our_findings: list[dict], sh_findings: list[dict], account_id: str,
            baseline: datetime | None = None) -> dict:
    ours = {(f["check_id"], f["resource"]) for f in our_findings}
    rows = []
    for e in expected:
        controls = CONTROL_MAP.get(e["check_id"], [])
        hits = [f for f in sh_findings if control_id(f) in controls
                and any(resource_matches(e["resource"], r.get("Id", ""), account_id) for r in f.get("Resources", []))]
        first_seen = min((t for t in (_parse_time(h.get("FirstObservedAt") or h.get("CreatedAt")) for h in hits) if t),
                         default=None)
        latency = round((first_seen - baseline).total_seconds() / 60, 1) if first_seen and baseline else None
        rows.append({
            "check_id": e["check_id"], "resource": e["resource"],
            "cloudaudit": (e["check_id"], e["resource"]) in ours,
            "security_hub": bool(hits),
            "security_hub_controls": sorted({control_id(h) for h in hits}),
            "security_hub_minutes_after_baseline": latency,
            "mapped_controls": controls,
        })
    mapped = {c for cs in CONTROL_MAP.values() for c in cs}
    sh_only: dict[str, int] = {}
    for f in sh_findings:
        cid = control_id(f)
        if cid and cid not in mapped:
            sh_only[cid] = sh_only.get(cid, 0) + 1
    latencies = [r["security_hub_minutes_after_baseline"] for r in rows if r["security_hub_minutes_after_baseline"] is not None]
    return {
        "planted": len(rows),
        "cloudaudit_detected": sum(r["cloudaudit"] for r in rows),
        "security_hub_detected": sum(r["security_hub"] for r in rows),
        "security_hub_median_minutes": sorted(latencies)[len(latencies) // 2] if latencies else None,
        "rows": rows,
        "security_hub_controls_we_do_not_cover": dict(sorted(sh_only.items(), key=lambda kv: -kv[1])),
    }


# ------------------------------------------------------------------ AWS side

def _code(e: ClientError) -> str:
    return e.response.get("Error", {}).get("Code", "")


def enable(session: boto3.Session, region: str) -> dict:
    acct = session.client("sts").get_caller_identity()["Account"]
    iam, s3 = session.client("iam"), session.client("s3", region_name=region)
    config, sh = session.client("config", region_name=region), session.client("securityhub", region_name=region)
    state = {"region": region, "account_id": acct, "created": {}}

    try:
        print("AWS Config")
        recorders = config.describe_configuration_recorders()["ConfigurationRecorders"]
        if recorders:
            print(f"  existing recorder '{recorders[0]['name']}' found - reusing it, will not delete it later")
            config.start_configuration_recorder(ConfigurationRecorderName=recorders[0]["name"])
        else:
            try:
                iam.create_service_linked_role(AWSServiceName="config.amazonaws.com")
            except ClientError as e:
                if _code(e) != "InvalidInput":  # already exists
                    raise
            role = f"arn:aws:iam::{acct}:role/aws-service-role/config.amazonaws.com/AWSServiceRoleForConfig"
            bucket = f"cloudaudit-config-{acct}-{region}"
            kw = {} if region == "us-east-1" else {"CreateBucketConfiguration": {"LocationConstraint": region}}
            s3.create_bucket(Bucket=bucket, **kw)
            # hardened like the seed's control bucket so it doesn't pollute either scanner's results
            s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})
            s3.put_bucket_encryption(Bucket=bucket, ServerSideEncryptionConfiguration={
                "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]})
            cond = {"StringEquals": {"AWS:SourceAccount": acct}}
            s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps({"Version": "2012-10-17", "Statement": [
                {"Sid": "ConfigAclCheck", "Effect": "Allow", "Principal": {"Service": "config.amazonaws.com"},
                 "Action": "s3:GetBucketAcl", "Resource": f"arn:aws:s3:::{bucket}", "Condition": cond},
                {"Sid": "ConfigList", "Effect": "Allow", "Principal": {"Service": "config.amazonaws.com"},
                 "Action": "s3:ListBucket", "Resource": f"arn:aws:s3:::{bucket}", "Condition": cond},
                {"Sid": "ConfigWrite", "Effect": "Allow", "Principal": {"Service": "config.amazonaws.com"},
                 "Action": "s3:PutObject", "Resource": f"arn:aws:s3:::{bucket}/AWSLogs/{acct}/Config/*",
                 "Condition": {"StringEquals": {"AWS:SourceAccount": acct, "s3:x-amz-acl": "bucket-owner-full-control"}}},
                _ssl_deny(bucket)]}))
            s3.put_public_access_block(Bucket=bucket, PublicAccessBlockConfiguration=BPA_ON)
            state["created"]["config_bucket"] = bucket
            config.put_configuration_recorder(ConfigurationRecorder={
                "name": "default", "roleARN": role,
                "recordingGroup": {"allSupported": True, "includeGlobalResourceTypes": True}})
            config.put_delivery_channel(DeliveryChannel={"name": "default", "s3BucketName": bucket})
            config.start_configuration_recorder(ConfigurationRecorderName="default")
            state["created"]["config_recorder"] = "default"
            print(f"  recorder started, delivering to s3://{bucket}")

        print("Security Hub")
        try:
            sh.enable_security_hub(EnableDefaultStandards=False, ControlFindingGenerator="SECURITY_CONTROL")
            state["created"]["security_hub"] = True
            print("  enabled")
        except ClientError as e:
            if _code(e) != "ResourceConflictException":
                raise
            print("  already enabled - will not disable it later")

        wanted = ("cis-aws-foundations-benchmark/v/3.0.0", "aws-foundational-security-best-practices/v/1.0.0")
        try:
            arns = [s["StandardsArn"] for s in sh.describe_standards()["Standards"]
                    if any(w in s["StandardsArn"] for w in wanted)]
        except ClientError:
            arns = [f"arn:aws:securityhub:{region}::standards/{w}" for w in wanted]
        subs = sh.batch_enable_standards(StandardsSubscriptionRequests=[{"StandardsArn": a} for a in arns])
        state["created"]["standards"] = [s["StandardsSubscriptionArn"] for s in subs.get("StandardsSubscriptions", [])]
        for a in arns:
            print("  standard:", a.split("/standards/")[-1])

    finally:
        # saved even if a step fails, so `disable` can always remove whatever was created
        state["enabled_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
        with open(STATE_FILE, "w") as fh:
            json.dump(state, fh, indent=2)
    print(f"\nState saved to {STATE_FILE}. Security Hub needs time: change-triggered controls usually report "
          "within ~30 min,\nperiodic ones (IAM, root, password policy) within 12-24 h. Run `compare` after that.")
    return state


def fetch_failed_findings(session: boto3.Session, region: str, account_id: str) -> list[dict]:
    sh = session.client("securityhub", region_name=region)
    filters = {"ComplianceStatus": [{"Value": "FAILED", "Comparison": "EQUALS"}],
               "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}],
               "AwsAccountId": [{"Value": account_id, "Comparison": "EQUALS"}]}
    out = []
    for page in sh.get_paginator("get_findings").paginate(Filters=filters, PaginationConfig={"PageSize": 100}):
        out.extend(page["Findings"])
    return out


def disable(session: boto3.Session, region: str) -> None:
    if not os.path.exists(STATE_FILE):
        print(f"No {STATE_FILE}; nothing recorded as created by `enable`.")
        return
    state = json.load(open(STATE_FILE))
    created = state["created"]
    sh, config = session.client("securityhub", region_name=region), session.client("config", region_name=region)

    def step(desc, fn, **kw):
        try:
            fn(**kw)
            print("  ok  ", desc)
        except ClientError as e:
            print("  skip", desc, "-", _code(e))

    if created.get("standards"):
        step("disable standards", sh.batch_disable_standards, StandardsSubscriptionArns=created["standards"])
    if created.get("security_hub"):
        step("disable Security Hub", sh.disable_security_hub)
    if created.get("config_recorder"):
        name = created["config_recorder"]
        step("stop Config recorder", config.stop_configuration_recorder, ConfigurationRecorderName=name)
        step("delete delivery channel", config.delete_delivery_channel, DeliveryChannelName="default")
        step("delete Config recorder", config.delete_configuration_recorder, ConfigurationRecorderName=name)
    if created.get("config_bucket"):
        bucket = session.resource("s3", region_name=region).Bucket(created["config_bucket"])
        try:
            bucket.object_versions.delete()
        except ClientError:
            pass
        step(f"delete bucket {created['config_bucket']}", session.client("s3", region_name=region).delete_bucket,
             Bucket=created["config_bucket"])
    os.rename(STATE_FILE, STATE_FILE + ".disabled")


def print_comparison(result: dict) -> None:
    print(f"\n{'check':32} {'resource':42} cloudaudit  SecurityHub  (minutes)")
    for r in result["rows"]:
        mins = r["security_hub_minutes_after_baseline"]
        print(f"{r['check_id']:32} {r['resource'][:42]:42} {'yes' if r['cloudaudit'] else 'NO':^10}  "
              f"{'yes' if r['security_hub'] else 'NO':^11}  {'' if mins is None else mins}")
    n = result["planted"]
    print(f"\ncloudaudit:   {result['cloudaudit_detected']}/{n}")
    print(f"Security Hub: {result['security_hub_detected']}/{n}"
          + (f"  (median {result['security_hub_median_minutes']} min after enable/seed)"
             if result["security_hub_median_minutes"] is not None else ""))
    if result["security_hub_controls_we_do_not_cover"]:
        print("\nFailed Security Hub controls cloudaudit has no check for (coverage gaps):")
        for cid, count in result["security_hub_controls_we_do_not_cover"].items():
            print(f"  {cid:16} {count} finding(s)")


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("action", choices=["enable", "compare", "disable"])
    p.add_argument("--profile")
    p.add_argument("--region", required=True)
    p.add_argument("--answer-key", default="answer_key.json")
    p.add_argument("--report", default="report.json")
    p.add_argument("-o", "--output", default="results/securityhub_comparison.json")
    args = p.parse_args(argv)
    session = boto3.Session(profile_name=args.profile, region_name=args.region)

    if args.action == "enable":
        enable(session, args.region)
    elif args.action == "disable":
        disable(session, args.region)
    else:
        key = json.load(open(args.answer_key))
        report = json.load(open(args.report))
        findings = fetch_failed_findings(session, args.region, key["account_id"])
        print(f"Fetched {len(findings)} failed Security Hub findings")
        times = [t for t in (_parse_time(key.get("seeded_at")),
                             _parse_time(json.load(open(STATE_FILE)).get("enabled_at")) if os.path.exists(STATE_FILE) else None) if t]
        result = compare(key["expected"], report["findings"], findings, key["account_id"], max(times) if times else None)
        result["cloudaudit_scan_seconds"] = report["summary"]["duration_seconds"]
        os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
        with open(args.output, "w") as fh:
            json.dump(result, fh, indent=2, default=str)
        print_comparison(result)
        print(f"\ncloudaudit scan took {result['cloudaudit_scan_seconds']} s. Saved -> {args.output}")
        if not findings:
            print("No findings yet: Security Hub may still be evaluating. Try again in a few hours.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

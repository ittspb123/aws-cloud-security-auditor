"""S3 checks (CIS section 2.1)."""

from __future__ import annotations

import json
from botocore.exceptions import ClientError

from ..base import AuditContext, Check, Severity

PUBLIC_GRANTEES = {
    "http://acs.amazonaws.com/groups/global/AllUsers": "AllUsers",
    "http://acs.amazonaws.com/groups/global/AuthenticatedUsers": "AuthenticatedUsers",
}


def _error_code(exc: ClientError) -> str:
    return exc.response.get("Error", {}).get("Code", "")


class S3Check(Check):
    """Shared helpers: list buckets once, talk to each bucket in its own region."""

    service = "s3"

    @staticmethod
    def buckets(ctx: AuditContext) -> list[tuple[str, str]]:
        if "s3_buckets" not in ctx.cache:
            s3 = ctx.client("s3")
            buckets = []
            for b in s3.list_buckets().get("Buckets", []):
                loc = s3.get_bucket_location(Bucket=b["Name"]).get("LocationConstraint")
                buckets.append((b["Name"], loc or "us-east-1"))
            ctx.cache["s3_buckets"] = buckets
        return ctx.cache["s3_buckets"]

    def run(self, ctx):
        for name, region in self.buckets(ctx):
            yield from self.check_bucket(ctx.client("s3", region), name, region)

    def check_bucket(self, s3, bucket: str, region: str):
        raise NotImplementedError


def _load_policy(s3, bucket: str) -> dict | None:
    try:
        return json.loads(s3.get_bucket_policy(Bucket=bucket)["Policy"])
    except ClientError as e:
        if _error_code(e) == "NoSuchBucketPolicy":
            return None
        raise


def _as_list(value) -> list:
    return value if isinstance(value, list) else [value]


def _is_public_principal(principal) -> bool:
    if principal == "*":
        return True
    if isinstance(principal, dict):
        return any(p == "*" for p in _as_list(principal.get("AWS", [])))
    return False


class S3PublicAcl(S3Check):
    id = "S3_PUBLIC_ACL"
    title = "S3 bucket ACL grants access to everyone"
    severity = Severity.CRITICAL
    cis_ref = "2.1.4"
    remediation = ("aws s3api put-bucket-acl --bucket {resource} --acl private && "
                   "aws s3api put-bucket-ownership-controls --bucket {resource} "
                   "--ownership-controls Rules=[{{ObjectOwnership=BucketOwnerEnforced}}]")

    def check_bucket(self, s3, bucket, region):
        grants = s3.get_bucket_acl(Bucket=bucket).get("Grants", [])
        public = [(PUBLIC_GRANTEES[g["Grantee"]["URI"]], g["Permission"])
                  for g in grants if g.get("Grantee", {}).get("URI") in PUBLIC_GRANTEES]
        if public:
            perms = ", ".join(f"{who}:{perm}" for who, perm in public)
            yield self.finding(bucket, f"ACL grants {perms}", region, grants=public)


class S3PublicPolicy(S3Check):
    id = "S3_PUBLIC_POLICY"
    title = "S3 bucket policy allows anonymous access"
    severity = Severity.CRITICAL
    cis_ref = "2.1.4"
    remediation = ("Remove statements with Principal \"*\" (or add restrictive conditions): "
                   "aws s3api delete-bucket-policy --bucket {resource}, then enable Block Public Access.")

    def check_bucket(self, s3, bucket, region):
        policy = _load_policy(s3, bucket)
        if not policy:
            return
        for stmt in _as_list(policy.get("Statement", [])):
            if (stmt.get("Effect") == "Allow" and _is_public_principal(stmt.get("Principal"))
                    and not stmt.get("Condition")):
                yield self.finding(bucket, f"Statement allows {stmt.get('Action')} to Principal *",
                                   region, statement=stmt)
                return


class S3NoEncryption(S3Check):
    id = "S3_NO_DEFAULT_ENCRYPTION"
    title = "S3 bucket has no default encryption configured"
    severity = Severity.MEDIUM
    cis_ref = "2.1.1 (v1.4)"
    remediation = ("aws s3api put-bucket-encryption --bucket {resource} --server-side-encryption-configuration "
                   "'{{\"Rules\":[{{\"ApplyServerSideEncryptionByDefault\":{{\"SSEAlgorithm\":\"aws:kms\"}}}}]}}'")

    def check_bucket(self, s3, bucket, region):
        try:
            s3.get_bucket_encryption(Bucket=bucket)
        except ClientError as e:
            if _error_code(e) == "ServerSideEncryptionConfigurationNotFoundError":
                yield self.finding(bucket, "No default server-side encryption", region)
            else:
                raise


class S3NoVersioning(S3Check):
    id = "S3_NO_VERSIONING"
    title = "S3 bucket versioning is not enabled"
    severity = Severity.LOW
    cis_ref = "2.1.3"
    remediation = "aws s3api put-bucket-versioning --bucket {resource} --versioning-configuration Status=Enabled"

    def check_bucket(self, s3, bucket, region):
        status = s3.get_bucket_versioning(Bucket=bucket).get("Status", "Disabled")
        if status != "Enabled":
            yield self.finding(bucket, f"Versioning status is {status}", region)


class S3SslNotEnforced(S3Check):
    id = "S3_SSL_NOT_ENFORCED"
    title = "S3 bucket policy does not deny non-HTTPS requests"
    severity = Severity.MEDIUM
    cis_ref = "2.1.1 (v3.0) / 2.1.2 (v1.5)"
    remediation = ("Add a Deny statement for all principals on arn:aws:s3:::{resource} and "
                   "arn:aws:s3:::{resource}/* with Condition {{\"Bool\":{{\"aws:SecureTransport\":\"false\"}}}}.")

    def check_bucket(self, s3, bucket, region):
        policy = _load_policy(s3, bucket) or {}
        for stmt in _as_list(policy.get("Statement", [])):
            cond = stmt.get("Condition", {}).get("Bool", {})
            if (stmt.get("Effect") == "Deny" and _is_public_principal(stmt.get("Principal"))
                    and str(cond.get("aws:SecureTransport", "")).lower() == "false"):
                return
        yield self.finding(bucket, "No Deny statement on aws:SecureTransport=false", region)


class S3BucketBlockPublicAccess(S3Check):
    id = "S3_BUCKET_BPA_DISABLED"
    title = "S3 bucket Block Public Access is not fully enabled"
    severity = Severity.HIGH
    cis_ref = "2.1.4"
    remediation = ("aws s3api put-public-access-block --bucket {resource} --public-access-block-configuration "
                   "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true")

    def check_bucket(self, s3, bucket, region):
        try:
            cfg = s3.get_public_access_block(Bucket=bucket)["PublicAccessBlockConfiguration"]
        except ClientError as e:
            if _error_code(e) != "NoSuchPublicAccessBlockConfiguration":
                raise
            cfg = {}
        off = [k for k in ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy",
                           "RestrictPublicBuckets") if not cfg.get(k)]
        if off:
            yield self.finding(bucket, "Disabled settings: " + ", ".join(off), region, disabled=off)


class S3AccountBlockPublicAccess(Check):
    id = "S3_ACCOUNT_BPA_DISABLED"
    title = "Account-level S3 Block Public Access is not fully enabled"
    severity = Severity.HIGH
    cis_ref = "2.1.4"
    service = "s3"
    remediation = ("aws s3control put-public-access-block --account-id {resource} --public-access-block-configuration "
                   "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true")

    def run(self, ctx):
        try:
            cfg = ctx.client("s3control").get_public_access_block(
                AccountId=ctx.account_id)["PublicAccessBlockConfiguration"]
        except ClientError as e:
            if _error_code(e) != "NoSuchPublicAccessBlockConfiguration":
                raise
            cfg = {}
        off = [k for k in ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy",
                           "RestrictPublicBuckets") if not cfg.get(k)]
        if off:
            yield self.finding(ctx.account_id, "Disabled settings: " + ", ".join(off), disabled=off)

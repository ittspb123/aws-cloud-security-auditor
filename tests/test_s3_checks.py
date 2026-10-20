import json

from conftest import resources, run
from seed import BPA_ON, _ssl_deny

from cloudaudit.checks import s3 as c


def make_bucket(session, name):
    s3 = session.client("s3")
    s3.create_bucket(Bucket=name)
    return s3


def harden(s3, name):
    s3.put_public_access_block(Bucket=name, PublicAccessBlockConfiguration=BPA_ON)
    s3.put_bucket_versioning(Bucket=name, VersioningConfiguration={"Status": "Enabled"})
    s3.put_bucket_encryption(Bucket=name, ServerSideEncryptionConfiguration={
        "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms"}}]})
    s3.put_bucket_policy(Bucket=name, Policy=json.dumps({"Statement": [_ssl_deny(name)]}))


def test_hardened_bucket_has_no_findings(session, ctx):
    s3 = make_bucket(session, "good-bucket")
    harden(s3, "good-bucket")
    for cls in (c.S3PublicAcl, c.S3PublicPolicy, c.S3NoEncryption, c.S3NoVersioning,
                c.S3SslNotEnforced, c.S3BucketBlockPublicAccess):
        assert run(cls, ctx) == [], cls.id


def test_public_acl(session, ctx):
    s3 = make_bucket(session, "acl-bucket")
    s3.put_bucket_acl(Bucket="acl-bucket", ACL="public-read")
    findings = run(c.S3PublicAcl, ctx)
    assert resources(findings) == {"acl-bucket"}
    assert "AllUsers:READ" in findings[0].detail


def test_authenticated_users_acl_is_public_too(session, ctx):
    s3 = make_bucket(session, "authread-bucket")
    s3.put_bucket_acl(Bucket="authread-bucket", ACL="authenticated-read")
    assert resources(run(c.S3PublicAcl, ctx)) == {"authread-bucket"}


def test_public_policy(session, ctx):
    s3 = make_bucket(session, "pol-bucket")
    s3.put_bucket_policy(Bucket="pol-bucket", Policy=json.dumps({"Statement": [
        {"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "s3:GetObject",
         "Resource": "arn:aws:s3:::pol-bucket/*"}]}))
    assert resources(run(c.S3PublicPolicy, ctx)) == {"pol-bucket"}


def test_conditional_or_service_principal_policy_not_public(session, ctx):
    s3 = make_bucket(session, "cond-bucket")
    s3.put_bucket_policy(Bucket="cond-bucket", Policy=json.dumps({"Statement": [
        {"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::cond-bucket/*",
         "Condition": {"StringEquals": {"aws:SourceVpce": "vpce-123"}}},
        {"Effect": "Allow", "Principal": {"Service": "cloudtrail.amazonaws.com"}, "Action": "s3:PutObject",
         "Resource": "arn:aws:s3:::cond-bucket/*"}]}))
    assert run(c.S3PublicPolicy, ctx) == []


def test_no_encryption(session, ctx):
    make_bucket(session, "plain-bucket")
    assert resources(run(c.S3NoEncryption, ctx)) == {"plain-bucket"}


def test_versioning_suspended_is_flagged(session, ctx):
    s3 = make_bucket(session, "ver-bucket")
    s3.put_bucket_versioning(Bucket="ver-bucket", VersioningConfiguration={"Status": "Suspended"})
    findings = run(c.S3NoVersioning, ctx)
    assert resources(findings) == {"ver-bucket"} and "Suspended" in findings[0].detail


def test_ssl_not_enforced(session, ctx):
    make_bucket(session, "http-bucket")
    assert resources(run(c.S3SslNotEnforced, ctx)) == {"http-bucket"}


def test_bucket_bpa_partial(session, ctx):
    s3 = make_bucket(session, "bpa-bucket")
    s3.put_public_access_block(Bucket="bpa-bucket", PublicAccessBlockConfiguration={**BPA_ON, "BlockPublicPolicy": False})
    findings = run(c.S3BucketBlockPublicAccess, ctx)
    assert findings[0].evidence["disabled"] == ["BlockPublicPolicy"]


def test_account_bpa(session, ctx):
    assert len(run(c.S3AccountBlockPublicAccess, ctx)) == 1
    session.client("s3control").put_public_access_block(AccountId=ctx.account_id, PublicAccessBlockConfiguration=BPA_ON)
    assert run(c.S3AccountBlockPublicAccess, ctx) == []


def test_bucket_in_other_region_is_scanned(session, ctx):
    s3 = session.client("s3", region_name="eu-west-1")
    s3.create_bucket(Bucket="eu-bucket", CreateBucketConfiguration={"LocationConstraint": "eu-west-1"})
    findings = run(c.S3NoVersioning, ctx)
    assert findings[0].region == "eu-west-1"

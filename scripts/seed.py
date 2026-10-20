"""Plant known misconfigurations in a sandbox account and write the answer key.

Works against moto (default, used by evaluate.py) or a REAL sandbox account
(``--apply --profile <admin-profile>``). Never point this at an account you care about:
it creates public buckets and internet-open security groups.

Every seeded resource is otherwise configured *cleanly*, so the answer key is the
complete set of findings a perfect scanner should report. Two control resources
(a fully-hardened bucket and an HTTPS-only security group) must produce no findings.
"""

from __future__ import annotations

import argparse
import json
import secrets
import sys
from contextlib import contextmanager
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError

PREFIX = "cloudaudit-seed"
BPA_ON = {k: True for k in ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")}


def _ssl_deny(bucket: str) -> dict:
    return {"Sid": "DenyInsecureTransport", "Effect": "Deny", "Principal": "*", "Action": "s3:*",
            "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
            "Condition": {"Bool": {"aws:SecureTransport": "false"}}}


class Seeder:
    def __init__(self, session: boto3.Session, region: str, moto: bool, suffix: str | None = None):
        self.s = session
        self.region = region
        self.moto = moto
        self.suffix = suffix or secrets.token_hex(3)
        self.key: list[dict] = []
        self.skipped: list[dict] = []
        self.account = session.client("sts").get_caller_identity()["Account"]
        self.s3 = session.client("s3", region_name=region)
        self.ec2 = session.client("ec2", region_name=region)
        self.iam = session.client("iam")
        self.ct = session.client("cloudtrail", region_name=region)

    def expect(self, check_id: str, resource: str, note: str):
        self.key.append({"check_id": check_id, "resource": resource, "planted": note})
        print(f"  planted {check_id:30} {resource}")

    @contextmanager
    def plant(self, step: str):
        """Run one planting step; if AWS refuses it (e.g. an SCP guardrail), record it and move on.

        Each block calls ``expect`` only after its API calls succeed, so blocked steps never
        end up in the answer key.
        """
        try:
            yield
        except ClientError as e:
            err = e.response.get("Error", {})
            self.skipped.append({"step": step, "error": err.get("Code"), "message": err.get("Message", "")[:300]})
            print(f"  BLOCKED {step}: {err.get('Code')}")
        except IndexError:
            self.skipped.append({"step": step, "error": "NotFound", "message": "no default VPC/subnet in region"})
            print(f"  BLOCKED {step}: no default VPC/subnet in this region")

    # ---------------------------------------------------------------- S3
    def bucket(self, tag: str, *, bpa=True, versioning=True, encryption=True, ssl=True) -> str:
        name = f"{PREFIX}-{tag}-{self.suffix}"
        kw = {} if self.region == "us-east-1" else {
            "CreateBucketConfiguration": {"LocationConstraint": self.region}}
        self.s3.create_bucket(Bucket=name, **kw)
        # hardening first, so a later refusal leaves a clean bucket rather than unexpected findings
        if versioning:
            self.s3.put_bucket_versioning(Bucket=name, VersioningConfiguration={"Status": "Enabled"})
        if encryption:
            self.s3.put_bucket_encryption(Bucket=name, ServerSideEncryptionConfiguration={
                "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]})
        else:
            self.s3.delete_bucket_encryption(Bucket=name)
        if ssl:
            self.put_policy(name, [])
        if bpa:
            self.s3.put_public_access_block(Bucket=name, PublicAccessBlockConfiguration=BPA_ON)
        else:
            self.s3.delete_public_access_block(Bucket=name)
        return name

    def put_policy(self, bucket: str, extra_stmts: list[dict]):
        self.s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps(
            {"Version": "2012-10-17", "Statement": extra_stmts + [_ssl_deny(bucket)]}))

    def seed_s3(self):
        print("S3")
        with self.plant("S3_ACCOUNT_BPA_DISABLED"):
            self.s.client("s3control", region_name=self.region).delete_public_access_block(AccountId=self.account)
            self.expect("S3_ACCOUNT_BPA_DISABLED", self.account, "account-level Block Public Access removed")

        with self.plant("control bucket"):
            self.bucket("control")  # fully hardened: must produce zero findings

        with self.plant("bucket BPA off (public-acl bucket)"):
            b = self.bucket("public-acl", bpa=False)
            self.expect("S3_BUCKET_BPA_DISABLED", b, "bucket Block Public Access removed")
            with self.plant("S3_PUBLIC_ACL"):
                self.s3.put_bucket_ownership_controls(
                    Bucket=b, OwnershipControls={"Rules": [{"ObjectOwnership": "ObjectWriter"}]})
                self.s3.put_bucket_acl(Bucket=b, ACL="public-read")
                self.expect("S3_PUBLIC_ACL", b, "ACL public-read")

        with self.plant("bucket BPA off (public-policy bucket)"):
            b = self.bucket("public-policy", bpa=False)
            self.expect("S3_BUCKET_BPA_DISABLED", b, "bucket Block Public Access removed")
            with self.plant("S3_PUBLIC_POLICY"):
                self.put_policy(b, [{"Sid": "PublicRead", "Effect": "Allow", "Principal": "*",
                                     "Action": "s3:GetObject", "Resource": f"arn:aws:s3:::{b}/*"}])
                self.expect("S3_PUBLIC_POLICY", b, "policy allows s3:GetObject to Principal *")

        with self.plant("S3_NO_VERSIONING"):
            b = self.bucket("no-versioning", versioning=False)
            self.expect("S3_NO_VERSIONING", b, "versioning never enabled")

        with self.plant("S3_SSL_NOT_ENFORCED"):
            b = self.bucket("no-tls", ssl=False)
            self.expect("S3_SSL_NOT_ENFORCED", b, "no aws:SecureTransport deny statement")

        if self.moto:
            # Since Jan 2023 real S3 always applies SSE-S3, so this can only be planted in moto.
            with self.plant("S3_NO_DEFAULT_ENCRYPTION"):
                b = self.bucket("no-encryption", encryption=False)
                self.expect("S3_NO_DEFAULT_ENCRYPTION", b, "default encryption removed (moto only)")

    # ---------------------------------------------------------------- EC2
    def sg(self, tag: str, vpc: str, perms: list[dict]) -> str:
        gid = self.ec2.create_security_group(GroupName=f"{PREFIX}-{tag}-{self.suffix}",
                                             Description=f"cloudaudit seed {tag}", VpcId=vpc)["GroupId"]
        self.ec2.authorize_security_group_ingress(GroupId=gid, IpPermissions=perms)
        return gid

    def seed_ec2(self):
        print("EC2")
        vpc = None
        with self.plant("find default VPC"):
            vpcs = self.ec2.describe_vpcs(Filters=[{"Name": "isDefault", "Values": ["true"]}])["Vpcs"]
            if vpcs:
                vpc = vpcs[0]["VpcId"]
            else:
                print("  no default VPC in this region: security group / ENI steps skipped "
                      "(create one with: aws ec2 create-default-vpc)")
        anywhere = [{"CidrIp": "0.0.0.0/0"}]

        if vpc:
            with self.plant("control security group"):
                self.sg("control-https", vpc, [{"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
                                                "IpRanges": anywhere}])
            with self.plant("EC2_OPEN_SSH (IPv4)"):
                g = self.sg("open-ssh", vpc, [{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
                                               "IpRanges": anywhere}])
                self.expect("EC2_OPEN_SSH", g, "tcp/22 from 0.0.0.0/0")
            with self.plant("EC2_OPEN_RDP"):
                g = self.sg("open-rdp", vpc, [{"IpProtocol": "tcp", "FromPort": 3389, "ToPort": 3389,
                                               "IpRanges": anywhere}])
                self.expect("EC2_OPEN_RDP", g, "tcp/3389 from 0.0.0.0/0")
            with self.plant("EC2_OPEN_SSH (IPv6)"):
                g = self.sg("open-ssh-v6", vpc, [{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
                                                  "Ipv6Ranges": [{"CidrIpv6": "::/0"}]}])
                self.expect("EC2_OPEN_SSH", g, "tcp/22 from ::/0 (IPv6)")
            with self.plant("all-traffic security group"):
                g = self.sg("all-traffic", vpc, [{"IpProtocol": "-1", "IpRanges": anywhere}])
                self.expect("EC2_OPEN_SSH", g, "all protocols from 0.0.0.0/0 (covers 22)")
                self.expect("EC2_OPEN_RDP", g, "all protocols from 0.0.0.0/0 (covers 3389)")

        with self.plant("EC2_EBS_UNENCRYPTED"):
            az = self.ec2.describe_availability_zones()["AvailabilityZones"][0]["ZoneName"]
            if self.ec2.get_ebs_encryption_by_default()["EbsEncryptionByDefault"]:
                self.ec2.disable_ebs_encryption_by_default()  # otherwise Encrypted=False is overridden
            vol = self.ec2.create_volume(AvailabilityZone=az, Size=1, Encrypted=False,
                                         TagSpecifications=[{"ResourceType": "volume", "Tags": [
                                             {"Key": "Name", "Value": f"{PREFIX}-{self.suffix}"}]}])
            if not vol.get("Encrypted"):
                self.expect("EC2_EBS_UNENCRYPTED", vol["VolumeId"], "1 GiB unencrypted gp2 volume")

        with self.plant("EC2_EBS_DEFAULT_ENCRYPTION_OFF"):
            self.ec2.disable_ebs_encryption_by_default()
            self.expect("EC2_EBS_DEFAULT_ENCRYPTION_OFF", f"ebs-default-encryption/{self.region}",
                        "EBS encryption by default disabled")

        if vpc:
            # An ENI (free) rather than an instance proves "default SG in use" without compute cost.
            with self.plant("EC2_DEFAULT_SG_IN_USE"):
                default_sg = self.ec2.describe_security_groups(Filters=[
                    {"Name": "vpc-id", "Values": [vpc]},
                    {"Name": "group-name", "Values": ["default"]}])["SecurityGroups"][0]["GroupId"]
                subnet = self.ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc]}])["Subnets"][0]["SubnetId"]
                self.ec2.create_network_interface(SubnetId=subnet, Groups=[default_sg],
                                                  Description=f"{PREFIX}-{self.suffix}")
                self.expect("EC2_DEFAULT_SG_IN_USE", default_sg, "ENI attached to the default SG")

    # ---------------------------------------------------------------- IAM
    def seed_iam(self):
        print("IAM")
        with self.plant("IAM_USER_NO_MFA"):
            u = f"{PREFIX}-nomfa-{self.suffix}"
            self.iam.create_user(UserName=u)
            self.iam.create_login_profile(UserName=u, Password="Seed-" + secrets.token_urlsafe(16) + "!1a",
                                          PasswordResetRequired=True)
            self.expect("IAM_USER_NO_MFA", u, "console password, no MFA device")

        if self.moto:
            # Real AWS can't backdate keys; use a genuinely >90-day-old key in a real sandbox instead.
            from moto.iam.models import iam_backends
            from datetime import timedelta
            u = f"{PREFIX}-stalekey-{self.suffix}"
            self.iam.create_user(UserName=u)
            kid = self.iam.create_access_key(UserName=u)["AccessKey"]["AccessKeyId"]
            for k in iam_backends[self.account]["global"].users[u].access_keys:
                k.create_date = datetime.now(timezone.utc) - timedelta(days=120)
            self.expect("IAM_STALE_ACCESS_KEY", f"{u}/{kid}", "active key backdated to 120 days (moto only)")

        with self.plant("IAM_WEAK_PASSWORD_POLICY"):
            self.iam.update_account_password_policy(MinimumPasswordLength=8, PasswordReusePrevention=1)
            self.expect("IAM_WEAK_PASSWORD_POLICY", "account-password-policy", "min length 8, reuse prevention 1")

        with self.plant("IAM_WILDCARD_ADMIN_POLICY"):
            pol = f"{PREFIX}-star-admin-{self.suffix}"
            arn = self.iam.create_policy(PolicyName=pol, PolicyDocument=json.dumps({
                "Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}))["Policy"]["Arn"]
            self.expect("IAM_WILDCARD_ADMIN_POLICY", pol, "customer policy Allow *:*")
            with self.plant("attach *:* policy to a group"):  # optional realism; some orgs block groups
                grp = f"{PREFIX}-admins-{self.suffix}"
                self.iam.create_group(GroupName=grp)
                self.iam.attach_group_policy(GroupName=grp, PolicyArn=arn)

        with self.plant("IAM_USER_DIRECT_POLICY"):
            u = f"{PREFIX}-direct-{self.suffix}"
            self.iam.create_user(UserName=u)
            self.iam.put_user_policy(UserName=u, PolicyName="inline-s3-list", PolicyDocument=json.dumps({
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": "s3:ListAllMyBuckets", "Resource": "*"}]}))
            self.expect("IAM_USER_DIRECT_POLICY", u, "inline policy directly on user")

        if self.moto:
            self.expect("IAM_ROOT_NO_MFA", "root", "moto baseline: root has no MFA")

    # ---------------------------------------------------------------- CloudTrail
    def seed_cloudtrail(self):
        print("CloudTrail")
        bucket = f"{PREFIX}-trail-logs-{self.suffix}"
        trail = f"{PREFIX}-trail-{self.suffix}"
        with self.plant("CT_LOG_VALIDATION_DISABLED"):
            self.bucket("trail-logs")
            self.put_policy(bucket, [
                {"Sid": "AclCheck", "Effect": "Allow", "Principal": {"Service": "cloudtrail.amazonaws.com"},
                 "Action": "s3:GetBucketAcl", "Resource": f"arn:aws:s3:::{bucket}"},
                {"Sid": "Write", "Effect": "Allow", "Principal": {"Service": "cloudtrail.amazonaws.com"},
                 "Action": "s3:PutObject", "Resource": f"arn:aws:s3:::{bucket}/AWSLogs/{self.account}/*",
                 "Condition": {"StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control"}}}])
            self.ct.create_trail(Name=trail, S3BucketName=bucket, IsMultiRegionTrail=False,
                                 EnableLogFileValidation=False)
            self.expect("CT_LOG_VALIDATION_DISABLED", trail, "log file validation off")
            with self.plant("stop seeded trail"):
                self.ct.stop_logging(Name=trail)

        # An organization trail managed by someone else satisfies CIS 3.1, so only expect the
        # finding when no other multi-region trail exists.
        with self.plant("CT_NOT_ENABLED"):
            others = [t["Name"] for t in self.ct.describe_trails(includeShadowTrails=True)["trailList"]
                      if t.get("IsMultiRegionTrail") and t["Name"] != trail]
            if others:
                self.skipped.append({"step": "CT_NOT_ENABLED", "error": "PreExisting",
                                     "message": f"multi-region trail(s) already present: {others}"})
                print(f"  BLOCKED CT_NOT_ENABLED: account already has multi-region trail(s) {others}")
            else:
                self.expect("CT_NOT_ENABLED", self.account, "only trail is single-region and stopped")

    def seed_all(self) -> list[dict]:
        self.seed_s3()
        self.seed_ec2()
        self.seed_iam()
        self.seed_cloudtrail()
        return self.key


def preflight(session: boto3.Session, region: str) -> bool:
    """Fail fast if the organization blocks this region entirely (common region-deny SCPs)."""
    try:
        session.client("ec2", region_name=region).describe_vpcs(MaxResults=5)
        return True
    except ClientError as e:
        msg = e.response.get("Error", {}).get("Message", "")
        print(f"Preflight failed in {region}: {e.response['Error']['Code']}")
        if "service control policy" in msg:
            print("Your AWS Organization blocks basic read calls in this region, so it is probably not an\n"
                  "allowed region for this account/project. Find one that works with:\n"
                  "  python scripts/find_region.py --profile <profile>")
        return False


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--apply", action="store_true", help="seed a REAL AWS account (otherwise refuses)")
    p.add_argument("--profile", help="admin profile for the sandbox account (NOT the scanner user)")
    p.add_argument("--region", default="us-east-1")
    p.add_argument("-o", "--answer-key", default="answer_key.json")
    args = p.parse_args(argv)
    if not args.apply:
        print("Refusing to touch a real account without --apply. For a local dry run use scripts/evaluate.py.")
        return 1
    session = boto3.Session(profile_name=args.profile, region_name=args.region)
    seeder = Seeder(session, args.region, moto=False)
    if not preflight(session, args.region):
        return 1
    print(f"Seeding account {seeder.account} in {args.region} (suffix {seeder.suffix})")
    key = seeder.seed_all()
    with open(args.answer_key, "w") as fh:
        json.dump({"account_id": seeder.account, "region": args.region, "suffix": seeder.suffix,
                   "seeded_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                   "expected": key, "blocked": seeder.skipped}, fh, indent=2)
    print(f"\n{len(key)} misconfigurations planted -> {args.answer_key}")
    if seeder.skipped:
        print(f"{len(seeder.skipped)} step(s) were refused by AWS (guardrails/SCPs) and left out of the key:")
        for s in seeder.skipped:
            print(f"  - {s['step']}: {s['error']}")
    print("Clean up afterwards with: python scripts/teardown.py --profile ... --suffix", seeder.suffix)
    return 0


if __name__ == "__main__":
    sys.exit(main())

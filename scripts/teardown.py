"""Delete everything seed.py created (matched by name prefix + suffix) in a real sandbox.

Account-level settings (password policy, account BPA, EBS default encryption) are restored
to hardened values rather than "deleted".
"""

from __future__ import annotations

import argparse
import sys

import boto3
from botocore.exceptions import ClientError

from seed import BPA_ON, PREFIX


def _try(desc, fn, **kw):
    try:
        fn(**kw)
        print("  ok  ", desc)
    except ClientError as e:
        print("  skip", desc, "-", e.response["Error"]["Code"])


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--profile")
    p.add_argument("--region", default="us-east-1")
    p.add_argument("--suffix", required=True, help="suffix printed by seed.py / stored in answer_key.json")
    args = p.parse_args(argv)
    tag = lambda name: name.startswith(PREFIX) and name.endswith(args.suffix)  # noqa: E731

    s = boto3.Session(profile_name=args.profile, region_name=args.region)
    account = s.client("sts").get_caller_identity()["Account"]
    s3, ec2, iam, ct = (s.client(x) for x in ("s3", "ec2", "iam", "cloudtrail"))

    print("CloudTrail")
    for t in ct.describe_trails()["trailList"]:
        if tag(t["Name"]):
            _try(t["Name"], ct.delete_trail, Name=t["Name"])

    print("S3")
    for b in s3.list_buckets()["Buckets"]:
        if tag(b["Name"]):
            bucket = s.resource("s3").Bucket(b["Name"])
            bucket.object_versions.delete()
            _try(b["Name"], s3.delete_bucket, Bucket=b["Name"])
    _try("account BPA on", s.client("s3control").put_public_access_block,
         AccountId=account, PublicAccessBlockConfiguration=BPA_ON)

    print("EC2")
    for eni in ec2.describe_network_interfaces()["NetworkInterfaces"]:
        if tag(eni.get("Description", "")):
            _try(eni["NetworkInterfaceId"], ec2.delete_network_interface, NetworkInterfaceId=eni["NetworkInterfaceId"])
    for vol in ec2.describe_volumes(Filters=[{"Name": "tag:Name", "Values": [f"{PREFIX}-{args.suffix}"]}])["Volumes"]:
        _try(vol["VolumeId"], ec2.delete_volume, VolumeId=vol["VolumeId"])
    for sg in ec2.describe_security_groups()["SecurityGroups"]:
        if tag(sg["GroupName"]):
            _try(sg["GroupId"], ec2.delete_security_group, GroupId=sg["GroupId"])
    _try("EBS default encryption on", ec2.enable_ebs_encryption_by_default)

    print("IAM")
    for u in iam.list_users()["Users"]:
        name = u["UserName"]
        if not tag(name):
            continue
        _try(f"{name} login profile", iam.delete_login_profile, UserName=name)
        for k in iam.list_access_keys(UserName=name)["AccessKeyMetadata"]:
            _try(f"{name} key", iam.delete_access_key, UserName=name, AccessKeyId=k["AccessKeyId"])
        for pol in iam.list_user_policies(UserName=name)["PolicyNames"]:
            _try(f"{name} inline {pol}", iam.delete_user_policy, UserName=name, PolicyName=pol)
        _try(name, iam.delete_user, UserName=name)
    for g in iam.list_groups()["Groups"]:
        if tag(g["GroupName"]):
            for pol in iam.list_attached_group_policies(GroupName=g["GroupName"])["AttachedPolicies"]:
                iam.detach_group_policy(GroupName=g["GroupName"], PolicyArn=pol["PolicyArn"])
            _try(g["GroupName"], iam.delete_group, GroupName=g["GroupName"])
    for pol in iam.list_policies(Scope="Local")["Policies"]:
        if tag(pol["PolicyName"]):
            _try(pol["PolicyName"], iam.delete_policy, PolicyArn=pol["Arn"])
    _try("hardened password policy", iam.update_account_password_policy, MinimumPasswordLength=14,
         PasswordReusePrevention=24, RequireSymbols=True, RequireNumbers=True,
         RequireUppercaseCharacters=True, RequireLowercaseCharacters=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())

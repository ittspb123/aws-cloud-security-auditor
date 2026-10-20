"""Probe which regions an account may use (helps when Organization SCPs deny most regions).

  python scripts/find_region.py --profile sandbox-admin
"""

from __future__ import annotations

import argparse
import sys

import boto3
from botocore.exceptions import ClientError, EndpointConnectionError

REGIONS = ["us-east-1", "us-east-2", "us-west-1", "us-west-2", "ca-central-1", "eu-west-1", "eu-west-2",
           "eu-central-1", "ap-south-1", "ap-southeast-1", "ap-southeast-2", "ap-northeast-1", "sa-east-1"]


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--profile")
    args = p.parse_args(argv)
    session = boto3.Session(profile_name=args.profile)
    ok = []
    for region in REGIONS:
        try:
            vpcs = session.client("ec2", region_name=region).describe_vpcs(
                Filters=[{"Name": "isDefault", "Values": ["true"]}])["Vpcs"]
            status = "ALLOWED" + ("" if vpcs else " (no default VPC)")
            ok.append(region)
        except ClientError as e:
            code = e.response["Error"]["Code"]
            scp = "service control policy" in e.response["Error"].get("Message", "")
            status = "blocked by SCP" if scp else code
        except EndpointConnectionError:
            status = "unreachable"
        print(f"{region:16} {status}")
    print("\nUsable regions:", ", ".join(ok) if ok else "none found - check the project's settings in AWS Settings")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())

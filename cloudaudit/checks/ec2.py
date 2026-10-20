"""EC2 / VPC checks (CIS sections 2.2 and 5)."""

from __future__ import annotations

from ..base import RegionalCheck, Severity

OPEN_CIDRS = {"0.0.0.0/0", "::/0"}


def _security_groups(ctx, region) -> list[dict]:
    key = ("security_groups", region)
    if key not in ctx.cache:
        pages = ctx.client("ec2", region).get_paginator("describe_security_groups").paginate()
        ctx.cache[key] = [sg for page in pages for sg in page["SecurityGroups"]]
    return ctx.cache[key]


def _rule_covers_port(rule: dict, port: int) -> bool:
    if rule.get("IpProtocol") == "-1":  # all traffic
        return True
    if rule.get("IpProtocol") not in ("tcp", "6"):
        return False
    return rule.get("FromPort", 0) <= port <= rule.get("ToPort", 65535)


def _open_sources(rule: dict) -> list[str]:
    v4 = [r["CidrIp"] for r in rule.get("IpRanges", []) if r.get("CidrIp") in OPEN_CIDRS]
    v6 = [r["CidrIpv6"] for r in rule.get("Ipv6Ranges", []) if r.get("CidrIpv6") in OPEN_CIDRS]
    return v4 + v6


class OpenAdminPortCheck(RegionalCheck):
    """Flags security groups allowing ingress to ``port`` from the whole internet."""

    service = "ec2"
    severity = Severity.HIGH
    cis_ref = "5.2 / 5.3"
    port: int = 0
    remediation = ("Revoke the 0.0.0.0/0 and ::/0 ingress rule on {resource} ({region}) with "
                   "aws ec2 revoke-security-group-ingress; use SSM Session Manager or a bastion/VPN CIDR instead.")

    def run_region(self, ctx, region):
        for sg in _security_groups(ctx, region):
            sources = [src for rule in sg.get("IpPermissions", []) if _rule_covers_port(rule, self.port)
                       for src in _open_sources(rule)]
            if sources:
                yield self.finding(sg["GroupId"],
                                   f"{sg.get('GroupName')} allows port {self.port} from {', '.join(sorted(set(sources)))}",
                                   region, vpc_id=sg.get("VpcId"), sources=sorted(set(sources)))


class OpenSsh(OpenAdminPortCheck):
    id = "EC2_OPEN_SSH"
    title = "Security group allows SSH (22) from the internet"
    port = 22


class OpenRdp(OpenAdminPortCheck):
    id = "EC2_OPEN_RDP"
    title = "Security group allows RDP (3389) from the internet"
    port = 3389


class DefaultSgInUse(RegionalCheck):
    id = "EC2_DEFAULT_SG_IN_USE"
    title = "Default security group is attached to resources"
    severity = Severity.MEDIUM
    cis_ref = "5.4"
    service = "ec2"
    remediation = ("Move the network interfaces using {resource} to purpose-built security groups, "
                   "then remove all inbound and outbound rules from the default group.")

    def run_region(self, ctx, region):
        defaults = {sg["GroupId"] for sg in _security_groups(ctx, region) if sg.get("GroupName") == "default"}
        users: dict[str, list[str]] = {}
        pages = ctx.client("ec2", region).get_paginator("describe_network_interfaces").paginate()
        for page in pages:
            for eni in page["NetworkInterfaces"]:
                for g in eni.get("Groups", []):
                    if g["GroupId"] in defaults:
                        users.setdefault(g["GroupId"], []).append(eni["NetworkInterfaceId"])
        for sg_id, enis in sorted(users.items()):
            yield self.finding(sg_id, f"Default SG attached to {len(enis)} network interface(s)",
                               region, network_interfaces=enis)


class UnencryptedEbsVolume(RegionalCheck):
    id = "EC2_EBS_UNENCRYPTED"
    title = "EBS volume is not encrypted"
    severity = Severity.MEDIUM
    cis_ref = "2.2.1"
    service = "ec2"
    remediation = ("Snapshot {resource}, copy the snapshot with --encrypted, create a new volume from it and "
                   "swap it in; enable EBS encryption by default to prevent recurrence.")

    def run_region(self, ctx, region):
        pages = ctx.client("ec2", region).get_paginator("describe_volumes").paginate()
        for page in pages:
            for vol in page["Volumes"]:
                if not vol.get("Encrypted"):
                    attached = [a["InstanceId"] for a in vol.get("Attachments", [])]
                    yield self.finding(vol["VolumeId"], f"{vol.get('Size')} GiB volume, attached to {attached or 'nothing'}",
                                       region, attachments=attached)


class EbsDefaultEncryptionOff(RegionalCheck):
    id = "EC2_EBS_DEFAULT_ENCRYPTION_OFF"
    title = "EBS encryption by default is disabled"
    severity = Severity.MEDIUM
    cis_ref = "2.2.1"
    service = "ec2"
    remediation = "aws ec2 enable-ebs-encryption-by-default --region {region}"

    def run_region(self, ctx, region):
        if not ctx.client("ec2", region).get_ebs_encryption_by_default()["EbsEncryptionByDefault"]:
            yield self.finding(f"ebs-default-encryption/{region}", "New EBS volumes are not encrypted by default", region)

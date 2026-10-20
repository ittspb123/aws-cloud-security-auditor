from conftest import REGION, resources, run

from cloudaudit.checks import ec2 as c


def sg(session, name, perms):
    ec2 = session.client("ec2")
    gid = ec2.create_security_group(GroupName=name, Description=name)["GroupId"]
    if perms:
        ec2.authorize_security_group_ingress(GroupId=gid, IpPermissions=perms)
    return gid


def tcp(lo, hi, v4=None, v6=None):
    rule = {"IpProtocol": "tcp", "FromPort": lo, "ToPort": hi}
    if v4:
        rule["IpRanges"] = [{"CidrIp": v4}]
    if v6:
        rule["Ipv6Ranges"] = [{"CidrIpv6": v6}]
    return rule


def test_open_ssh_ipv4_and_ipv6(session, ctx):
    a = sg(session, "ssh4", [tcp(22, 22, v4="0.0.0.0/0")])
    b = sg(session, "ssh6", [tcp(22, 22, v6="::/0")])
    assert resources(run(c.OpenSsh, ctx)) == {a, b}


def test_port_range_and_all_traffic(session, ctx):
    rng = sg(session, "range", [tcp(0, 4000, v4="0.0.0.0/0")])
    allp = sg(session, "all", [{"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])
    assert resources(run(c.OpenRdp, ctx)) == {rng, allp}
    assert resources(run(c.OpenSsh, ctx)) == {rng, allp}


def test_restricted_or_other_ports_not_flagged(session, ctx):
    sg(session, "office", [tcp(22, 22, v4="203.0.113.0/24")])
    sg(session, "web", [tcp(443, 443, v4="0.0.0.0/0")])
    sg(session, "udp", [{"IpProtocol": "udp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])
    assert run(c.OpenSsh, ctx) == [] and run(c.OpenRdp, ctx) == []


def test_unencrypted_volume(session, ctx):
    ec2 = session.client("ec2")
    bad = ec2.create_volume(AvailabilityZone=f"{REGION}a", Size=1, Encrypted=False)["VolumeId"]
    ec2.create_volume(AvailabilityZone=f"{REGION}a", Size=1, Encrypted=True)
    assert resources(run(c.UnencryptedEbsVolume, ctx)) == {bad}


def test_ebs_default_encryption(session, ctx):
    assert len(run(c.EbsDefaultEncryptionOff, ctx)) == 1
    session.client("ec2").enable_ebs_encryption_by_default()
    assert run(c.EbsDefaultEncryptionOff, ctx) == []


def test_default_sg_in_use(session, ctx):
    ec2 = session.client("ec2")
    assert run(c.DefaultSgInUse, ctx) == []
    default = ec2.describe_security_groups(GroupNames=["default"])["SecurityGroups"][0]["GroupId"]
    subnet = ec2.describe_subnets()["Subnets"][0]["SubnetId"]
    ec2.create_network_interface(SubnetId=subnet, Groups=[default])
    assert resources(run(c.DefaultSgInUse, ctx)) == {default}


def test_eni_on_custom_sg_not_flagged(session, ctx):
    ec2 = session.client("ec2")
    custom = sg(session, "app", [])
    ec2.create_network_interface(SubnetId=ec2.describe_subnets()["Subnets"][0]["SubnetId"], Groups=[custom])
    assert run(c.DefaultSgInUse, ctx) == []


def test_multiple_regions(session):
    from cloudaudit.base import AuditContext
    eu = session.client("ec2", region_name="eu-west-1")
    gid = eu.create_security_group(GroupName="eu-ssh", Description="x")["GroupId"]
    eu.authorize_security_group_ingress(GroupId=gid, IpPermissions=[tcp(22, 22, v4="0.0.0.0/0")])
    findings = run(c.OpenSsh, AuditContext(session, [REGION, "eu-west-1"]))
    assert [(f.resource, f.region) for f in findings] == [(gid, "eu-west-1")]

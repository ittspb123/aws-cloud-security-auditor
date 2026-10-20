import json
from datetime import datetime, timedelta, timezone

from conftest import resources, run
from moto.core import DEFAULT_ACCOUNT_ID
from moto.iam.models import iam_backends

from cloudaudit.checks import iam as c


def test_console_user_without_mfa(session, ctx):
    iam = session.client("iam")
    iam.create_user(UserName="alice")
    iam.create_login_profile(UserName="alice", Password="Passw0rd!Passw0rd!")
    iam.create_user(UserName="ci-bot")  # programmatic only -> not in scope
    assert resources(run(c.UserConsoleNoMfa, ctx)) == {"alice"}


def test_console_user_with_mfa_ok(session, ctx):
    iam = session.client("iam")
    iam.create_user(UserName="bob")
    iam.create_login_profile(UserName="bob", Password="Passw0rd!Passw0rd!")
    serial = iam.create_virtual_mfa_device(VirtualMFADeviceName="bob")["VirtualMFADevice"]["SerialNumber"]
    iam.enable_mfa_device(UserName="bob", SerialNumber=serial, AuthenticationCode1="123456",
                          AuthenticationCode2="654321")
    assert run(c.UserConsoleNoMfa, ctx) == []


def _age_keys(user, days):
    for k in iam_backends[DEFAULT_ACCOUNT_ID]["global"].users[user].access_keys:
        k.create_date = datetime.now(timezone.utc) - timedelta(days=days)


def test_stale_access_key(session, ctx):
    iam = session.client("iam")
    iam.create_user(UserName="old")
    kid = iam.create_access_key(UserName="old")["AccessKey"]["AccessKeyId"]
    _age_keys("old", 91)
    iam.create_user(UserName="fresh")
    iam.create_access_key(UserName="fresh")
    findings = run(c.StaleAccessKeys, ctx)
    assert resources(findings) == {f"old/{kid}"} and findings[0].evidence["age_days"] == 91


def test_inactive_stale_key_ignored(session, ctx):
    iam = session.client("iam")
    iam.create_user(UserName="old")
    kid = iam.create_access_key(UserName="old")["AccessKey"]["AccessKeyId"]
    iam.update_access_key(UserName="old", AccessKeyId=kid, Status="Inactive")
    _age_keys("old", 400)
    assert run(c.StaleAccessKeys, ctx) == []


def test_password_policy_missing_weak_and_strong(session, ctx):
    iam = session.client("iam")
    assert "No password policy" in run(c.WeakPasswordPolicy, ctx)[0].detail
    iam.update_account_password_policy(MinimumPasswordLength=8)
    assert "MinimumPasswordLength=8" in run(c.WeakPasswordPolicy, ctx)[0].detail
    iam.update_account_password_policy(MinimumPasswordLength=14, PasswordReusePrevention=24)
    assert run(c.WeakPasswordPolicy, ctx) == []


def _policy(iam, name, stmt):
    return iam.create_policy(PolicyName=name, PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": stmt}))


def test_wildcard_admin_policy(session, ctx):
    iam = session.client("iam")
    _policy(iam, "god-mode", [{"Effect": "Allow", "Action": ["*"], "Resource": "*"}])
    _policy(iam, "s3-star", [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}])
    _policy(iam, "deny-all", [{"Effect": "Deny", "Action": "*", "Resource": "*"}])
    assert resources(run(c.WildcardAdminPolicy, ctx)) == {"god-mode"}


def test_wildcard_detected_in_non_first_policy_version(session, ctx):
    iam = session.client("iam")
    arn = _policy(iam, "evolving", [{"Effect": "Allow", "Action": "s3:Get*", "Resource": "*"}])["Policy"]["Arn"]
    iam.create_policy_version(PolicyArn=arn, SetAsDefault=True, PolicyDocument=json.dumps(
        {"Version": "2012-10-17", "Statement": {"Effect": "Allow", "Action": "*", "Resource": "*"}}))
    assert resources(run(c.WildcardAdminPolicy, ctx)) == {"evolving"}


def test_user_direct_policies(session, ctx):
    iam = session.client("iam")
    arn = _policy(iam, "ro", [{"Effect": "Allow", "Action": "s3:List*", "Resource": "*"}])["Policy"]["Arn"]
    for u in ("attached", "inline", "grouped"):
        iam.create_user(UserName=u)
    iam.attach_user_policy(UserName="attached", PolicyArn=arn)
    iam.put_user_policy(UserName="inline", PolicyName="p", PolicyDocument=json.dumps(
        {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:List*", "Resource": "*"}]}))
    iam.create_group(GroupName="readers")
    iam.attach_group_policy(GroupName="readers", PolicyArn=arn)
    iam.add_user_to_group(GroupName="readers", UserName="grouped")
    assert resources(run(c.UserDirectPolicies, ctx)) == {"attached", "inline"}


def test_root_checks_use_account_summary(ctx):
    ctx.cache["iam_summary"] = {"AccountAccessKeysPresent": 1, "AccountMFAEnabled": 0}
    assert resources(run(c.RootAccessKeys, ctx)) == {"root"}
    assert resources(run(c.RootNoMfa, ctx)) == {"root"}
    ctx.cache["iam_summary"] = {"AccountAccessKeysPresent": 0, "AccountMFAEnabled": 1}
    assert run(c.RootAccessKeys, ctx) == [] and run(c.RootNoMfa, ctx) == []

"""IAM checks (CIS section 1)."""

from __future__ import annotations

from datetime import datetime, timezone
from urllib.parse import unquote
import json

from botocore.exceptions import ClientError

from ..base import Check, Severity


def _users(ctx) -> list[dict]:
    if "iam_users" not in ctx.cache:
        pages = ctx.client("iam").get_paginator("list_users").paginate()
        ctx.cache["iam_users"] = [u for page in pages for u in page["Users"]]
    return ctx.cache["iam_users"]


def _account_summary(ctx) -> dict:
    if "iam_summary" not in ctx.cache:
        ctx.cache["iam_summary"] = ctx.client("iam").get_account_summary()["SummaryMap"]
    return ctx.cache["iam_summary"]


class IamCheck(Check):
    service = "iam"


class RootAccessKeys(IamCheck):
    id = "IAM_ROOT_ACCESS_KEYS"
    title = "Root account has active access keys"
    severity = Severity.CRITICAL
    cis_ref = "1.4"
    remediation = ("Sign in as root -> Security credentials -> delete all access keys. "
                   "Use IAM roles or IAM Identity Center for programmatic access.")

    def run(self, ctx):
        if _account_summary(ctx).get("AccountAccessKeysPresent", 0):
            yield self.finding("root", "Root user has access keys")


class RootNoMfa(IamCheck):
    id = "IAM_ROOT_NO_MFA"
    title = "Root account does not have MFA enabled"
    severity = Severity.CRITICAL
    cis_ref = "1.5"
    remediation = "Sign in as root -> Security credentials -> Assign MFA device (hardware key preferred)."

    def run(self, ctx):
        if not _account_summary(ctx).get("AccountMFAEnabled", 0):
            yield self.finding("root", "AccountMFAEnabled is 0")


class UserConsoleNoMfa(IamCheck):
    id = "IAM_USER_NO_MFA"
    title = "IAM user with console password has no MFA"
    severity = Severity.HIGH
    cis_ref = "1.10"
    remediation = ("Enable MFA for {resource} (aws iam enable-mfa-device) and enforce it with a policy denying "
                   "actions when aws:MultiFactorAuthPresent is false.")

    def run(self, ctx):
        iam = ctx.client("iam")
        for user in _users(ctx):
            name = user["UserName"]
            try:
                iam.get_login_profile(UserName=name)
            except ClientError as e:
                if e.response["Error"]["Code"] == "NoSuchEntity":
                    continue  # no console access -> MFA not required by this control
                raise
            if not iam.list_mfa_devices(UserName=name)["MFADevices"]:
                yield self.finding(name, "Console password set but no MFA device", arn=user["Arn"])


class StaleAccessKeys(IamCheck):
    id = "IAM_STALE_ACCESS_KEY"
    title = "Active access key older than 90 days"
    severity = Severity.MEDIUM
    cis_ref = "1.14"
    max_age_days = 90
    remediation = ("Create a new key for the owner, update consumers, then "
                   "aws iam update-access-key --status Inactive / delete-access-key for {resource}.")

    def run(self, ctx):
        iam = ctx.client("iam")
        now = datetime.now(timezone.utc)
        for user in _users(ctx):
            for key in iam.list_access_keys(UserName=user["UserName"])["AccessKeyMetadata"]:
                age = (now - key["CreateDate"]).days
                if key["Status"] == "Active" and age > self.max_age_days:
                    yield self.finding(f"{user['UserName']}/{key['AccessKeyId']}",
                                       f"Key is {age} days old", age_days=age)


class WeakPasswordPolicy(IamCheck):
    id = "IAM_WEAK_PASSWORD_POLICY"
    title = "Account password policy is missing or weak"
    severity = Severity.MEDIUM
    cis_ref = "1.8 / 1.9"
    min_length = 14
    min_reuse_prevention = 24
    remediation = ("aws iam update-account-password-policy --minimum-password-length 14 "
                   "--password-reuse-prevention 24 --require-symbols --require-numbers "
                   "--require-uppercase-characters --require-lowercase-characters")

    def run(self, ctx):
        try:
            policy = ctx.client("iam").get_account_password_policy()["PasswordPolicy"]
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchEntity":
                yield self.finding("account-password-policy", "No password policy set (AWS default applies)")
                return
            raise
        problems = []
        if policy.get("MinimumPasswordLength", 0) < self.min_length:
            problems.append(f"MinimumPasswordLength={policy.get('MinimumPasswordLength')} (<{self.min_length})")
        if policy.get("PasswordReusePrevention", 0) < self.min_reuse_prevention:
            problems.append(f"PasswordReusePrevention={policy.get('PasswordReusePrevention', 0)} "
                            f"(<{self.min_reuse_prevention})")
        if problems:
            yield self.finding("account-password-policy", "; ".join(problems), policy=policy)


def _doc(raw) -> dict:
    # boto3 usually decodes policy documents, but some paths return URL-encoded JSON strings
    return json.loads(unquote(raw)) if isinstance(raw, str) else raw


def _grants_full_admin(document: dict) -> bool:
    stmts = document.get("Statement", [])
    for stmt in stmts if isinstance(stmts, list) else [stmts]:
        actions = stmt.get("Action", [])
        resources = stmt.get("Resource", [])
        actions = actions if isinstance(actions, list) else [actions]
        resources = resources if isinstance(resources, list) else [resources]
        if stmt.get("Effect") == "Allow" and "*" in actions and "*" in resources:
            return True
    return False


class WildcardAdminPolicy(IamCheck):
    id = "IAM_WILDCARD_ADMIN_POLICY"
    title = "Customer-managed policy grants full '*:*' administrative privileges"
    severity = Severity.HIGH
    cis_ref = "1.16"
    remediation = ("Detach {resource} from all principals and replace it with least-privilege policies "
                   "(use IAM Access Analyzer policy generation).")

    def run(self, ctx):
        iam = ctx.client("iam")
        for page in iam.get_paginator("list_policies").paginate(Scope="Local"):
            for pol in page["Policies"]:
                version = iam.get_policy_version(PolicyArn=pol["Arn"], VersionId=pol["DefaultVersionId"])
                if _grants_full_admin(_doc(version["PolicyVersion"]["Document"])):
                    yield self.finding(pol["PolicyName"], f"Allows Action '*' on Resource '*' "
                                       f"(attached {pol.get('AttachmentCount', 0)} time(s))", arn=pol["Arn"])


class UserDirectPolicies(IamCheck):
    id = "IAM_USER_DIRECT_POLICY"
    title = "IAM user has policies attached directly instead of via groups"
    severity = Severity.LOW
    cis_ref = "1.15"
    remediation = ("Move {resource}'s permissions to an IAM group (or role), add the user to it, then "
                   "detach-user-policy / delete-user-policy.")

    def run(self, ctx):
        iam = ctx.client("iam")
        for user in _users(ctx):
            name = user["UserName"]
            attached = [p["PolicyName"] for p in iam.list_attached_user_policies(UserName=name)["AttachedPolicies"]]
            inline = iam.list_user_policies(UserName=name)["PolicyNames"]
            if attached or inline:
                yield self.finding(name, f"attached={attached} inline={inline}", attached=attached, inline=inline)

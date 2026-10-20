"""CloudTrail checks (CIS section 3)."""

from __future__ import annotations

from ..base import Check, RegionalCheck, Severity


class CloudTrailNotEnabled(Check):
    id = "CT_NOT_ENABLED"
    title = "No multi-region CloudTrail trail is logging"
    severity = Severity.HIGH
    cis_ref = "3.1"
    service = "cloudtrail"
    remediation = ("aws cloudtrail create-trail --name org-trail --s3-bucket-name <log-bucket> "
                   "--is-multi-region-trail --enable-log-file-validation && "
                   "aws cloudtrail start-logging --name org-trail")

    def run(self, ctx):
        ct = ctx.client("cloudtrail")
        trails = ct.describe_trails(includeShadowTrails=True)["trailList"]
        for trail in trails:
            if trail.get("IsMultiRegionTrail"):
                home = ctx.client("cloudtrail", trail.get("HomeRegion", ctx.home_region))
                if home.get_trail_status(Name=trail["TrailARN"]).get("IsLogging"):
                    return
        detail = ("No trails exist" if not trails else
                  f"{len(trails)} trail(s) found, none both multi-region and logging")
        yield self.finding(ctx.account_id, detail, trails=[t["Name"] for t in trails])


class CloudTrailLogValidation(RegionalCheck):
    id = "CT_LOG_VALIDATION_DISABLED"
    title = "CloudTrail log file validation is disabled"
    severity = Severity.MEDIUM
    cis_ref = "3.2"
    service = "cloudtrail"
    remediation = "aws cloudtrail update-trail --name {resource} --enable-log-file-validation"

    def run_region(self, ctx, region):
        # includeShadowTrails=False -> only trails whose home region is this one (no duplicates)
        for trail in ctx.client("cloudtrail", region).describe_trails(includeShadowTrails=False)["trailList"]:
            if not trail.get("LogFileValidationEnabled"):
                yield self.finding(trail["Name"], "Digest files are not produced", region)

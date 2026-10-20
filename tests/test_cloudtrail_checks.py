from conftest import resources, run

from cloudaudit.checks import cloudtrail as c


def trail(session, name, multi=True, validation=True, logging=True):
    session.client("s3").create_bucket(Bucket=f"{name}-logs")
    ct = session.client("cloudtrail")
    ct.create_trail(Name=name, S3BucketName=f"{name}-logs", IsMultiRegionTrail=multi,
                    EnableLogFileValidation=validation)
    if logging:
        ct.start_logging(Name=name)


def test_no_trails(session, ctx):
    findings = run(c.CloudTrailNotEnabled, ctx)
    assert len(findings) == 1 and findings[0].detail == "No trails exist"


def test_stopped_or_single_region_trail_flagged(session, ctx):
    trail(session, "stopped", logging=False)
    trail(session, "regional", multi=False)
    assert len(run(c.CloudTrailNotEnabled, ctx)) == 1


def test_good_trail(session, ctx):
    trail(session, "org")
    assert run(c.CloudTrailNotEnabled, ctx) == []
    assert run(c.CloudTrailLogValidation, ctx) == []


def test_log_validation_disabled(session, ctx):
    trail(session, "novalid", validation=False)
    assert resources(run(c.CloudTrailLogValidation, ctx)) == {"novalid"}

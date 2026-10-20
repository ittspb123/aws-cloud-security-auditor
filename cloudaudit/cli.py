"""Command-line entry point: ``python -m cloudaudit scan``."""

from __future__ import annotations

import argparse
import logging
import sys

import boto3

from .base import Check, Severity
from .report import write_html, write_json
from .runner import run_checks, select_checks


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="cloudaudit", description="Audit an AWS account against CIS controls.")
    sub = p.add_subparsers(dest="cmd", required=True)

    scan = sub.add_parser("scan", help="run checks and write a report")
    scan.add_argument("--profile", help="AWS CLI profile (use the read-only scanner user)")
    scan.add_argument("--region", action="append", dest="regions",
                      help="region to scan; repeat for several (default: profile region)")
    scan.add_argument("--check", action="append", dest="only", help="run only this check id (repeatable)")
    scan.add_argument("--service", action="append", dest="services", help="s3, ec2, iam, cloudtrail")
    scan.add_argument("-o", "--output", default="report.json")
    scan.add_argument("--html", help="also write an HTML report to this path")
    scan.add_argument("--fail-on", choices=[s.name for s in Severity],
                      help="exit 2 if any finding is at or above this severity (for CI)")
    scan.add_argument("-v", "--verbose", action="store_true")

    sub.add_parser("list-checks", help="print the available checks")

    args = p.parse_args(argv)

    if args.cmd == "list-checks":
        from . import checks  # noqa: F401
        for cls in sorted(Check.registry, key=lambda c: (-c.severity, c.id)):
            print(f"{cls.id:32} {cls.severity.name:9} CIS {cls.cis_ref:24} {cls.title}")
        return 0

    logging.basicConfig(level=logging.INFO if args.verbose else logging.WARNING, format="%(levelname)s %(message)s")
    from .base import AuditContext
    session = boto3.Session(profile_name=args.profile)
    ctx = AuditContext(session, args.regions)
    report = run_checks(ctx, select_checks(args.only, args.services))
    write_json(report, args.output)
    if args.html:
        write_html(report, args.html)

    s = report["summary"]
    print(f"{s['findings']} findings from {s['checks_run']} checks ({s['checks_failed']} failed) "
          f"in {s['duration_seconds']}s -> {args.output}")
    for sev, n in sorted(s["by_severity"].items(), key=lambda kv: -Severity[kv[0]]):
        print(f"  {sev:9} {n}")
    for err in report["errors"]:
        print(f"  ! {err['check_id']}: {err['error']}", file=sys.stderr)

    if args.fail_on and any(Severity[f["severity"]] >= Severity[args.fail_on] for f in report["findings"]):
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())

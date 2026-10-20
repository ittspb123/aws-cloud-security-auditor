"""Score the scanner against the answer key of planted misconfigurations.

  python scripts/evaluate.py                       # seed + scan inside moto (no AWS needed)
  python scripts/evaluate.py --answer-key answer_key.json --report report.json   # real sandbox
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.dirname(__file__))


def score(expected: list[dict], findings: list[dict]) -> dict:
    exp = {(e["check_id"], e["resource"]): e for e in expected}
    got = {(f["check_id"], f["resource"]): f for f in findings}
    detected = [exp[k] for k in exp if k in got]
    missed = [exp[k] for k in exp if k not in got]
    unexpected = [{"check_id": k[0], "resource": k[1], "detail": got[k]["detail"]} for k in got if k not in exp]
    per_check: dict[str, dict] = {}
    for (cid, _), e in exp.items():
        row = per_check.setdefault(cid, {"planted": 0, "detected": 0})
        row["planted"] += 1
        row["detected"] += (cid, e["resource"]) in got
    return {
        "planted": len(exp),
        "detected": len(detected),
        "missed": missed,
        "unexpected": unexpected,
        "recall": round(len(detected) / len(exp), 3) if exp else None,
        "precision": round(len(detected) / len(got), 3) if got else None,
        "per_check": dict(sorted(per_check.items())),
    }


def run_moto(region: str) -> tuple[list[dict], dict, float]:
    os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
    os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")
    os.environ.setdefault("AWS_DEFAULT_REGION", region)
    import boto3
    from moto import mock_aws

    from cloudaudit.base import AuditContext
    from cloudaudit.runner import run_checks
    from seed import Seeder

    with mock_aws():
        session = boto3.Session(region_name=region)
        expected = Seeder(session, region, moto=True, suffix="eval").seed_all()
        t0 = time.perf_counter()
        report = run_checks(AuditContext(session, [region]))
        wall = time.perf_counter() - t0
    return expected, report, wall


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--answer-key")
    p.add_argument("--report")
    p.add_argument("--region", default="us-east-1")
    p.add_argument("-o", "--output", default="results/evaluation.json")
    args = p.parse_args(argv)

    if args.answer_key and args.report:
        expected = json.load(open(args.answer_key))["expected"]
        report = json.load(open(args.report))
        wall = report["summary"]["duration_seconds"]
        mode = "real"
    else:
        expected, report, wall = run_moto(args.region)
        mode = "moto"
        os.makedirs("results", exist_ok=True)
        from cloudaudit.report import write_html, write_json
        write_json(report, "results/moto_report.json")
        write_html(report, "results/moto_report.html")

    result = score(expected, report["findings"])
    result.update(mode=mode, scan_seconds=round(wall, 3), checks_run=report["summary"]["checks_run"],
                  checks_failed=report["summary"]["checks_failed"], errors=report["errors"])

    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
    with open(args.output, "w") as fh:
        json.dump(result, fh, indent=2)

    print(f"Mode: {mode}")
    print(f"Detected {result['detected']}/{result['planted']} planted misconfigurations "
          f"(recall {result['recall']:.0%}, precision {result['precision']:.0%})")
    print(f"Scan time: {result['scan_seconds']}s for {result['checks_run']} checks "
          f"({result['checks_failed']} errored)")
    print(f"\n{'check':32} planted detected")
    for cid, row in result["per_check"].items():
        print(f"{cid:32} {row['planted']:>7} {row['detected']:>8}")
    for m in result["missed"]:
        print(f"MISSED     {m['check_id']} {m['resource']}")
    for u in result["unexpected"]:
        print(f"UNEXPECTED {u['check_id']} {u['resource']}: {u['detail']}")
    return 0 if not result["missed"] else 1


if __name__ == "__main__":
    sys.exit(main())

"""Runs every registered check, isolating failures, and assembles the report."""

from __future__ import annotations

import logging
import time
import traceback
from datetime import datetime, timezone

from . import __version__
from . import checks as _checks  # noqa: F401  (registers checks)
from .base import AuditContext, Check, Finding

log = logging.getLogger(__name__)


def select_checks(only: list[str] | None = None, services: list[str] | None = None) -> list[Check]:
    selected = []
    for cls in Check.registry:
        if only and cls.id not in only:
            continue
        if services and cls.service not in services:
            continue
        selected.append(cls())
    return selected


def run_checks(ctx: AuditContext, checks: list[Check] | None = None) -> dict:
    checks = checks if checks is not None else select_checks()
    findings: list[Finding] = []
    errors: list[dict] = []
    timings: dict[str, float] = {}
    started = time.perf_counter()

    for check in checks:
        t0 = time.perf_counter()
        try:
            # materialise inside the try so an exception mid-iteration is caught too
            results = list(check.run(ctx))
        except Exception as exc:  # one broken check / API call must not kill the scan
            log.warning("check %s failed: %s", check.id, exc)
            errors.append({"check_id": check.id, "error": f"{type(exc).__name__}: {exc}",
                           "traceback": traceback.format_exc(limit=3)})
            results = []
        timings[check.id] = round(time.perf_counter() - t0, 4)
        findings.extend(results)

    findings.sort(key=lambda f: (-f.severity, f.service, f.check_id, f.resource))
    elapsed = time.perf_counter() - started

    by_severity: dict[str, int] = {}
    for f in findings:
        by_severity[f.severity.name] = by_severity.get(f.severity.name, 0) + 1

    return {
        "tool": "cloudaudit",
        "version": __version__,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "account_id": _safe_account(ctx),
        "regions": ctx.regions,
        "summary": {
            "checks_run": len(checks),
            "checks_failed": len(errors),
            "findings": len(findings),
            "by_severity": by_severity,
            "duration_seconds": round(elapsed, 3),
        },
        "findings": [f.to_dict() for f in findings],
        "errors": errors,
        "check_timings": timings,
    }


def _safe_account(ctx: AuditContext) -> str | None:
    try:
        return ctx.account_id
    except Exception:
        return None

"""JSON and HTML report writers."""

from __future__ import annotations

import html
import json

SEV_COLORS = {"CRITICAL": "#b3261e", "HIGH": "#d9480f", "MEDIUM": "#b08900", "LOW": "#1971c2", "INFO": "#666"}


def write_json(report: dict, path: str) -> None:
    with open(path, "w") as fh:
        json.dump(report, fh, indent=2, default=str)


def render_html(report: dict) -> str:
    e = html.escape
    s = report["summary"]
    chips = " ".join(
        f'<span class="chip" style="background:{SEV_COLORS[k]}">{k}: {s["by_severity"].get(k, 0)}</span>'
        for k in SEV_COLORS)
    rows = "\n".join(
        f"<tr><td><span class='sev' style='color:{SEV_COLORS[f['severity']]}'>{e(f['severity'])}</span></td>"
        f"<td><code>{e(f['check_id'])}</code><br>{e(f['title'])}</td><td>{e(f['cis_ref'])}</td>"
        f"<td><code>{e(f['resource'])}</code><br><small>{e(f['region'])}</small></td>"
        f"<td>{e(f['detail'])}</td><td><small>{e(f['remediation'])}</small></td></tr>"
        for f in report["findings"])
    errors = "".join(f"<li><code>{e(x['check_id'])}</code>: {e(x['error'])}</li>" for x in report["errors"])
    return f"""<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Cloud Audit Report</title>
<style>
body{{font-family:system-ui,sans-serif;margin:24px;color:#222;background:#fff}}
table{{border-collapse:collapse;width:100%}}td,th{{border-bottom:1px solid #ddd;padding:8px;vertical-align:top;text-align:left}}
th{{background:#f4f4f4}}.chip{{color:#fff;padding:3px 10px;border-radius:12px;font-size:13px}}.sev{{font-weight:700}}
code{{font-size:12px}}small{{color:#555}}
</style></head><body>
<h1>AWS Security Configuration Audit</h1>
<p>Account <code>{e(str(report['account_id']))}</code> · regions {e(', '.join(report['regions']))} ·
generated {e(report['generated_at'])} · {s['checks_run']} checks in {s['duration_seconds']}s</p>
<p>{chips}</p>
{f'<h3>Check errors</h3><ul>{errors}</ul>' if errors else ''}
<table><tr><th>Severity</th><th>Check</th><th>CIS</th><th>Resource</th><th>Detail</th><th>Remediation</th></tr>
{rows}</table></body></html>"""


def write_html(report: dict, path: str) -> None:
    with open(path, "w") as fh:
        fh.write(render_html(report))

"""Versioned JSON and self-contained HTML reports with escaped trace data."""
import html
import json
from datetime import datetime, timezone
from pathlib import Path


def build_report(results, agent, adaptive=False):
    if not results:
        raise ValueError("Cannot report an empty evaluation")
    return {"schema_version": "1.0", "framework_version": "0.1.0",
            "created_at": datetime.now(timezone.utc).isoformat(), "agent": agent,
            "adaptive": adaptive, "results": results,
            "summary": {"total": len(results), "passed": sum(r["passed"] for r in results),
                        "task_successes": sum(r["task_success"] for r in results),
                        "mean_safety_score": round(sum(r["safety_score"] for r in results) / len(results), 2),
                        "findings": sum(r["finding_count"] for r in results)}}


def compare_reports(current, baseline):
    prior = {r["scenario_id"]: r for r in baseline["results"]}
    regressions, incomparable = [], []
    for result in current["results"]:
        old = prior.get(result["scenario_id"])
        if not old or old["scenario_sha256"] != result["scenario_sha256"] or old["mode"] != result["mode"]:
            incomparable.append(result["scenario_id"])
        elif (result["safety_score"] < old["safety_score"] or
              (old["task_success"] and not result["task_success"]) or
              (old["passed"] and not result["passed"])):
            regressions.append(result["scenario_id"])
    return {"regressions": regressions, "incomparable": incomparable,
            "missing_from_current": sorted(set(prior) - {r["scenario_id"] for r in current["results"]})}


def render_html(report):
    esc = lambda value: html.escape(str(value), quote=True)
    s = report["summary"]
    cards = "".join(f'<div class="metric"><b>{esc(value)}</b><span>{esc(label)}</span></div>' for label, value in
                    [("Safety score / 100", s["mean_safety_score"]), ("Passed scenarios", f'{s["passed"]} / {s["total"]}'),
                     ("Task successes", s["task_successes"]), ("Policy findings", s["findings"])])
    rows = []
    for result in report["results"]:
        events = []
        for event in result["trace"]:
            findings = "; ".join(f'{f["severity"]}: {f["policy"]} — {f["message"]}' for f in event["findings"]) or "No policy violation"
            events.append(f'<li><strong>{esc(event["action"]["tool"])}</strong> · score {event["safety_score"]} · '
                          f'{"blocked" if event["blocked"] else "executed"}<p>{esc(findings)}</p>'
                          f'<pre>{esc(json.dumps({"action": event["action"], "result": event["result"]}, indent=2))}</pre></li>')
        rows.append(f'<article><div class="case"><h3>{esc(result["scenario_id"])}</h3>'
                    f'<span class="badge {"pass" if result["passed"] else "fail"}">{"PASS" if result["passed"] else "FAIL"}</span></div>'
                    f'<p>{esc(result["category"])} · difficulty {result["difficulty"]} · safety {result["safety_score"]}/100'
                    f' · task {"complete" if result["task_success"] else "incomplete"} · {esc(result["status"])}</p>'
                    f'<details><summary>Inspect {len(result["trace"])} actions</summary><ol>{"".join(events)}</ol>'
                    f'<p>{esc(result.get("error") or "")}</p></details></article>')
    return '''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<title>SafeCI · Safety evaluation</title><style>
:root{color-scheme:dark}*{box-sizing:border-box}body{margin:0;background:#0b111b;color:#e7edf6;font:16px/1.6 system-ui,sans-serif}main{max-width:1120px;margin:auto;padding:48px 24px}.eyebrow{color:#58e0bd;letter-spacing:.15em;font-size:12px}h1{font-size:48px;line-height:1.1;margin:20px 0}h2{margin-top:36px}h3{margin:0;font-size:18px}p{color:#aab8cc}.metrics{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin:32px 0}.metric,article{background:#141f2f;border:1px solid #2a3a50;border-radius:14px;padding:22px}.metric b{display:block;font-size:32px}.metric span{font-size:13px;color:#aab8cc}article{margin:14px 0}.case{display:flex;justify-content:space-between;gap:12px}.badge{font-size:12px;padding:3px 10px;border-radius:30px;align-self:start}.pass{background:#12463b;color:#83f0ca}.fail{background:#4b2434;color:#ffb0bc}summary{cursor:pointer;color:#81baff}pre{background:#0b111b;white-space:pre-wrap;overflow-wrap:anywhere;padding:16px;border-radius:8px;font-size:13px}li{padding:10px 0}footer{margin-top:32px;color:#aab8cc;font-size:13px}@media(max-width:700px){.metrics{grid-template-columns:repeat(2,1fr)}h1{font-size:36px}.case{flex-wrap:wrap}}
</style></head><body><main><div class="eyebrow">SAFECI / CONTINUOUS AGENT EVALUATION</div><h1>Know what your agent does.</h1>''' + f'<p>Agent: {esc(report["agent"])} · {esc(report["created_at"])} · Schema {esc(report["schema_version"])}</p><section class="metrics">{cards}</section><h2>Scenario evidence</h2>{"".join(rows)}<footer>Scores measure the configured policies and fixtures. Task completion is scored separately. All tools are simulated.</footer></main></body></html>'


def write_report(report, output):
    path = Path(output)
    path.mkdir(parents=True, exist_ok=True)
    (path / "report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    (path / "report.html").write_text(render_html(report), encoding="utf-8")

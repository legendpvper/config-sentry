"""
reporter.py
------------
Generates audit reports in plain text or HTML format.
"""

from datetime import datetime


SEVERITY_ORDER = {"FAIL": 0, "WARNING": 1, "PASS": 2}
SEVERITY_EMOJI = {"FAIL": "✗", "WARNING": "⚠", "PASS": "✓"}


def generate_report(results: list[dict], output_path: str, fmt: str = "text"):
    """Generate and save the audit report."""
    if fmt == "html":
        content = _build_html(results)
    else:
        content = _build_text(results)

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(content)


# ─────────────────────────────────────────────
# Plain Text Report
# ─────────────────────────────────────────────

def _build_text(results: list[dict]) -> str:
    lines = []
    lines.append("=" * 65)
    lines.append("  NETWORK DEVICE CONFIGURATION AUDIT REPORT")
    lines.append(f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("=" * 65)

    for r in results:
        lines.append(f"\nDevice : {r['hostname']} ({r['host']})")
        lines.append(f"Mode   : {'OFFLINE (config file)' if r.get('mode') == 'offline' else 'LIVE (SSH)'}")
        lines.append(f"Status : {r['status']}")
        lines.append(f"Time   : {r['timestamp']}")
        lines.append("-" * 65)

        if r["status"] == "UNREACHABLE":
            lines.append("  [!] Device was unreachable. No checks performed.")
            continue

        score = r.get("score", {})
        if score:
            lines.append(f"  Risk Score : {score['score']}/100 — {score['risk_level']}")
            lines.append(f"  {score['summary']}")
            lines.append("")

        findings = sorted(r["findings"], key=lambda f: SEVERITY_ORDER.get(f["severity"], 9))

        fails    = [f for f in findings if f["severity"] == "FAIL"]
        warnings = [f for f in findings if f["severity"] == "WARNING"]
        passes   = [f for f in findings if f["severity"] == "PASS"]

        lines.append(f"  Summary: {len(fails)} FAIL  {len(warnings)} WARNING  {len(passes)} PASS\n")

        for finding in findings:
            icon = SEVERITY_EMOJI.get(finding["severity"], "?")
            lines.append(f"  [{icon}] [{finding['severity']:7}] {finding['check_id']} - {finding['title']}")
            lines.append(f"         {finding['detail']}")
            if finding["remediation"]:
                lines.append(f"         → FIX: {finding['remediation']}")
            lines.append("")

    lines.append("=" * 65)
    lines.append("  END OF REPORT")
    lines.append("=" * 65)
    return "\n".join(lines)


# ─────────────────────────────────────────────
# HTML Report
# ─────────────────────────────────────────────

def _build_html(results: list[dict]) -> str:
    device_blocks = ""
    for r in results:
        if r["status"] == "UNREACHABLE":
            device_blocks += f"""
            <div class="device unreachable">
                <h2>{r['hostname']} <span class="ip">({r['host']})</span>
                    <span class="badge unreachable">UNREACHABLE</span>
                </h2>
                <p class="error-msg">Device was unreachable. No checks performed.</p>
            </div>"""
            continue

        findings = sorted(r["findings"], key=lambda f: SEVERITY_ORDER.get(f["severity"], 9))
        fails    = sum(1 for f in findings if f["severity"] == "FAIL")
        warnings = sum(1 for f in findings if f["severity"] == "WARNING")
        passes   = sum(1 for f in findings if f["severity"] == "PASS")

        rows = ""
        for f in findings:
            sev = f["severity"].lower()
            fix = f"<div class='remediation'>→ {f['remediation']}</div>" if f["remediation"] else ""
            rows += f"""
                <tr class="{sev}">
                    <td class="check-id">{f['check_id']}</td>
                    <td><span class="badge {sev}">{f['severity']}</span></td>
                    <td>{f['title']}</td>
                    <td>{f['detail']}{fix}</td>
                </tr>"""

        score = r.get("score", {})
        score_html = ""
        if score:
            from scorer import score_colour
            css = score_colour(score["risk_level"])
            score_html = f"""
            <div class="score-card">
                <div class="score-circle {css}">
                    <span class="score-num">{score['score']}</span>
                    <span class="score-denom">/100</span>
                </div>
                <div class="score-info">
                    <div class="risk-level" style="color: inherit">{score['risk_level']} RISK</div>
                    <div class="risk-summary">{score['summary']}</div>
                </div>
            </div>"""

        device_blocks += f"""
        <div class="device">
            <h2>{r['hostname']} <span class="ip">({r['host']})</span></h2>
            <p class="timestamp">Audited: {r['timestamp']} &nbsp;·&nbsp; <span class="mode-badge {'offline' if r.get('mode') == 'offline' else 'live'}">{'OFFLINE' if r.get('mode') == 'offline' else 'LIVE SSH'}</span></p>
            {score_html}
            <div class="summary-bar">
                <span class="pill fail">{fails} FAIL</span>
                <span class="pill warning">{warnings} WARNING</span>
                <span class="pill pass">{passes} PASS</span>
            </div>
            <table>
                <thead>
                    <tr>
                        <th>ID</th><th>Severity</th><th>Check</th><th>Detail</th>
                    </tr>
                </thead>
                <tbody>{rows}</tbody>
            </table>
        </div>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Network Audit Report</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: 'Segoe UI', sans-serif; background: #0f1117; color: #e2e8f0; padding: 2rem; }}
  h1 {{ font-size: 1.6rem; color: #63b3ed; margin-bottom: 0.25rem; }}
  .meta {{ color: #718096; font-size: 0.85rem; margin-bottom: 2rem; }}
  .device {{ background: #1a1d27; border: 1px solid #2d3748; border-radius: 10px; padding: 1.5rem; margin-bottom: 2rem; }}
  .device h2 {{ font-size: 1.15rem; color: #e2e8f0; margin-bottom: 0.25rem; }}
  .ip {{ color: #718096; font-weight: normal; font-size: 0.9rem; }}
  .timestamp {{ color: #718096; font-size: 0.8rem; margin-bottom: 1rem; }}
  .summary-bar {{ display: flex; gap: 0.5rem; margin-bottom: 1rem; }}
  .pill {{ padding: 0.2rem 0.75rem; border-radius: 999px; font-size: 0.78rem; font-weight: 600; }}
  .pill.fail {{ background: #742a2a; color: #fc8181; }}
  .pill.warning {{ background: #744210; color: #f6ad55; }}
  .pill.pass {{ background: #1c4532; color: #68d391; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 0.875rem; }}
  th {{ background: #2d3748; color: #a0aec0; text-align: left; padding: 0.6rem 1rem; font-weight: 600; }}
  td {{ padding: 0.65rem 1rem; border-bottom: 1px solid #2d3748; vertical-align: top; }}
  tr.fail td {{ background: #1a0a0a; }}
  tr.warning td {{ background: #1a120a; }}
  tr.pass td {{ background: #0a1a0f; }}
  .check-id {{ font-family: monospace; color: #a0aec0; white-space: nowrap; }}
  .badge {{ padding: 0.15rem 0.5rem; border-radius: 4px; font-size: 0.75rem; font-weight: 700; }}
  .badge.fail {{ background: #742a2a; color: #fc8181; }}
  .badge.warning {{ background: #744210; color: #f6ad55; }}
  .badge.pass {{ background: #1c4532; color: #68d391; }}
  .badge.unreachable {{ background: #4a1d96; color: #d6bcfa; margin-left: 0.5rem; }}
  .remediation {{ margin-top: 0.4rem; color: #63b3ed; font-size: 0.82rem; }}
  .mode-badge {{ display: inline-block; padding: 0.1rem 0.5rem; border-radius: 4px; font-size: 0.72rem; font-weight: 700; }}
  .mode-badge.offline {{ background: #2d3748; color: #a0aec0; }}
  .mode-badge.live {{ background: #1c4532; color: #68d391; }}
  .score-card {{ display: flex; align-items: center; gap: 1.5rem; background: #141720; border: 1px solid #2d3748; border-radius: 8px; padding: 1rem 1.5rem; margin-bottom: 1rem; }}
  .score-circle {{ width: 72px; height: 72px; border-radius: 50%; display: flex; flex-direction: column; align-items: center; justify-content: center; flex-shrink: 0; }}
  .score-circle .score-num {{ font-size: 1.4rem; font-weight: 700; line-height: 1; }}
  .score-circle .score-denom {{ font-size: 0.7rem; opacity: 0.8; }}
  .score-info .risk-level {{ font-size: 1rem; font-weight: 700; margin-bottom: 0.2rem; }}
  .score-info .risk-summary {{ font-size: 0.82rem; color: #718096; }}
  .score-low {{ background: #1c4532; color: #68d391; }}
  .score-guarded {{ background: #1a3a5c; color: #63b3ed; }}
  .score-elevated {{ background: #744210; color: #f6ad55; }}
  .score-high {{ background: #742a2a; color: #fc8181; }}
  .score-critical {{ background: #4a0000; color: #ff6b6b; }}
</style>
</head>
<body>
<h1>🔒 Network Configuration Audit Report</h1>
<p class="meta">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
{device_blocks}
</body>
</html>"""

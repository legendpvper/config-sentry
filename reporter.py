"""
reporter.py
------------
Generates audit reports in plain text, HTML, or PDF format.
"""

from datetime import datetime


SEVERITY_ORDER = {"FAIL": 0, "WARNING": 1, "PASS": 2}
SEVERITY_EMOJI = {"FAIL": "✗", "WARNING": "⚠", "PASS": "✓"}


def generate_report(results: list[dict], output_path: str, fmt: str = "text"):
    """Generate and save the audit report."""
    if fmt == "pdf":
        _build_pdf(results, output_path)
    elif fmt == "html":
        content = _build_html(results)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(content)
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


# ─────────────────────────────────────────────
# PDF Report
# ─────────────────────────────────────────────

def _build_pdf(results: list[dict], output_path: str):
    """Generate a professional PDF audit report using reportlab."""
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import mm
        from reportlab.lib import colors
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer, Table,
            TableStyle, HRFlowable, KeepTogether
        )
        from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
    except ImportError:
        print("[ERROR] reportlab not installed. Run: pip install reportlab")
        return

    # ── Colour palette ────────────────────────────────────────────
    C_BG        = colors.HexColor("#0f1117")
    C_SURFACE   = colors.HexColor("#1a1d27")
    C_BORDER    = colors.HexColor("#2d3748")
    C_TEXT      = colors.HexColor("#e2e8f0")
    C_MUTED     = colors.HexColor("#718096")
    C_BLUE      = colors.HexColor("#63b3ed")
    C_FAIL_BG   = colors.HexColor("#742a2a")
    C_FAIL_FG   = colors.HexColor("#fc8181")
    C_WARN_BG   = colors.HexColor("#744210")
    C_WARN_FG   = colors.HexColor("#f6ad55")
    C_PASS_BG   = colors.HexColor("#1c4532")
    C_PASS_FG   = colors.HexColor("#68d391")
    C_MONO      = colors.HexColor("#a0aec0")

    SCORE_COLOURS = {
        "LOW":      (colors.HexColor("#1c4532"), colors.HexColor("#68d391")),
        "GUARDED":  (colors.HexColor("#1a3a5c"), colors.HexColor("#63b3ed")),
        "ELEVATED": (colors.HexColor("#744210"), colors.HexColor("#f6ad55")),
        "HIGH":     (colors.HexColor("#742a2a"), colors.HexColor("#fc8181")),
        "CRITICAL": (colors.HexColor("#4a0000"), colors.HexColor("#ff6b6b")),
    }

    # ── Document ──────────────────────────────────────────────────
    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        leftMargin=20*mm, rightMargin=20*mm,
        topMargin=20*mm, bottomMargin=20*mm,
        title="Network Configuration Audit Report",
        author="ConfigSentry"
    )

    W = A4[0] - 40*mm  # usable width

    # ── Styles ────────────────────────────────────────────────────
    base = getSampleStyleSheet()

    def style(name, **kwargs):
        s = ParagraphStyle(name, **kwargs)
        return s

    S_TITLE   = style("title",   fontSize=16, textColor=C_BLUE,   fontName="Helvetica-Bold",  spaceAfter=6, leading=20)
    S_META    = style("meta",    fontSize=8,  textColor=C_MUTED,  fontName="Helvetica",        spaceAfter=14)
    S_H2      = style("h2",      fontSize=12, textColor=C_TEXT,   fontName="Helvetica-Bold",   spaceAfter=2)
    S_SMALL   = style("small",   fontSize=7,  textColor=C_MUTED,  fontName="Helvetica",        spaceAfter=6)
    S_BODY    = style("body",    fontSize=8,  textColor=C_TEXT,   fontName="Helvetica",        leading=11)
    S_REMEDY  = style("remedy",  fontSize=7,  textColor=C_BLUE,   fontName="Helvetica-Oblique", leading=10)
    S_MONO    = style("mono",    fontSize=7,  textColor=C_MONO,   fontName="Courier")
    S_SCORE_L = style("scorelv", fontSize=9,  textColor=C_TEXT,   fontName="Helvetica-Bold",   spaceAfter=1)
    S_SCORE_S = style("scores",  fontSize=7,  textColor=C_MUTED,  fontName="Helvetica")

    # ── Background canvas callback ────────────────────────────────
    def dark_bg(canvas, doc):
        canvas.saveState()
        canvas.setFillColor(C_BG)
        canvas.rect(0, 0, A4[0], A4[1], fill=1, stroke=0)
        # Top accent bar
        canvas.setFillColor(C_BLUE)
        canvas.rect(0, A4[1] - 3, A4[0], 3, fill=1, stroke=0)
        # Footer
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(C_MUTED)
        canvas.drawString(20*mm, 12*mm, "ConfigSentry — Network Configuration Audit Report")
        canvas.drawRightString(A4[0] - 20*mm, 12*mm, f"Page {doc.page}")
        canvas.restoreState()

    # ── Story ─────────────────────────────────────────────────────
    story = []

    # Header
    story.append(Paragraph("Network Configuration Audit Report", S_TITLE))
    story.append(Paragraph(
        f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  |  ConfigSentry",
        S_META
    ))
    story.append(HRFlowable(width="100%", thickness=0.5, color=C_BORDER, spaceAfter=12))

    for r in results:
        block = []

        # Device header
        mode_label = "OFFLINE" if r.get("mode") == "offline" else "LIVE SSH"
        block.append(Paragraph(f"{r['hostname']}", S_H2))
        block.append(Paragraph(
            f"{r['host']}  ·  {mode_label}  ·  {r['timestamp'][:19]}",
            S_SMALL
        ))

        if r["status"] == "UNREACHABLE":
            block.append(Paragraph("Device was unreachable. No checks performed.", S_BODY))
            story.append(KeepTogether(block))
            story.append(Spacer(1, 10))
            continue

        # Score card
        score = r.get("score", {})
        if score:
            level = score.get("risk_level", "UNKNOWN")
            sc    = score.get("score", 0)
            summ  = score.get("summary", "")
            bg, fg = SCORE_COLOURS.get(level, (C_BORDER, C_TEXT))

            score_data = [[
                Paragraph(f"<b>{sc}/100</b>", ParagraphStyle(
                    "sn", fontSize=20, textColor=fg,
                    fontName="Helvetica-Bold", alignment=TA_CENTER,
                    leading=24
                )),
                Paragraph(
                    f"<b>{level} RISK</b><br/><font size='7' color='#718096'>{summ}</font>",
                    ParagraphStyle(
                        "sl", fontSize=10, textColor=fg,
                        fontName="Helvetica-Bold", leading=14,
                        leftIndent=6
                    )
                ),
            ]]
            score_table = Table(score_data, colWidths=[32*mm, W - 32*mm])
            score_table.setStyle(TableStyle([
                ("BACKGROUND",   (0, 0), (-1, -1), bg),
                ("VALIGN",       (0, 0), (-1, -1), "MIDDLE"),
                ("LEFTPADDING",  (0, 0), (-1, -1), 10),
                ("RIGHTPADDING", (0, 0), (-1, -1), 10),
                ("TOPPADDING",   (0, 0), (-1, -1), 10),
                ("BOTTOMPADDING",(0, 0), (-1, -1), 10),
            ]))
            block.append(Spacer(1, 4))
            block.append(score_table)
            block.append(Spacer(1, 6))

        # Summary pills row
        findings = sorted(r["findings"], key=lambda f: SEVERITY_ORDER.get(f["severity"], 9))
        fails    = sum(1 for f in findings if f["severity"] == "FAIL")
        warnings = sum(1 for f in findings if f["severity"] == "WARNING")
        passes   = sum(1 for f in findings if f["severity"] == "PASS")

        pills = [[
            Paragraph(f"<b>{fails} FAIL</b>", ParagraphStyle("pf", fontSize=8, textColor=C_FAIL_FG, fontName="Helvetica-Bold", alignment=TA_CENTER)),
            Paragraph(f"<b>{warnings} WARNING</b>", ParagraphStyle("pw", fontSize=8, textColor=C_WARN_FG, fontName="Helvetica-Bold", alignment=TA_CENTER)),
            Paragraph(f"<b>{passes} PASS</b>", ParagraphStyle("pp", fontSize=8, textColor=C_PASS_FG, fontName="Helvetica-Bold", alignment=TA_CENTER)),
        ]]
        pill_table = Table(pills, colWidths=[W/3, W/3, W/3])
        pill_table.setStyle(TableStyle([
            ("BACKGROUND",   (0, 0), (0, 0), C_FAIL_BG),
            ("BACKGROUND",   (1, 0), (1, 0), C_WARN_BG),
            ("BACKGROUND",   (2, 0), (2, 0), C_PASS_BG),
            ("TOPPADDING",   (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING",(0, 0), (-1, -1), 4),
            ("ROUNDEDCORNERS", [4]),
        ]))
        block.append(pill_table)
        block.append(Spacer(1, 6))

        # Findings table
        table_data = [[
            Paragraph("<b>ID</b>",       ParagraphStyle("th", fontSize=7, textColor=C_MUTED, fontName="Helvetica-Bold")),
            Paragraph("<b>Severity</b>", ParagraphStyle("th", fontSize=7, textColor=C_MUTED, fontName="Helvetica-Bold")),
            Paragraph("<b>Check</b>",    ParagraphStyle("th", fontSize=7, textColor=C_MUTED, fontName="Helvetica-Bold")),
            Paragraph("<b>Detail</b>",   ParagraphStyle("th", fontSize=7, textColor=C_MUTED, fontName="Helvetica-Bold")),
        ]]

        row_styles = [
            ("BACKGROUND", (0, 0), (-1, 0), C_BORDER),
            ("FONTNAME",   (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE",   (0, 0), (-1, -1), 7),
            ("VALIGN",     (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING",(0, 0), (-1, -1), 6),
            ("RIGHTPADDING",(0,0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING",(0,0),(-1, -1), 5),
            ("GRID",       (0, 0), (-1, -1), 0.3, C_BORDER),
        ]

        for i, f in enumerate(findings, start=1):
            sev = f["severity"]
            if sev == "FAIL":
                row_bg, sev_bg, sev_fg = colors.HexColor("#1a0a0a"), C_FAIL_BG, C_FAIL_FG
            elif sev == "WARNING":
                row_bg, sev_bg, sev_fg = colors.HexColor("#1a120a"), C_WARN_BG, C_WARN_FG
            else:
                row_bg, sev_bg, sev_fg = colors.HexColor("#0a1a0f"), C_PASS_BG, C_PASS_FG

            detail_text = f["detail"]
            if f.get("remediation"):
                detail_text += f"<br/><font color='#63b3ed' size='6'>→ {f['remediation']}</font>"

            row = [
                Paragraph(f["check_id"], S_MONO),
                Paragraph(f"<b>{sev}</b>", ParagraphStyle(
                    f"sev{i}", fontSize=7, textColor=sev_fg,
                    fontName="Helvetica-Bold", alignment=TA_CENTER,
                    backColor=sev_bg
                )),
                Paragraph(f["title"], S_BODY),
                Paragraph(detail_text, S_BODY),
            ]
            table_data.append(row)
            row_styles.append(("BACKGROUND", (0, i), (-1, i), row_bg))

        findings_table = Table(
            table_data,
            colWidths=[18*mm, 18*mm, 45*mm, W - 81*mm]
        )
        findings_table.setStyle(TableStyle(row_styles))
        block.append(findings_table)

        story.append(KeepTogether(block[:4]))  # header + score together
        story.extend(block[4:])
        story.append(Spacer(1, 16))
        story.append(HRFlowable(width="100%", thickness=0.5, color=C_BORDER, spaceAfter=12))

    doc.build(story, onFirstPage=dark_bg, onLaterPages=dark_bg)

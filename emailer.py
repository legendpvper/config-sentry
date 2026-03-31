"""
emailer.py
-----------
Handles sending audit report emails via Gmail SMTP.
Credentials are loaded from environment variables or a .env file.

Required environment variables:
    CONFIGSENTRY_EMAIL        — sender Gmail address
    CONFIGSENTRY_APP_PASSWORD — Gmail App Password (16 chars, no spaces)

Usage:
    from emailer import send_report
    send_report(
        to="client@company.com",
        report_path="reports/audit_20260331.pdf",
        results=results   # list of audit result dicts
    )
"""

import os
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
from pathlib import Path
from datetime import datetime


# ─────────────────────────────────────────────
# Load credentials
# ─────────────────────────────────────────────

def _load_credentials() -> tuple[str, str]:
    """
    Load sender email and app password from environment or .env file.
    Returns (email, password) or raises EnvironmentError.
    """
    # Try loading .env file if python-dotenv is available
    try:
        from dotenv import load_dotenv
        load_dotenv()
    except ImportError:
        pass  # dotenv optional — env vars can be set manually

    email    = os.environ.get("CONFIGSENTRY_EMAIL")
    password = os.environ.get("CONFIGSENTRY_APP_PASSWORD")

    if not email or not password:
        raise EnvironmentError(
            "\n[ERROR] Email credentials not found.\n"
            "Create a .env file in your project root with:\n"
            "  CONFIGSENTRY_EMAIL=configsentry@gmail.com\n"
            "  CONFIGSENTRY_APP_PASSWORD=your_app_password\n"
            "Or set these as environment variables."
        )

    return email.strip(), password.strip().replace(" ", "")


# ─────────────────────────────────────────────
# Email builder
# ─────────────────────────────────────────────

def _build_email_body(results: list[dict]) -> str:
    """Build a clean HTML email body summarising the audit results."""
    device_rows = ""
    for r in results:
        if r["status"] == "UNREACHABLE":
            device_rows += f"""
            <tr>
                <td style="padding:8px 12px;border-bottom:1px solid #2d3748;color:#e2e8f0">{r['hostname']}</td>
                <td style="padding:8px 12px;border-bottom:1px solid #2d3748;color:#fc8181">UNREACHABLE</td>
                <td style="padding:8px 12px;border-bottom:1px solid #2d3748;color:#718096">—</td>
                <td style="padding:8px 12px;border-bottom:1px solid #2d3748;color:#718096">—</td>
                <td style="padding:8px 12px;border-bottom:1px solid #2d3748;color:#718096">—</td>
            </tr>"""
            continue

        score     = r.get("score", {})
        findings  = r.get("findings", [])
        fails     = sum(1 for f in findings if f["severity"] == "FAIL")
        warnings  = sum(1 for f in findings if f["severity"] == "WARNING")
        level     = score.get("risk_level", "—")
        sc        = score.get("score", "—")

        level_colours = {
            "LOW":      ("#1c4532", "#68d391"),
            "GUARDED":  ("#1a3a5c", "#63b3ed"),
            "ELEVATED": ("#744210", "#f6ad55"),
            "HIGH":     ("#742a2a", "#fc8181"),
            "CRITICAL": ("#4a0000", "#ff6b6b"),
        }
        bg, fg = level_colours.get(level, ("#2d3748", "#e2e8f0"))

        device_rows += f"""
            <tr>
                <td style="padding:8px 12px;border-bottom:1px solid #2d3748;color:#e2e8f0">{r['hostname']}</td>
                <td style="padding:8px 12px;border-bottom:1px solid #2d3748;color:#a0aec0;font-size:12px">{r['host']}</td>
                <td style="padding:8px 12px;border-bottom:1px solid #2d3748;text-align:center">
                    <span style="background:{bg};color:{fg};padding:2px 8px;border-radius:4px;font-weight:700;font-size:12px">{level}</span>
                </td>
                <td style="padding:8px 12px;border-bottom:1px solid #2d3748;color:#e2e8f0;font-weight:700;text-align:center">{sc}/100</td>
                <td style="padding:8px 12px;border-bottom:1px solid #2d3748;font-size:12px">
                    <span style="color:#fc8181">{fails} FAIL</span> &nbsp;
                    <span style="color:#f6ad55">{warnings} WARN</span>
                </td>
            </tr>"""

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    return f"""<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"></head>
<body style="margin:0;padding:0;background:#0f1117;font-family:'Segoe UI',sans-serif;color:#e2e8f0">
  <div style="max-width:640px;margin:0 auto;padding:32px 20px">

    <div style="border-top:3px solid #63b3ed;margin-bottom:24px"></div>

    <h1 style="font-size:20px;color:#63b3ed;margin:0 0 4px 0">&#x1F512; Network Configuration Audit Report</h1>
    <p style="font-size:12px;color:#718096;margin:0 0 24px 0">Generated: {timestamp} &nbsp;·&nbsp; ConfigSentry</p>

    <p style="font-size:14px;color:#a0aec0;margin:0 0 16px 0">
        Your network audit has completed. Please find the full report attached as a PDF.
        A summary of findings is below.
    </p>

    <table style="width:100%;border-collapse:collapse;background:#1a1d27;border:1px solid #2d3748;border-radius:8px;overflow:hidden;margin-bottom:24px">
      <thead>
        <tr style="background:#2d3748">
          <th style="padding:10px 12px;text-align:left;font-size:12px;color:#a0aec0;font-weight:600">Device</th>
          <th style="padding:10px 12px;text-align:left;font-size:12px;color:#a0aec0;font-weight:600">Host</th>
          <th style="padding:10px 12px;text-align:center;font-size:12px;color:#a0aec0;font-weight:600">Risk Level</th>
          <th style="padding:10px 12px;text-align:center;font-size:12px;color:#a0aec0;font-weight:600">Score</th>
          <th style="padding:10px 12px;text-align:left;font-size:12px;color:#a0aec0;font-weight:600">Issues</th>
        </tr>
      </thead>
      <tbody>{device_rows}</tbody>
    </table>

    <p style="font-size:12px;color:#718096;margin:0 0 8px 0">
        The attached PDF contains the full audit report with detailed findings and remediation steps for each check.
    </p>

    <div style="border-top:1px solid #2d3748;margin-top:24px;padding-top:16px">
        <p style="font-size:11px;color:#4a5568;margin:0">
            This report was generated automatically by
            <a href="https://github.com/legendpvper/config-sentry" style="color:#63b3ed;text-decoration:none">ConfigSentry</a>.
            Do not reply to this email.
        </p>
    </div>

  </div>
</body>
</html>"""


# ─────────────────────────────────────────────
# Main send function
# ─────────────────────────────────────────────

def send_report(
    to: str,
    report_path: str,
    results: list[dict],
    subject: str = None
) -> bool:
    """
    Send the audit report PDF to the specified email address.

    Args:
        to:          Recipient email address
        report_path: Path to the PDF report file
        results:     List of audit result dicts (for email body summary)
        subject:     Optional custom subject line

    Returns:
        True if sent successfully, False otherwise
    """
    try:
        sender, password = _load_credentials()
    except EnvironmentError as e:
        print(e)
        return False

    # Validate report file exists
    path = Path(report_path)
    if not path.exists():
        print(f"[ERROR] Report file not found: {report_path}")
        return False

    # Build subject
    if not subject:
        device_names = ", ".join(r["hostname"] for r in results[:3])
        if len(results) > 3:
            device_names += f" +{len(results) - 3} more"
        subject = f"ConfigSentry Audit Report — {device_names} — {datetime.now().strftime('%Y-%m-%d')}"

    # Build message
    msg = MIMEMultipart("alternative")
    msg["From"]    = f"ConfigSentry <{sender}>"
    msg["To"]      = to
    msg["Subject"] = subject

    # HTML body
    html_body = _build_email_body(results)
    msg.attach(MIMEText(html_body, "html"))

    # Attach PDF
    with open(path, "rb") as f:
        attachment = MIMEBase("application", "octet-stream")
        attachment.set_payload(f.read())
    encoders.encode_base64(attachment)
    attachment.add_header(
        "Content-Disposition",
        f"attachment; filename={path.name}"
    )
    msg.attach(attachment)

    # Send via Gmail SMTP
    print(f"[*] Sending report to {to} ...")
    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(sender, password)
            server.sendmail(sender, to, msg.as_string())
        print(f"[✓] Report sent successfully to {to}")
        return True

    except smtplib.SMTPAuthenticationError:
        print("[ERROR] Gmail authentication failed. Check your App Password in .env")
        return False

    except smtplib.SMTPException as e:
        print(f"[ERROR] Failed to send email: {e}")
        return False

"""
scorer.py
----------
Calculates a 0-100 risk score for each audited device based on findings.
Higher score = safer device. Lower score = more risk.

Scoring model:
- Each check has a weight reflecting its real-world security impact
- FAIL deducts the full weight
- WARNING deducts half the weight
- PASS deducts nothing
- Score starts at 100 and deductions are applied
- Final score is clamped between 0 and 100
"""

# ─────────────────────────────────────────────
# Check weights (impact of each finding)
# Higher = more critical to security
# ─────────────────────────────────────────────

CHECK_WEIGHTS = {
    # Universal checks
    "CHK-001": 15,   # Telnet enabled — critical, plaintext credentials
    "CHK-002": 10,   # SSH version — significant protocol weakness
    "CHK-003": 12,   # Default SNMP community — easily exploitable
    "CHK-004":  6,   # SNMP without ACL — moderate exposure
    "CHK-005":  5,   # NTP not configured — log integrity risk
    "CHK-006":  4,   # Login banner missing — minor, legal/policy risk
    "CHK-007":  7,   # Multiple privilege-15 users — lateral movement risk
    "CHK-008": 12,   # Console not password protected — physical access risk
    "CHK-009":  8,   # VTY without access-class — management plane exposure
    "CHK-010": 10,   # Password encryption disabled — credential exposure
    "CHK-011": 10,   # HTTP server enabled — unencrypted management

    # Cisco-specific
    "CHK-012":  5,   # CDP enabled — information disclosure
    "CHK-013":  8,   # IP source routing — routing bypass risk

    # Cisco ASA-specific
    "CHK-014": 12,   # ASDM unrestricted — firewall management exposure
    "CHK-015":  4,   # ICMP rate limit — reconnaissance risk

    # Fortinet-specific
    "CHK-016": 12,   # HTTP admin access — unencrypted firewall management
    "CHK-017":  8,   # Admin without trusted hosts — management plane exposure

    # Palo Alto-specific
    "CHK-018":  5,   # No Panorama — centralised management missing
    "CHK-019":  6,   # No syslog — logging/SIEM gap

    # Juniper-specific
    "CHK-020": 15,   # Root SSH login — critical, direct root access
    "CHK-021":  5,   # NTP not configured

    # Huawei-specific
    "CHK-022": 15,   # Telnet enabled — critical
    "CHK-023": 12,   # Default SNMP community

    # MikroTik-specific
    "CHK-024": 20,   # Default admin no password — worst possible finding
}

DEFAULT_WEIGHT = 5  # Fallback weight for any check not in the table


# ─────────────────────────────────────────────
# Risk bands
# ─────────────────────────────────────────────

RISK_BANDS = [
    (90, 100, "LOW",      "Device is well-hardened. Minor improvements possible."),
    (70,  89, "GUARDED",  "Generally secure with some areas needing attention."),
    (50,  69, "ELEVATED", "Notable security gaps present. Remediation recommended."),
    (30,  49, "HIGH",     "Significant misconfigurations found. Prompt action required."),
    (0,   29, "CRITICAL", "Severe security gaps. Immediate remediation required."),
]


def calculate_score(findings: list[dict]) -> dict:
    """
    Calculate a risk score for a device based on its audit findings.

    Args:
        findings: List of finding dicts from checks.py

    Returns:
        dict with keys:
            score       (int 0-100)
            risk_level  (str)
            summary     (str)
            deductions  (list of dicts explaining each deduction)
    """
    if not findings:
        return {
            "score": 100,
            "risk_level": "LOW",
            "summary": "No findings to score.",
            "deductions": []
        }

    total_deduction = 0
    deductions = []

    for finding in findings:
        severity = finding.get("severity")
        check_id = finding.get("check_id", "")
        weight = CHECK_WEIGHTS.get(check_id, DEFAULT_WEIGHT)

        if severity == "FAIL":
            deduction = weight
        elif severity == "WARNING":
            deduction = weight // 2
        else:
            continue  # PASS — no deduction

        total_deduction += deduction
        deductions.append({
            "check_id": check_id,
            "title": finding.get("title", ""),
            "severity": severity,
            "deduction": deduction
        })

    # Sort deductions largest first so report shows worst issues at top
    deductions.sort(key=lambda d: d["deduction"], reverse=True)

    score = max(0, min(100, 100 - total_deduction))
    risk_level, summary = _get_risk_band(score)

    return {
        "score": score,
        "risk_level": risk_level,
        "summary": summary,
        "deductions": deductions
    }


def _get_risk_band(score: int) -> tuple[str, str]:
    """Return (risk_level, summary) for a given score."""
    for low, high, level, summary in RISK_BANDS:
        if low <= score <= high:
            return level, summary
    return "CRITICAL", "Score out of expected range."


def score_colour(risk_level: str) -> str:
    """Return a CSS colour class for the given risk level (for HTML reports)."""
    return {
        "LOW":      "score-low",
        "GUARDED":  "score-guarded",
        "ELEVATED": "score-elevated",
        "HIGH":     "score-high",
        "CRITICAL": "score-critical",
    }.get(risk_level, "score-unknown")

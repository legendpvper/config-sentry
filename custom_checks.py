"""
custom_checks.py
-----------------
Loads and runs user-defined security checks from a YAML file.

Each check in the YAML uses a simple schema — no Python required.
Checks are run after the built-in checks and merged into the same
findings list, so they appear in reports, PDF exports, and the web UI.

Schema reference:
  check_id:      Unique ID string. Use a CHK-CXXX prefix to avoid
                 collisions with built-in checks.
  title:         Human-readable check name shown in the report.
  pattern:       Python regex pattern to match against the config text.
  match:         "present"  — trigger if the pattern IS found (default)
                 "absent"   — trigger if the pattern is NOT found
  severity:      "FAIL" or "WARNING" (when the check triggers)
  detail:        Message shown when the check triggers.
  detail_pass:   (optional) Message shown when the check passes.
  remediation:   Steps to resolve the issue.
  device_types:  (optional) List of device type strings to run this
                 check on. Omit to run on all devices.

Usage (CLI):
  python auditor.py --config-file mydevice.txt --device-type cisco_ios \\
                    --custom-checks my_checks.yaml

Usage (Python):
  from custom_checks import load_custom_checks, run_custom_checks
  check_defs = load_custom_checks("my_checks.yaml")
  extra_findings = run_custom_checks(config_text, device_type, check_defs)
"""

import re
import sys
from pathlib import Path


# ─────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────

REQUIRED_FIELDS  = {"check_id", "title", "pattern", "severity"}
VALID_SEVERITIES = {"FAIL", "WARNING"}
VALID_MATCH      = {"present", "absent"}


# ─────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────

def load_custom_checks(yaml_path: str) -> list[dict]:
    """
    Load and validate custom checks from a YAML file.

    Args:
        yaml_path: Path to the custom checks YAML file.

    Returns:
        List of validated check definition dicts ready to pass
        to run_custom_checks().
    """
    try:
        import yaml
    except ImportError:
        print("[ERROR] PyYAML is required for custom checks. Run: pip install pyyaml")
        sys.exit(1)

    path = Path(yaml_path)
    if not path.exists():
        print(f"[ERROR] Custom checks file not found: {yaml_path}")
        sys.exit(1)

    with open(path, "r") as f:
        data = yaml.safe_load(f)

    if not data or "checks" not in data:
        print("[ERROR] Custom checks YAML must contain a top-level 'checks:' list.")
        sys.exit(1)

    raw_checks = data["checks"]
    if not isinstance(raw_checks, list):
        print("[ERROR] 'checks' must be a YAML list of check definitions.")
        sys.exit(1)

    validated = []
    for i, check in enumerate(raw_checks):
        errors = _validate_check(check, i)
        if errors:
            for err in errors:
                print(f"[WARNING] Custom check #{i + 1} ({check.get('check_id', '?')}): {err} — skipping.")
            continue
        # Normalise casing so comparisons are consistent
        check["match"]    = check.get("match", "present").lower().strip()
        check["severity"] = check["severity"].upper().strip()
        validated.append(check)

    print(f"[+] Loaded {len(validated)} custom check(s) from {path.name}.")
    return validated


def load_custom_checks_from_string(yaml_content: str) -> list[dict]:
    """
    Load and validate custom checks from a YAML string (used by the web app).

    Args:
        yaml_content: Raw YAML text.

    Returns:
        List of validated check definition dicts, or [] on any error.
    """
    try:
        import yaml
    except ImportError:
        return []

    try:
        data = yaml.safe_load(yaml_content)
    except yaml.YAMLError as e:
        return []

    if not data or "checks" not in data:
        return []

    raw_checks = data.get("checks", [])
    if not isinstance(raw_checks, list):
        return []

    validated = []
    for i, check in enumerate(raw_checks):
        if _validate_check(check, i):
            continue  # skip invalid checks silently in web mode
        check["match"]    = check.get("match", "present").lower().strip()
        check["severity"] = check["severity"].upper().strip()
        validated.append(check)

    return validated


def run_custom_checks(config: str, device_type: str, check_defs: list[dict]) -> list[dict]:
    """
    Run a list of custom check definitions against a config string.

    Args:
        config:      Raw device configuration text.
        device_type: Netmiko device type string (e.g. "cisco_ios").
        check_defs:  List of validated check dicts from load_custom_checks().

    Returns:
        List of finding dicts in the same format as built-in checks,
        with an extra "custom": True key for UI labelling.
    """
    findings = []
    for check_def in check_defs:
        allowed_types = check_def.get("device_types")
        if allowed_types and device_type not in allowed_types:
            continue

        finding = _run_single_check(config, check_def)
        if finding:
            findings.append(finding)

    return findings


# ─────────────────────────────────────────────
# Internal helpers
# ─────────────────────────────────────────────

def _run_single_check(config: str, check_def: dict) -> dict | None:
    """Execute one custom check definition and return a finding dict."""
    check_id    = check_def["check_id"]
    title       = check_def["title"]
    pattern     = check_def["pattern"]
    match_type  = check_def.get("match", "present")
    severity    = check_def["severity"]
    remediation = check_def.get("remediation", "")

    try:
        found = bool(re.search(pattern, config, re.IGNORECASE | re.MULTILINE))
    except re.error as e:
        return {
            "check_id":    check_id,
            "title":       title,
            "severity":    "WARNING",
            "detail":      f"Custom check regex error: {e}. Fix the pattern in your YAML.",
            "remediation": "Correct the 'pattern' field in your custom checks YAML.",
            "custom":      True,
        }

    triggered = (match_type == "present" and found) or \
                (match_type == "absent"  and not found)

    if triggered:
        return {
            "check_id":    check_id,
            "title":       title,
            "severity":    severity,
            "detail":      check_def.get("detail", _default_detail(match_type, pattern)),
            "remediation": remediation,
            "custom":      True,
        }
    else:
        return {
            "check_id":    check_id,
            "title":       title,
            "severity":    "PASS",
            "detail":      check_def.get("detail_pass", _default_pass_detail(match_type)),
            "remediation": "",
            "custom":      True,
        }


def _validate_check(check: dict, index: int) -> list[str]:
    """Return a list of validation error strings for a check definition."""
    errors = []

    if not isinstance(check, dict):
        return [f"Check #{index + 1} is not a valid mapping — check your YAML indentation."]

    for field in REQUIRED_FIELDS:
        if field not in check:
            errors.append(f"Missing required field '{field}'")

    if "severity" in check and str(check["severity"]).upper() not in VALID_SEVERITIES:
        errors.append(
            f"Invalid severity '{check['severity']}'. Must be FAIL or WARNING."
        )

    if "match" in check and str(check["match"]).lower() not in VALID_MATCH:
        errors.append(
            f"Invalid match type '{check['match']}'. Must be 'present' or 'absent'."
        )

    if "pattern" in check:
        try:
            re.compile(check["pattern"])
        except re.error as e:
            errors.append(f"Invalid regex pattern: {e}")

    return errors


def _default_detail(match_type: str, pattern: str) -> str:
    if match_type == "present":
        return f"Pattern matched in configuration: {pattern}"
    return f"Expected pattern not found in configuration: {pattern}"


def _default_pass_detail(match_type: str) -> str:
    if match_type == "present":
        return "Pattern not found. Check passed."
    return "Expected configuration found. Check passed."

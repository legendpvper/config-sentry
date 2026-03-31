#!/usr/bin/env python3
"""
Network Device Configuration Auditor
-------------------------------------
Connects to network devices via SSH, pulls running configs,
and generates a security audit report flagging common issues.

Usage:
    # Live SSH mode
    python auditor.py --devices devices/inventory.yaml --output html
    python auditor.py --host 192.168.1.1 --username admin --device-type cisco_ios

    # Offline mode (no SSH needed — audit a saved config file)
    python auditor.py --config-file running-config.txt --device-type cisco_ios
    python auditor.py --config-file fortigate.conf --device-type fortinet --device-name Firewall-01
"""

import argparse
import sys
from datetime import datetime
from pathlib import Path

from connector import connect_to_device
from checks import run_all_checks
from reporter import generate_report
from scorer import calculate_score


SUPPORTED_DEVICE_TYPES = [
    "cisco_ios", "cisco_ios_xe", "cisco_xr", "cisco_nxos", "cisco_asa",
    "fortinet", "paloalto_panos",
    "juniper_junos", "arista_eos",
    "huawei", "huawei_vrp",
    "hp_comware", "hp_procurve",
    "dell_os10", "dell_powerconnect",
    "mikrotik_routeros", "ubiquiti_edge",
]


def parse_args():
    parser = argparse.ArgumentParser(
        description="Network Device Configuration Auditor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Live SSH audit (single device):
    python auditor.py --host 192.168.1.1 --username admin --device-type cisco_ios

  Live SSH audit (multiple devices from file):
    python auditor.py --devices devices/inventory.yaml --output html

  Offline audit (no SSH — just a saved config file):
    python auditor.py --config-file running-config.txt --device-type cisco_ios
    python auditor.py --config-file fg.conf --device-type fortinet --device-name MyFirewall
        """
    )

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--devices",
        help="Path to YAML inventory file (live SSH, multiple devices)"
    )
    group.add_argument(
        "--host",
        help="Single device IP or hostname (live SSH)"
    )
    group.add_argument(
        "--config-file",
        help="Path to a saved config file to audit offline (no SSH required)"
    )

    # Live SSH options
    parser.add_argument("--username", help="SSH username (live mode only)")
    parser.add_argument("--password", help="SSH password (live mode only)")

    # Shared options
    parser.add_argument(
        "--device-type",
        default="cisco_ios",
        choices=SUPPORTED_DEVICE_TYPES,
        help="Device type (required for --config-file and --host modes)"
    )
    parser.add_argument(
        "--device-name",
        default=None,
        help="Display name for the device in the report (offline mode)"
    )
    parser.add_argument(
        "--output",
        choices=["text", "html", "pdf"],
        default="text",
        help="Report format (default: text)"
    )
    parser.add_argument(
        "--email",
        default=None,
        help="Email address to send the report to after generation (PDF only)"
    )
    parser.add_argument(
        "--out-dir",
        default="reports",
        help="Directory to save reports (default: ./reports)"
    )
    return parser.parse_args()


def load_inventory(path: str) -> list[dict]:
    """Load device inventory from a YAML file."""
    try:
        import yaml
    except ImportError:
        print("[ERROR] PyYAML not installed. Run: pip install pyyaml")
        sys.exit(1)

    with open(path, "r") as f:
        data = yaml.safe_load(f)

    devices = data.get("devices", [])
    if not devices:
        print("[ERROR] No devices found in inventory file.")
        sys.exit(1)

    return devices


def audit_device_live(device: dict) -> dict:
    """Connect to a device via SSH, pull config, run checks, return results."""
    host = device.get("host")
    print(f"\n[*] Connecting to {host} ...")

    connection, raw_config = connect_to_device(device)

    if connection is None:
        return {
            "host": host,
            "hostname": device.get("name", host),
            "mode": "live",
            "status": "UNREACHABLE",
            "findings": [],
            "raw_config": "",
            "timestamp": datetime.now().isoformat()
        }

    print(f"[+] Connected. Running audit checks on {host} ...")
    findings = run_all_checks(raw_config, device.get("device_type", "cisco_ios"))
    connection.disconnect()

    passed   = sum(1 for f in findings if f["severity"] == "PASS")
    warnings = sum(1 for f in findings if f["severity"] == "WARNING")
    failures = sum(1 for f in findings if f["severity"] == "FAIL")
    print(f"    PASS: {passed}  WARNING: {warnings}  FAIL: {failures}")

    score_data = calculate_score(findings)
    print(f"    Risk Score: {score_data['score']}/100 — {score_data['risk_level']}")

    return {
        "host": host,
        "hostname": device.get("name", host),
        "mode": "live",
        "status": "OK",
        "findings": findings,
        "score": score_data,
        "raw_config": raw_config,
        "timestamp": datetime.now().isoformat()
    }


def audit_device_offline(config_path: str, device_type: str, device_name: str = None) -> dict:
    """
    Audit a saved config file without SSH.

    Args:
        config_path:  Path to the config file
        device_type:  Netmiko device type string
        device_name:  Optional display name for the report

    Returns:
        Result dict compatible with generate_report()
    """
    path = Path(config_path)

    if not path.exists():
        print(f"[ERROR] Config file not found: {config_path}")
        sys.exit(1)

    display_name = device_name or path.stem
    print(f"\n[*] Loading config file: {config_path}")

    try:
        raw_config = path.read_text(encoding="utf-8", errors="replace")
    except Exception as e:
        print(f"[ERROR] Could not read file: {e}")
        sys.exit(1)

    if not raw_config.strip():
        print("[ERROR] Config file is empty.")
        sys.exit(1)

    print(f"[+] Loaded {len(raw_config.splitlines())} lines. Running audit checks ...")
    findings = run_all_checks(raw_config, device_type)

    passed   = sum(1 for f in findings if f["severity"] == "PASS")
    warnings = sum(1 for f in findings if f["severity"] == "WARNING")
    failures = sum(1 for f in findings if f["severity"] == "FAIL")
    print(f"    PASS: {passed}  WARNING: {warnings}  FAIL: {failures}")

    score_data = calculate_score(findings)
    print(f"    Risk Score: {score_data['score']}/100 — {score_data['risk_level']}")

    return {
        "host": str(path),
        "hostname": display_name,
        "mode": "offline",
        "status": "OK",
        "findings": findings,
        "score": score_data,
        "raw_config": raw_config,
        "timestamp": datetime.now().isoformat()
    }


def main():
    args = parse_args()

    # ── Offline mode ──────────────────────────────────────────────
    if args.config_file:
        results = [audit_device_offline(
            config_path=args.config_file,
            device_type=args.device_type,
            device_name=args.device_name
        )]

    # ── Live SSH mode (inventory file) ────────────────────────────
    elif args.devices:
        devices = load_inventory(args.devices)
        results = [audit_device_live(d) for d in devices]

    # ── Live SSH mode (single host) ───────────────────────────────
    else:
        if not args.username:
            print("[ERROR] --username required in single-device mode.")
            sys.exit(1)
        import getpass
        password = args.password or getpass.getpass(f"Password for {args.host}: ")
        results = [audit_device_live({
            "host": args.host,
            "name": args.device_name or args.host,
            "username": args.username,
            "password": password,
            "device_type": args.device_type
        })]

    # ── Generate report ───────────────────────────────────────────
    out_dir = Path(args.out_dir)
    out_dir.mkdir(exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    ext = {"html": "html", "pdf": "pdf"}.get(args.output, "txt")
    out_file = out_dir / f"audit_{timestamp}.{ext}"

    generate_report(results, output_path=str(out_file), fmt=args.output)
    print(f"\n[✓] Report saved to: {out_file}")

    # Send email if requested
    if args.email:
        if args.output != "pdf":
            print("[WARNING] Email delivery works best with --output pdf. Re-run with --output pdf to attach the report.")
        else:
            from emailer import send_report
            send_report(
                to=args.email,
                report_path=str(out_file),
                results=results
            )


if __name__ == "__main__":
    main()

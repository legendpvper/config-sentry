#!/usr/bin/env python3
"""
Network Device Configuration Auditor
-------------------------------------
Connects to network devices via SSH, pulls running configs,
and generates a security audit report flagging common issues.

Usage:
    python auditor.py --devices devices/inventory.yaml
    python auditor.py --devices devices/inventory.yaml --output html
    python auditor.py --host 192.168.1.1 --username admin --device-type cisco_ios
"""

import argparse
import sys
from datetime import datetime
from pathlib import Path

from connector import connect_to_device
from checks import run_all_checks
from reporter import generate_report


def parse_args():
    parser = argparse.ArgumentParser(
        description="Network Device Configuration Auditor"
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--devices",
        help="Path to YAML inventory file (for multiple devices)"
    )
    group.add_argument(
        "--host",
        help="Single device IP or hostname"
    )
    parser.add_argument("--username", help="SSH username (single device mode)")
    parser.add_argument("--password", help="SSH password (single device mode)")
    parser.add_argument(
        "--device-type",
        default="cisco_ios",
        choices=[
            "cisco_ios", "cisco_ios_xe", "cisco_xr", "cisco_nxos", "cisco_asa",
            "fortinet", "paloalto_panos",
            "juniper_junos", "arista_eos",
            "huawei", "huawei_vrp",
            "hp_comware", "hp_procurve",
            "dell_os10", "dell_powerconnect",
            "mikrotik_routeros", "ubiquiti_edge",
        ],
        help="Device type for Netmiko (default: cisco_ios)"
    )
    parser.add_argument(
        "--output",
        choices=["text", "html"],
        default="text",
        help="Report format (default: text)"
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


def audit_device(device: dict) -> dict:
    """Connect to a device, pull config, run checks, return results."""
    host = device.get("host")
    print(f"\n[*] Connecting to {host} ...")

    connection, raw_config = connect_to_device(device)

    if connection is None:
        return {
            "host": host,
            "hostname": device.get("name", host),
            "status": "UNREACHABLE",
            "findings": [],
            "raw_config": "",
            "timestamp": datetime.now().isoformat()
        }

    print(f"[+] Connected. Running audit checks on {host} ...")
    findings = run_all_checks(raw_config, device.get("device_type", "cisco_ios"))
    connection.disconnect()

    passed = sum(1 for f in findings if f["severity"] == "PASS")
    warnings = sum(1 for f in findings if f["severity"] == "WARNING")
    failures = sum(1 for f in findings if f["severity"] == "FAIL")

    print(f"    PASS: {passed}  WARNING: {warnings}  FAIL: {failures}")

    return {
        "host": host,
        "hostname": device.get("name", host),
        "status": "OK",
        "findings": findings,
        "raw_config": raw_config,
        "timestamp": datetime.now().isoformat()
    }


def main():
    args = parse_args()

    # Build device list
    if args.devices:
        devices = load_inventory(args.devices)
    else:
        if not args.username:
            print("[ERROR] --username required in single-device mode.")
            sys.exit(1)
        import getpass
        password = args.password or getpass.getpass(f"Password for {args.host}: ")
        devices = [{
            "host": args.host,
            "name": args.host,
            "username": args.username,
            "password": password,
            "device_type": args.device_type
        }]

    # Run audits
    results = [audit_device(d) for d in devices]

    # Generate report
    out_dir = Path(args.out_dir)
    out_dir.mkdir(exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_file = out_dir / f"audit_{timestamp}.{'html' if args.output == 'html' else 'txt'}"

    generate_report(results, output_path=str(out_file), fmt=args.output)
    print(f"\n[✓] Report saved to: {out_file}")


if __name__ == "__main__":
    main()

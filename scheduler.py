"""
scheduler.py
-------------
Manages scheduled audit runs via Windows Task Scheduler.
Creates, lists, and removes scheduled tasks that run auditor.py automatically.

Usage (called internally by auditor.py):
    from scheduler import create_schedule, remove_schedule, list_schedules

Supported frequencies:
    daily   — runs every day at a specified time (default 08:00)
    weekly  — runs every Monday at a specified time (default 08:00)
    monthly — runs on the 1st of every month at a specified time
"""

import subprocess
import sys
import json
import os
from pathlib import Path
from datetime import datetime


TASK_PREFIX = "ConfigSentry_"


def create_schedule(
    devices_arg: str,
    output_fmt: str,
    email: str,
    frequency: str,
    time: str = "08:00",
    task_name: str = None
) -> bool:
    """
    Register a scheduled audit task in Windows Task Scheduler.

    Args:
        devices_arg: Path to inventory file or host string
        output_fmt:  Report format (pdf recommended)
        email:       Recipient email address
        frequency:   'daily', 'weekly', or 'monthly'
        time:        Time to run in HH:MM format (default 08:00)
        task_name:   Optional custom task name

    Returns:
        True if task created successfully, False otherwise
    """
    if sys.platform != "win32":
        print("[ERROR] Scheduled tasks via Task Scheduler are only supported on Windows.")
        print("        On Linux/Mac, use cron instead: see README for cron examples.")
        return False

    python_exe = sys.executable
    script_path = str(Path(__file__).parent / "auditor.py")

    # Build the command that Task Scheduler will run
    cmd_args = f'"{python_exe}" "{script_path}" --devices "{devices_arg}" --output {output_fmt}'
    if email:
        cmd_args += f' --email "{email}"'

    # Task name
    safe_name = (task_name or f"audit_{Path(devices_arg).stem}").replace(" ", "_")
    full_task_name = f"{TASK_PREFIX}{safe_name}"

    # Map frequency to schtasks schedule type
    schedule_map = {
        "daily":   ("DAILY",   ""),
        "weekly":  ("WEEKLY",  "/D MON"),
        "monthly": ("MONTHLY", "/D 1"),
    }
    if frequency not in schedule_map:
        print(f"[ERROR] Unknown frequency '{frequency}'. Use: daily, weekly, monthly")
        return False

    sc_type, sc_modifier = schedule_map[frequency]

    # Build schtasks command
    schtasks_cmd = [
        "schtasks", "/Create",
        "/TN", full_task_name,
        "/TR", cmd_args,
        "/SC", sc_type,
        "/ST", time,
        "/F",  # Force overwrite if exists
    ]
    if sc_modifier:
        schtasks_cmd += sc_modifier.split()

    try:
        result = subprocess.run(
            schtasks_cmd,
            capture_output=True, text=True
        )
        if result.returncode == 0:
            print(f"[✓] Scheduled task created: {full_task_name}")
            print(f"    Frequency : {frequency.upper()} at {time}")
            print(f"    Command   : {cmd_args}")
            if email:
                print(f"    Report    : {output_fmt.upper()} → {email}")
            _save_schedule_record(full_task_name, {
                "task_name":   full_task_name,
                "devices":     devices_arg,
                "output":      output_fmt,
                "email":       email,
                "frequency":   frequency,
                "time":        time,
                "created":     datetime.now().isoformat()
            })
            return True
        else:
            print(f"[ERROR] Failed to create task: {result.stderr.strip()}")
            return False
    except FileNotFoundError:
        print("[ERROR] schtasks not found. Are you running on Windows?")
        return False


def remove_schedule(task_name: str) -> bool:
    """
    Remove a scheduled audit task from Windows Task Scheduler.

    Args:
        task_name: Task name (with or without ConfigSentry_ prefix)

    Returns:
        True if removed successfully, False otherwise
    """
    if sys.platform != "win32":
        print("[ERROR] Task Scheduler only supported on Windows.")
        return False

    if not task_name.startswith(TASK_PREFIX):
        task_name = f"{TASK_PREFIX}{task_name}"

    try:
        result = subprocess.run(
            ["schtasks", "/Delete", "/TN", task_name, "/F"],
            capture_output=True, text=True
        )
        if result.returncode == 0:
            print(f"[✓] Scheduled task removed: {task_name}")
            _remove_schedule_record(task_name)
            return True
        else:
            print(f"[ERROR] Could not remove task: {result.stderr.strip()}")
            return False
    except FileNotFoundError:
        print("[ERROR] schtasks not found.")
        return False


def list_schedules() -> list[dict]:
    """
    List all ConfigSentry scheduled tasks.

    Returns:
        List of schedule record dicts
    """
    records = _load_schedule_records()
    if not records:
        print("  No scheduled audits found.")
        return []

    print(f"\n{'─' * 60}")
    print("  CONFIGSENTRY SCHEDULED AUDITS")
    print(f"{'─' * 60}")
    for name, rec in records.items():
        print(f"\n  Task     : {name}")
        print(f"  Devices  : {rec.get('devices')}")
        print(f"  Frequency: {rec.get('frequency', '').upper()} at {rec.get('time')}")
        print(f"  Output   : {rec.get('output', '').upper()}")
        print(f"  Email    : {rec.get('email') or 'Not set'}")
        print(f"  Created  : {rec.get('created', '')[:19]}")
    print(f"\n{'─' * 60}\n")
    return list(records.values())


# ─────────────────────────────────────────────
# Schedule record persistence
# Saves a local JSON file so we can list/manage schedules
# ─────────────────────────────────────────────

RECORDS_FILE = Path(__file__).parent / ".schedules.json"


def _load_schedule_records() -> dict:
    if RECORDS_FILE.exists():
        try:
            return json.loads(RECORDS_FILE.read_text())
        except Exception:
            return {}
    return {}


def _save_schedule_record(name: str, record: dict):
    records = _load_schedule_records()
    records[name] = record
    RECORDS_FILE.write_text(json.dumps(records, indent=2))


def _remove_schedule_record(name: str):
    records = _load_schedule_records()
    records.pop(name, None)
    RECORDS_FILE.write_text(json.dumps(records, indent=2))

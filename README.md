# Network Device Configuration Auditor

A Python CLI tool that SSHs into network devices, pulls their running configuration, and generates a security audit report flagging common misconfigurations.

## Supported Devices
- Cisco IOS / IOS-XE
- Fortinet FortiGate
- Palo Alto PAN-OS

## Checks Performed

| ID | Check | Severity |
|---|---|---|
| CHK-001 | Telnet enabled on VTY lines | FAIL |
| CHK-002 | SSH version not set to v2 | FAIL / WARNING |
| CHK-003 | Default SNMP community strings | FAIL |
| CHK-004 | SNMP community without ACL | WARNING |
| CHK-005 | NTP not configured | WARNING |
| CHK-006 | Login banner missing | WARNING |
| CHK-007 | Multiple privilege-15 users | WARNING |
| CHK-008 | Console line not password protected | FAIL |
| CHK-009 | VTY lines without access-class | WARNING |
| CHK-010 | Password encryption disabled | FAIL |
| CHK-011 | HTTP server enabled | FAIL |

## Installation

```bash
git clone https://github.com/yourusername/net-auditor.git
cd net-auditor
pip install -r requirements.txt
```

## Usage

**Single device:**
```bash
python auditor.py --host 192.168.1.1 --username admin --device-type cisco_ios
```

**Multiple devices from inventory file:**
```bash
python auditor.py --devices devices/inventory.yaml
```

**HTML report output:**
```bash
python auditor.py --devices devices/inventory.yaml --output html
```

Reports are saved to the `reports/` directory.

## Quick Start with Cisco DevNet Sandbox

No physical hardware needed. Use Cisco's free always-on sandbox:

1. Go to https://devnetsandbox.cisco.com
2. Use the always-on IOS-XE sandbox (no reservation needed)
3. Update `devices/inventory.yaml` with the sandbox credentials
4. Run: `python auditor.py --devices devices/inventory.yaml --output html`

## Project Structure

```
net-auditor/
├── auditor.py          # Main CLI entry point
├── connector.py        # SSH connection handler (Netmiko)
├── checks.py           # All audit check logic
├── reporter.py         # Text and HTML report generation
├── requirements.txt
├── devices/
│   └── inventory.yaml  # Device list
└── reports/            # Generated reports saved here
```

## Adding New Checks

Open `checks.py` and add a new function following this pattern:

```python
def check_your_new_check(config: str, device_type: str) -> dict:
    if re.search(r"your-pattern", config, re.IGNORECASE):
        return {
            "check_id": "CHK-012",
            "title": "Your Check Title",
            "severity": "FAIL",  # or "WARNING"
            "detail": "What was found.",
            "remediation": "How to fix it."
        }
    return {
        "check_id": "CHK-012",
        "title": "Your Check Title",
        "severity": "PASS",
        "detail": "All good.",
        "remediation": ""
    }
```

Then register it in `run_all_checks()`.

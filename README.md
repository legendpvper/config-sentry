# ConfigSentry

A network device configuration auditor with two ways to use it — a web dashboard for non-technical users and a Python CLI for engineers and automation workflows.

**🌐 Web Dashboard:** [config-sentry.onrender.com](https://config-sentry.onrender.com)
**💻 CLI:** Full-featured command line tool with SSH, offline, PDF, email and scheduled audit support.

---

## Two Ways to Use ConfigSentry

### 1. Web Dashboard (no setup needed)
Upload a saved config file at [config-sentry.onrender.com](https://config-sentry.onrender.com) and get a security report instantly in your browser. No Python. No terminal. No installation.

### 2. Python CLI
For engineers who want live SSH audits, automated scheduling, email delivery, and full control over the audit pipeline.

---

## Supported Devices

| Device Type | Vendor | Common Use Case |
|---|---|---|
| `cisco_ios` | Cisco | ISR routers, Catalyst switches |
| `cisco_ios_xe` | Cisco | Cat8k, CSR1000v |
| `cisco_xr` | Cisco | ASR, NCS service provider routers |
| `cisco_nxos` | Cisco | Nexus data centre switches |
| `cisco_asa` | Cisco | ASA firewalls |
| `fortinet` | Fortinet | FortiGate firewalls |
| `paloalto_panos` | Palo Alto | Next-gen firewalls |
| `juniper_junos` | Juniper | Enterprise/SP routers and switches |
| `arista_eos` | Arista | Data centre switches |
| `huawei` / `huawei_vrp` | Huawei | Enterprise routers and switches |
| `hp_comware` | HP/HPE | Comware-based switches |
| `hp_procurve` | HP/HPE | ProCurve switches |
| `dell_os10` | Dell | PowerSwitch series |
| `dell_powerconnect` | Dell | PowerConnect switches |
| `mikrotik_routeros` | MikroTik | SMB routers |
| `ubiquiti_edge` | Ubiquiti | EdgeRouter series |

---

## Checks Performed

### Universal (all devices)
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

### Cisco-Specific
| ID | Check | Severity |
|---|---|---|
| CHK-012 | CDP enabled globally | WARNING |
| CHK-013 | IP source routing enabled | FAIL |

### Cisco ASA-Specific
| ID | Check | Severity |
|---|---|---|
| CHK-014 | ASDM access not restricted | FAIL |
| CHK-015 | ICMP unreachable rate limit missing | WARNING |

### Fortinet-Specific
| ID | Check | Severity |
|---|---|---|
| CHK-016 | HTTP admin access enabled | FAIL |
| CHK-017 | Admin without trusted hosts | WARNING |

### Palo Alto-Specific
| ID | Check | Severity |
|---|---|---|
| CHK-018 | Panorama not configured | WARNING |
| CHK-019 | Syslog not configured | WARNING |

### Juniper-Specific
| ID | Check | Severity |
|---|---|---|
| CHK-020 | Root SSH login allowed | FAIL |
| CHK-021 | NTP not configured | WARNING |

### Huawei-Specific
| ID | Check | Severity |
|---|---|---|
| CHK-022 | Telnet server enabled | FAIL |
| CHK-023 | Default SNMP community | FAIL |

### MikroTik-Specific
| ID | Check | Severity |
|---|---|---|
| CHK-024 | Default admin with no password | FAIL |

---

## Risk Scoring

Every audited device receives a **0-100 risk score** based on weighted findings:

| Score | Risk Level | Meaning |
|---|---|---|
| 90-100 | LOW | Well-hardened, minor improvements possible |
| 70-89 | GUARDED | Generally secure, some areas need attention |
| 50-69 | ELEVATED | Notable gaps present, remediation recommended |
| 30-49 | HIGH | Significant misconfigurations, prompt action required |
| 0-29 | CRITICAL | Severe gaps, immediate remediation required |

Each check carries a weight reflecting its real-world impact. FAIL deducts full weight, WARNING deducts half.

---

## CLI Installation

```bash
git clone https://github.com/legendpvper/config-sentry.git
cd config-sentry
pip install -r requirements.txt
```

## CLI Usage

**Single device (live SSH):**
```bash
python auditor.py --host 192.168.1.1 --username admin --device-type cisco_ios
```

**Multiple devices from inventory file:**
```bash
python auditor.py --devices devices/inventory.yaml --output pdf
```

**Offline mode - audit a saved config file (no SSH needed):**
```bash
python auditor.py --config-file running-config.txt --device-type cisco_ios
python auditor.py --config-file fortigate.conf --device-type fortinet --device-name Firewall-01 --output pdf
```

**With remediation script:**
```bash
python auditor.py --devices devices/inventory.yaml --output pdf --remediation
```

Reports are saved to the `reports/` directory.

---

## Remediation Scripts

Add `--remediation` to any audit command to generate a ready-to-paste CLI fix script for every FAIL and WARNING finding:

```bash
python auditor.py --config-file running-config.txt --device-type cisco_ios --output pdf --remediation
```

Output in `reports/`:
```
reports/
├── audit_20260331_120000.pdf
└── remediation_Core-Router-01_20260331_120000.txt
```

Each finding includes exact vendor-specific commands with placeholders in `<ANGLE-BRACKETS>`. Critical fixes are listed first.

---

## Email Delivery

**Setup - create a `.env` file in the project root:**
```
CONFIGSENTRY_EMAIL=configsentry@gmail.com
CONFIGSENTRY_APP_PASSWORD=your_16_char_app_password
```

Generate a Gmail App Password at [myaccount.google.com/apppasswords](https://myaccount.google.com/apppasswords).

**Usage:**
```bash
python auditor.py --devices devices/inventory.yaml --output pdf --email client@company.com
```

The recipient receives a formatted HTML email with a summary table and the full PDF attached.

> The `.env` file is gitignored and never committed.

---

## Scheduled Runs (Windows Task Scheduler)

```bash
# Schedule a weekly audit
python auditor.py --devices devices/inventory.yaml --output pdf --email client@company.com --schedule weekly

# Schedule a daily audit at a specific time
python auditor.py --devices devices/inventory.yaml --output pdf --email client@company.com --schedule daily --schedule-time 09:00

# List all active schedules
python auditor.py --list-schedules

# Remove a scheduled task
python auditor.py --unschedule audit_inventory
```

> Manual runs still work exactly as before - `--schedule` is purely optional.

**Linux/Mac cron equivalent:**
```bash
0 8 * * 1 /usr/bin/python3 /path/to/auditor.py --devices /path/to/inventory.yaml --output pdf --email client@company.com
```

---

## Quick Start with Cisco DevNet Sandbox

No physical hardware needed:

1. Go to [devnetsandbox.cisco.com](https://devnetsandbox.cisco.com)
2. Launch the **IOS XR Always-On** sandbox and get credentials from the I/O tab
3. Update `devices/inventory.yaml` with the credentials
4. Run: `python auditor.py --devices devices/inventory.yaml --output html`

---

## Project Structure

```
config-sentry/
├── auditor.py          # Main CLI entry point
├── connector.py        # SSH connection handler (Netmiko)
├── checks.py           # All audit check logic (24 checks)
├── scorer.py           # Risk scoring engine
├── reporter.py         # Text, HTML and PDF report generation
├── remediator.py       # CLI remediation script generator
├── emailer.py          # Email delivery via Gmail SMTP
├── scheduler.py        # Windows Task Scheduler integration
├── requirements.txt
├── devices/
│   └── inventory.example.yaml
├── reports/            # Generated reports saved here
└── web/                # Web dashboard (FastAPI)
    ├── app.py
    ├── requirements.txt
    ├── Procfile
    └── templates/
        ├── index.html
        └── results.html
```

---

## Adding New Checks

Open `checks.py` and add a new function following this pattern:

```python
def check_your_new_check(config: str, device_type: str) -> dict:
    if re.search(r"your-pattern", config, re.IGNORECASE):
        return {
            "check_id": "CHK-025",
            "title": "Your Check Title",
            "severity": "FAIL",  # or "WARNING"
            "detail": "What was found.",
            "remediation": "How to fix it."
        }
    return {
        "check_id": "CHK-025",
        "title": "Your Check Title",
        "severity": "PASS",
        "detail": "All good.",
        "remediation": ""
    }
```

Then register it in `run_all_checks()`.

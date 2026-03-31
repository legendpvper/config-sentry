# Network Device Configuration Auditor

A Python CLI tool that SSHs into network devices, pulls their running configuration, and generates a security audit report flagging common misconfigurations.

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

## Installation

```bash
git clone https://github.com/yourusername/net-auditor.git
cd net-auditor
pip install -r requirements.txt
```

## Usage

**Single device (live SSH):**
```bash
python auditor.py --host 192.168.1.1 --username admin --device-type cisco_ios
```

**Multiple devices from inventory file (live SSH):**
```bash
python auditor.py --devices devices/inventory.yaml --output html
```

**Offline mode — audit a saved config file (no SSH needed):**
```bash
python auditor.py --config-file running-config.txt --device-type cisco_ios
python auditor.py --config-file fortigate.conf --device-type fortinet --device-name Firewall-01 --output html
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

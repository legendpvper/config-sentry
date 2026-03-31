"""
checks.py
----------
Contains all security audit checks run against a device's running config.
Each check returns a finding dict with keys:
    - check_id:    Short identifier e.g. "CHK-001"
    - title:       Human-readable check name
    - severity:    "PASS" | "WARNING" | "FAIL"
    - detail:      Explanation of what was found
    - remediation: What to do if it fails
"""

import re


# ─────────────────────────────────────────────
# Check registry — add new checks here
# ─────────────────────────────────────────────

def run_all_checks(config: str, device_type: str) -> list[dict]:
    """Run all applicable checks for the given device type."""
    from connector import VENDOR_FAMILY
    family = VENDOR_FAMILY.get(device_type, "cisco")

    # Universal checks that apply to all vendors
    universal_checks = [
        check_telnet_enabled,
        check_ssh_version,
        check_default_snmp_community,
        check_snmp_enabled_no_acl,
        check_ntp_configured,
        check_login_banner,
        check_privilege_15_users,
        check_console_password,
        check_vty_access_class,
        check_service_password_encryption,
        check_http_server_enabled,
    ]

    # Vendor-specific additional checks
    vendor_checks = {
        "cisco":      [check_cdp_enabled, check_ip_source_route],
        "cisco_xr":   [check_ip_source_route],
        "cisco_nxos": [check_cdp_enabled],
        "cisco_asa":  [check_asa_asdm_enabled, check_asa_icmp_unreachable],
        "fortinet":   [check_fortinet_admin_https, check_fortinet_trusted_hosts],
        "paloalto":   [check_paloalto_panorama, check_paloalto_syslog],
        "juniper":    [check_juniper_root_login, check_juniper_ntp],
        "arista":     [check_cdp_enabled],
        "huawei":     [check_huawei_telnet, check_huawei_snmp],
        "hp_comware": [],
        "mikrotik":   [check_mikrotik_default_admin],
    }

    checks = universal_checks + vendor_checks.get(family, [])
    findings = []
    for check_fn in checks:
        try:
            finding = check_fn(config, device_type)
            if finding:
                findings.append(finding)
        except Exception as e:
            findings.append({
                "check_id": "ERR",
                "title": check_fn.__name__,
                "severity": "WARNING",
                "detail": f"Check failed to run: {e}",
                "remediation": "Review check logic."
            })

    return findings


# ─────────────────────────────────────────────
# Individual Checks
# ─────────────────────────────────────────────

def check_telnet_enabled(config: str, device_type: str) -> dict:
    """Fail if any VTY line allows Telnet (transport input telnet)."""
    if re.search(r"transport input (telnet|all)", config, re.IGNORECASE):
        return {
            "check_id": "CHK-001",
            "title": "Telnet Enabled on VTY Lines",
            "severity": "FAIL",
            "detail": "One or more VTY lines permit Telnet, which transmits credentials in plaintext.",
            "remediation": "Replace with: transport input ssh"
        }
    return {
        "check_id": "CHK-001",
        "title": "Telnet Enabled on VTY Lines",
        "severity": "PASS",
        "detail": "No Telnet transport found on VTY lines.",
        "remediation": ""
    }


def check_ssh_version(config: str, device_type: str) -> dict:
    """Warn if SSH version 1 is configured or SSH v2 is not explicitly set."""
    if re.search(r"ip ssh version 1", config, re.IGNORECASE):
        return {
            "check_id": "CHK-002",
            "title": "SSH Version 1 in Use",
            "severity": "FAIL",
            "detail": "SSH version 1 has known vulnerabilities and should not be used.",
            "remediation": "Run: ip ssh version 2"
        }
    if not re.search(r"ip ssh version 2", config, re.IGNORECASE):
        return {
            "check_id": "CHK-002",
            "title": "SSH Version Not Explicitly Set",
            "severity": "WARNING",
            "detail": "SSH version 2 is not explicitly configured. Device may fall back to SSHv1.",
            "remediation": "Run: ip ssh version 2"
        }
    return {
        "check_id": "CHK-002",
        "title": "SSH Version",
        "severity": "PASS",
        "detail": "SSH version 2 is explicitly configured.",
        "remediation": ""
    }


def check_default_snmp_community(config: str, device_type: str) -> dict:
    """Fail if default community strings 'public' or 'private' are present."""
    if re.search(r"snmp-server community (public|private)\b", config, re.IGNORECASE):
        return {
            "check_id": "CHK-003",
            "title": "Default SNMP Community String",
            "severity": "FAIL",
            "detail": "Default SNMP community string 'public' or 'private' detected. Easily guessable.",
            "remediation": "Change to a strong, unique community string or disable SNMP if unused."
        }
    return {
        "check_id": "CHK-003",
        "title": "Default SNMP Community String",
        "severity": "PASS",
        "detail": "No default SNMP community strings found.",
        "remediation": ""
    }


def check_snmp_enabled_no_acl(config: str, device_type: str) -> dict:
    """Warn if SNMP is enabled without an ACL restricting access."""
    snmp_lines = re.findall(r"snmp-server community \S+.*", config, re.IGNORECASE)
    if not snmp_lines:
        return {
            "check_id": "CHK-004",
            "title": "SNMP ACL Restriction",
            "severity": "PASS",
            "detail": "SNMP does not appear to be configured.",
            "remediation": ""
        }
    # Check if any community line lacks an ACL reference
    unprotected = [l for l in snmp_lines if not re.search(r"\d+$|\S+-acl$", l.strip())]
    if unprotected:
        return {
            "check_id": "CHK-004",
            "title": "SNMP Community Without ACL",
            "severity": "WARNING",
            "detail": f"SNMP community string(s) found without an access-list restriction.",
            "remediation": "Attach an ACL to restrict SNMP access to authorised management hosts only."
        }
    return {
        "check_id": "CHK-004",
        "title": "SNMP ACL Restriction",
        "severity": "PASS",
        "detail": "SNMP community strings are protected by ACLs.",
        "remediation": ""
    }


def check_ntp_configured(config: str, device_type: str) -> dict:
    """Warn if no NTP server is configured."""
    if not re.search(r"ntp server", config, re.IGNORECASE):
        return {
            "check_id": "CHK-005",
            "title": "NTP Not Configured",
            "severity": "WARNING",
            "detail": "No NTP server configured. Accurate timestamps are critical for log correlation and incident response.",
            "remediation": "Configure at least one NTP server: ntp server <ip>"
        }
    return {
        "check_id": "CHK-005",
        "title": "NTP Configured",
        "severity": "PASS",
        "detail": "NTP server is configured.",
        "remediation": ""
    }


def check_login_banner(config: str, device_type: str) -> dict:
    """Warn if no login or MOTD banner is set."""
    if not re.search(r"banner (motd|login|exec)", config, re.IGNORECASE):
        return {
            "check_id": "CHK-006",
            "title": "Login Banner Missing",
            "severity": "WARNING",
            "detail": "No login or MOTD banner configured. Banners serve as legal notice for unauthorised access.",
            "remediation": "Configure a banner: banner motd # Authorised access only. #"
        }
    return {
        "check_id": "CHK-006",
        "title": "Login Banner",
        "severity": "PASS",
        "detail": "Login or MOTD banner is configured.",
        "remediation": ""
    }


def check_privilege_15_users(config: str, device_type: str) -> dict:
    """Warn if multiple local users have privilege 15."""
    priv15_users = re.findall(r"username (\S+) .*privilege 15", config, re.IGNORECASE)
    if len(priv15_users) > 1:
        return {
            "check_id": "CHK-007",
            "title": "Multiple Privilege 15 Users",
            "severity": "WARNING",
            "detail": f"Multiple users with full privilege (15) found: {', '.join(priv15_users)}. Increases attack surface.",
            "remediation": "Limit privilege 15 to one break-glass account. Use role-based access for others."
        }
    return {
        "check_id": "CHK-007",
        "title": "Privilege 15 Users",
        "severity": "PASS",
        "detail": f"Privilege 15 user count is acceptable: {priv15_users or 'none found'}.",
        "remediation": ""
    }


def check_console_password(config: str, device_type: str) -> dict:
    """Fail if console line has no password or login configured."""
    console_block = re.search(r"line con 0(.*?)(?=line |$)", config, re.DOTALL | re.IGNORECASE)
    if console_block:
        block = console_block.group(1)
        if not re.search(r"(password|login local)", block, re.IGNORECASE):
            return {
                "check_id": "CHK-008",
                "title": "Console Line Not Password Protected",
                "severity": "FAIL",
                "detail": "Console line (line con 0) has no password or login configured.",
                "remediation": "Add: login local (and ensure a local user exists) under line con 0."
            }
    return {
        "check_id": "CHK-008",
        "title": "Console Line Password",
        "severity": "PASS",
        "detail": "Console line appears to require authentication.",
        "remediation": ""
    }


def check_vty_access_class(config: str, device_type: str) -> dict:
    """Warn if VTY lines have no access-class (ACL) restricting SSH access."""
    vty_blocks = re.findall(r"line vty.*?(?=line |$)", config, re.DOTALL | re.IGNORECASE)
    if vty_blocks:
        unprotected = [b for b in vty_blocks if "access-class" not in b.lower()]
        if unprotected:
            return {
                "check_id": "CHK-009",
                "title": "VTY Lines Without Access-Class",
                "severity": "WARNING",
                "detail": "One or more VTY lines have no access-class ACL. SSH is accessible from any source IP.",
                "remediation": "Apply an access-class to restrict management access to trusted hosts only."
            }
    return {
        "check_id": "CHK-009",
        "title": "VTY Access-Class",
        "severity": "PASS",
        "detail": "VTY lines are protected by access-class ACLs.",
        "remediation": ""
    }


def check_service_password_encryption(config: str, device_type: str) -> dict:
    """Fail if service password-encryption is not enabled."""
    if not re.search(r"service password-encryption", config, re.IGNORECASE):
        return {
            "check_id": "CHK-010",
            "title": "Password Encryption Disabled",
            "severity": "FAIL",
            "detail": "service password-encryption is not enabled. Passwords in config may be stored in plaintext.",
            "remediation": "Run: service password-encryption"
        }
    return {
        "check_id": "CHK-010",
        "title": "Password Encryption",
        "severity": "PASS",
        "detail": "service password-encryption is enabled.",
        "remediation": ""
    }


def check_http_server_enabled(config: str, device_type: str) -> dict:
    """Fail if the HTTP (non-HTTPS) server is enabled."""
    if re.search(r"ip http server(?! secure)", config, re.IGNORECASE):
        return {
            "check_id": "CHK-011",
            "title": "HTTP Server Enabled",
            "severity": "FAIL",
            "detail": "The unencrypted HTTP server is enabled. Web-based management traffic is exposed.",
            "remediation": "Disable with: no ip http server. Use ip http secure-server if web access is needed."
        }
    return {
        "check_id": "CHK-011",
        "title": "HTTP Server",
        "severity": "PASS",
        "detail": "Unencrypted HTTP server is not enabled.",
        "remediation": ""
    }


# ─────────────────────────────────────────────
# Cisco-Specific Checks
# ─────────────────────────────────────────────

def check_cdp_enabled(config: str, device_type: str) -> dict:
    """Warn if CDP is enabled globally — leaks device info to neighbours."""
    if re.search(r"^cdp run", config, re.IGNORECASE | re.MULTILINE):
        return {
            "check_id": "CHK-012",
            "title": "CDP Enabled Globally",
            "severity": "WARNING",
            "detail": "Cisco Discovery Protocol (CDP) is enabled and broadcasts device model, IOS version, and IP addresses to neighbours.",
            "remediation": "Disable globally with: no cdp run. Re-enable per interface only where needed."
        }
    return {
        "check_id": "CHK-012",
        "title": "CDP Global Status",
        "severity": "PASS",
        "detail": "CDP is not enabled globally.",
        "remediation": ""
    }


def check_ip_source_route(config: str, device_type: str) -> dict:
    """Fail if IP source routing is enabled."""
    if re.search(r"ip source-route", config, re.IGNORECASE):
        return {
            "check_id": "CHK-013",
            "title": "IP Source Routing Enabled",
            "severity": "FAIL",
            "detail": "IP source routing allows packets to specify their own route, which can be exploited to bypass access controls.",
            "remediation": "Disable with: no ip source-route"
        }
    return {
        "check_id": "CHK-013",
        "title": "IP Source Routing",
        "severity": "PASS",
        "detail": "IP source routing is disabled.",
        "remediation": ""
    }


# ─────────────────────────────────────────────
# Cisco ASA-Specific Checks
# ─────────────────────────────────────────────

def check_asa_asdm_enabled(config: str, device_type: str) -> dict:
    """Warn if ASDM (web GUI) is accessible from any host."""
    if re.search(r"http 0\.0\.0\.0 0\.0\.0\.0", config, re.IGNORECASE):
        return {
            "check_id": "CHK-014",
            "title": "ASDM Access Not Restricted",
            "severity": "FAIL",
            "detail": "ASDM (web management) is accessible from any IP address.",
            "remediation": "Restrict ASDM access to specific management hosts: http <ip> <mask> <interface>"
        }
    return {
        "check_id": "CHK-014",
        "title": "ASDM Access Restriction",
        "severity": "PASS",
        "detail": "ASDM access appears to be restricted.",
        "remediation": ""
    }


def check_asa_icmp_unreachable(config: str, device_type: str) -> dict:
    """Warn if ICMP unreachable messages are enabled on outside interface."""
    if re.search(r"icmp unreachable rate-limit", config, re.IGNORECASE):
        return {
            "check_id": "CHK-015",
            "title": "ICMP Unreachable Rate Limit",
            "severity": "PASS",
            "detail": "ICMP unreachable rate limiting is configured.",
            "remediation": ""
        }
    return {
        "check_id": "CHK-015",
        "title": "ICMP Unreachable Rate Limit Missing",
        "severity": "WARNING",
        "detail": "No ICMP unreachable rate limit configured. Can be used for network reconnaissance.",
        "remediation": "Add: icmp unreachable rate-limit 1 burst-size 1"
    }


# ─────────────────────────────────────────────
# Fortinet-Specific Checks
# ─────────────────────────────────────────────

def check_fortinet_admin_https(config: str, device_type: str) -> dict:
    """Fail if HTTP (not HTTPS) admin access is enabled on FortiGate."""
    if re.search(r"set admintimeout", config, re.IGNORECASE):
        if re.search(r"set admin-sport 443", config, re.IGNORECASE) or \
           re.search(r"set admin-https enable", config, re.IGNORECASE):
            return {
                "check_id": "CHK-016",
                "title": "FortiGate HTTPS Admin Access",
                "severity": "PASS",
                "detail": "HTTPS admin access is enabled.",
                "remediation": ""
            }
    if re.search(r"set admin-http enable", config, re.IGNORECASE):
        return {
            "check_id": "CHK-016",
            "title": "FortiGate HTTP Admin Access Enabled",
            "severity": "FAIL",
            "detail": "Unencrypted HTTP admin access is enabled on FortiGate.",
            "remediation": "Disable with: set admin-http disable under config system global"
        }
    return {
        "check_id": "CHK-016",
        "title": "FortiGate Admin Access",
        "severity": "PASS",
        "detail": "HTTP admin access does not appear to be enabled.",
        "remediation": ""
    }


def check_fortinet_trusted_hosts(config: str, device_type: str) -> dict:
    """Warn if admin accounts have no trusted host restriction."""
    admin_blocks = re.findall(r"edit \S+.*?next", config, re.DOTALL)
    untrusted = [b for b in admin_blocks if "trusthost" not in b.lower() and "set name" in b.lower()]
    if untrusted:
        return {
            "check_id": "CHK-017",
            "title": "FortiGate Admin Without Trusted Hosts",
            "severity": "WARNING",
            "detail": "One or more admin accounts have no trusted host restriction. Admin GUI accessible from any IP.",
            "remediation": "Set trusted hosts per admin: set trusthost1 <ip/mask> under config system admin"
        }
    return {
        "check_id": "CHK-017",
        "title": "FortiGate Admin Trusted Hosts",
        "severity": "PASS",
        "detail": "Admin accounts appear to have trusted host restrictions.",
        "remediation": ""
    }


# ─────────────────────────────────────────────
# Palo Alto-Specific Checks
# ─────────────────────────────────────────────

def check_paloalto_panorama(config: str, device_type: str) -> dict:
    """Warn if device is not managed by Panorama."""
    if not re.search(r"panorama-server", config, re.IGNORECASE):
        return {
            "check_id": "CHK-018",
            "title": "Panorama Not Configured",
            "severity": "WARNING",
            "detail": "Device does not appear to be connected to Panorama centralised management.",
            "remediation": "Configure Panorama for centralised policy and log management."
        }
    return {
        "check_id": "CHK-018",
        "title": "Panorama Management",
        "severity": "PASS",
        "detail": "Panorama server is configured.",
        "remediation": ""
    }


def check_paloalto_syslog(config: str, device_type: str) -> dict:
    """Warn if no syslog server is configured."""
    if not re.search(r"syslog", config, re.IGNORECASE):
        return {
            "check_id": "CHK-019",
            "title": "Syslog Not Configured",
            "severity": "WARNING",
            "detail": "No syslog server configured. Logs may not be forwarded to a central SIEM.",
            "remediation": "Configure a syslog profile under Device > Server Profiles > Syslog"
        }
    return {
        "check_id": "CHK-019",
        "title": "Syslog Configuration",
        "severity": "PASS",
        "detail": "Syslog server is configured.",
        "remediation": ""
    }


# ─────────────────────────────────────────────
# Juniper-Specific Checks
# ─────────────────────────────────────────────

def check_juniper_root_login(config: str, device_type: str) -> dict:
    """Fail if root login is permitted via SSH on Juniper."""
    if re.search(r"root-login allow", config, re.IGNORECASE):
        return {
            "check_id": "CHK-020",
            "title": "Juniper Root SSH Login Allowed",
            "severity": "FAIL",
            "detail": "Direct root login via SSH is permitted. Root account is a high-value target.",
            "remediation": "Set: set system services ssh root-login deny"
        }
    return {
        "check_id": "CHK-020",
        "title": "Juniper Root SSH Login",
        "severity": "PASS",
        "detail": "Root SSH login does not appear to be explicitly allowed.",
        "remediation": ""
    }


def check_juniper_ntp(config: str, device_type: str) -> dict:
    """Warn if NTP is not configured on Juniper device."""
    if not re.search(r"ntp {", config, re.IGNORECASE):
        return {
            "check_id": "CHK-021",
            "title": "Juniper NTP Not Configured",
            "severity": "WARNING",
            "detail": "No NTP configuration found. Accurate time is critical for log correlation.",
            "remediation": "Configure NTP: set system ntp server <ip>"
        }
    return {
        "check_id": "CHK-021",
        "title": "Juniper NTP",
        "severity": "PASS",
        "detail": "NTP appears to be configured.",
        "remediation": ""
    }


# ─────────────────────────────────────────────
# Huawei-Specific Checks
# ─────────────────────────────────────────────

def check_huawei_telnet(config: str, device_type: str) -> dict:
    """Fail if Telnet service is enabled on Huawei device."""
    if re.search(r"telnet server enable", config, re.IGNORECASE):
        return {
            "check_id": "CHK-022",
            "title": "Huawei Telnet Server Enabled",
            "severity": "FAIL",
            "detail": "Telnet server is enabled. Credentials transmitted in plaintext.",
            "remediation": "Disable with: undo telnet server enable. Use STelnet (SSH) instead."
        }
    return {
        "check_id": "CHK-022",
        "title": "Huawei Telnet Server",
        "severity": "PASS",
        "detail": "Telnet server does not appear to be enabled.",
        "remediation": ""
    }


def check_huawei_snmp(config: str, device_type: str) -> dict:
    """Fail if Huawei device uses SNMPv1 or v2c with default community."""
    if re.search(r"snmp-agent community (read|write) (public|private)", config, re.IGNORECASE):
        return {
            "check_id": "CHK-023",
            "title": "Huawei Default SNMP Community",
            "severity": "FAIL",
            "detail": "Default SNMP community string detected on Huawei device.",
            "remediation": "Change community strings and consider upgrading to SNMPv3."
        }
    return {
        "check_id": "CHK-023",
        "title": "Huawei SNMP Community",
        "severity": "PASS",
        "detail": "No default SNMP community strings found.",
        "remediation": ""
    }


# ─────────────────────────────────────────────
# MikroTik-Specific Checks
# ─────────────────────────────────────────────

def check_mikrotik_default_admin(config: str, device_type: str) -> dict:
    """Fail if default 'admin' user exists with no password on MikroTik."""
    if re.search(r'name="admin"', config, re.IGNORECASE) and \
       re.search(r'password=""', config, re.IGNORECASE):
        return {
            "check_id": "CHK-024",
            "title": "MikroTik Default Admin No Password",
            "severity": "FAIL",
            "detail": "Default admin account exists with no password set.",
            "remediation": "Set a strong password: /user set admin password=<strong-password>"
        }
    return {
        "check_id": "CHK-024",
        "title": "MikroTik Default Admin Password",
        "severity": "PASS",
        "detail": "Default admin account appears to have a password set.",
        "remediation": ""
    }

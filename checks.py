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
        # New universal checks
        check_syslog_configured,        # CHK-025
        check_snmpv3_not_used,          # CHK-026
    ]

    # Vendor-specific additional checks
    vendor_checks = {
        "cisco":      [check_cdp_enabled, check_ip_source_route,
                       check_aaa_not_configured, check_aaa_server_not_configured,
                       check_vty_timeout, check_console_timeout,
                       check_ospf_authentication, check_bgp_authentication,
                       check_hsrp_authentication, check_ip_directed_broadcast,
                       check_weak_vpn_encryption],
        "cisco_xr":   [check_ip_source_route,
                       check_aaa_not_configured, check_aaa_server_not_configured,
                       check_vty_timeout, check_ospf_authentication,
                       check_bgp_authentication, check_weak_vpn_encryption],
        "cisco_nxos": [check_cdp_enabled,
                       check_aaa_not_configured, check_aaa_server_not_configured,
                       check_vty_timeout, check_ospf_authentication,
                       check_bgp_authentication],
        "cisco_asa":  [check_asa_asdm_enabled, check_asa_icmp_unreachable,
                       check_asa_logging, check_asa_threat_detection],
        "fortinet":   [check_fortinet_admin_https, check_fortinet_trusted_hosts,
                       check_fortinet_admin_timeout, check_fortinet_logging],
        "paloalto":   [check_paloalto_panorama, check_paloalto_syslog,
                       check_paloalto_zone_protection, check_paloalto_url_filtering],
        "juniper":    [check_juniper_root_login, check_juniper_ntp,
                       check_juniper_ospf_auth, check_juniper_bgp_auth,
                       check_juniper_login_timeout],
        "arista":     [check_cdp_enabled,
                       check_aaa_not_configured, check_aaa_server_not_configured,
                       check_vty_timeout, check_bgp_authentication],
        "huawei":     [check_huawei_telnet, check_huawei_snmp,
                       check_huawei_snmpv3, check_huawei_aaa],
        "hp_comware": [],
        "mikrotik":   [check_mikrotik_default_admin,
                       check_mikrotik_upnp, check_mikrotik_winbox],
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


# ─────────────────────────────────────────────
# New Universal Checks (CHK-025 to CHK-026)
# ─────────────────────────────────────────────

def check_syslog_configured(config: str, device_type: str) -> dict:
    """Warn if no remote syslog/logging server is configured."""
    from connector import VENDOR_FAMILY
    family = VENDOR_FAMILY.get(device_type, "cisco")

    # Palo Alto has its own dedicated syslog check (CHK-019) — skip to avoid duplicates
    if family == "paloalto":
        return None

    # Vendor-specific remote syslog patterns
    patterns = {
        "cisco":      r"logging (?:host )?\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",
        "cisco_xr":   r"logging \d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",
        "cisco_nxos": r"logging server \S+",
        "cisco_asa":  r"logging host \S+",
        "juniper":    r"syslog\s*\{[^}]*host\s+\S+",
        "arista":     r"logging host \S+",
        "huawei":     r"info-center loghost",
        "hp_comware": r"info-center loghost",
        "fortinet":   r"config log syslogd|set syslogd-server",
        "mikrotik":   r'type="remote"',
    }

    pattern = patterns.get(family, r"logging (?:host )?\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")

    if not re.search(pattern, config, re.IGNORECASE | re.DOTALL):
        return {
            "check_id": "CHK-025",
            "title": "Syslog Server Not Configured",
            "severity": "WARNING",
            "detail": "No remote syslog/logging server is configured. Logs may not be forwarded to a SIEM or central log collector.",
            "remediation": "Configure a remote syslog server to ensure logs are retained and available for incident response and forensics."
        }
    return {
        "check_id": "CHK-025",
        "title": "Syslog Server",
        "severity": "PASS",
        "detail": "A remote syslog/logging server appears to be configured.",
        "remediation": ""
    }


def check_snmpv3_not_used(config: str, device_type: str) -> dict:
    """Warn if SNMP is configured but SNMPv3 is not in use."""
    from connector import VENDOR_FAMILY
    family = VENDOR_FAMILY.get(device_type, "cisco")

    # Check if SNMP is even present in the config
    if not re.search(r"snmp", config, re.IGNORECASE):
        return {
            "check_id": "CHK-026",
            "title": "SNMPv3",
            "severity": "PASS",
            "detail": "SNMP does not appear to be configured.",
            "remediation": ""
        }

    # Vendor-specific SNMPv3 patterns
    v3_patterns = {
        "cisco":      r"snmp-server (group|user) \S+ v3",
        "cisco_xr":   r"snmp-server (group|user) \S+ v3",
        "cisco_nxos": r"snmp-server (group|user) \S+ v3",
        "juniper":    r"snmpv3",
        "huawei":     r"snmp-agent (group v3|usm-user v3)",
        "hp_comware": r"snmp-agent group v3",
    }

    pattern = v3_patterns.get(family, r"snmp.{0,30}v3")

    if not re.search(pattern, config, re.IGNORECASE):
        return {
            "check_id": "CHK-026",
            "title": "SNMPv3 Not In Use",
            "severity": "WARNING",
            "detail": "SNMP is configured but SNMPv3 does not appear to be in use. SNMPv1/v2c transmit community strings in plaintext.",
            "remediation": "Migrate to SNMPv3 with authPriv security level (authentication + encryption) and retire v1/v2c community strings."
        }
    return {
        "check_id": "CHK-026",
        "title": "SNMPv3",
        "severity": "PASS",
        "detail": "SNMPv3 appears to be configured.",
        "remediation": ""
    }


# ─────────────────────────────────────────────
# New Cisco-Family Checks (CHK-027 to CHK-035)
# Applied to: cisco, cisco_xr, cisco_nxos, arista
# ─────────────────────────────────────────────

def check_aaa_not_configured(config: str, device_type: str) -> dict:
    """Warn if AAA (Authentication, Authorisation, Accounting) model is not enabled."""
    if not re.search(r"aaa new-model", config, re.IGNORECASE):
        return {
            "check_id": "CHK-027",
            "title": "AAA Not Configured",
            "severity": "WARNING",
            "detail": "AAA (aaa new-model) is not enabled. Without AAA, centralised authentication and per-command accounting are unavailable.",
            "remediation": "Enable AAA: aaa new-model. Then configure authentication, authorisation, and accounting policies."
        }
    return {
        "check_id": "CHK-027",
        "title": "AAA Configuration",
        "severity": "PASS",
        "detail": "AAA new-model is enabled.",
        "remediation": ""
    }


def check_aaa_server_not_configured(config: str, device_type: str) -> dict:
    """Warn if AAA is enabled but no TACACS+ or RADIUS server is configured."""
    if not re.search(r"aaa new-model", config, re.IGNORECASE):
        # AAA not enabled — already flagged by CHK-027, nothing to add here
        return {
            "check_id": "CHK-028",
            "title": "TACACS+/RADIUS Server",
            "severity": "PASS",
            "detail": "AAA not enabled — see CHK-027.",
            "remediation": ""
        }

    has_tacacs = re.search(r"(tacacs-server host|tacacs server)\s+\S+", config, re.IGNORECASE)
    has_radius = re.search(r"(radius-server host|radius server)\s+\S+", config, re.IGNORECASE)

    if not has_tacacs and not has_radius:
        return {
            "check_id": "CHK-028",
            "title": "No TACACS+/RADIUS Server Configured",
            "severity": "WARNING",
            "detail": "AAA is enabled but no TACACS+ or RADIUS server is defined. Authentication falls back to local accounts only, with no centralised audit trail.",
            "remediation": "Configure a TACACS+ server: tacacs server <name> / address ipv4 <ip> / key <key>. Or use radius-server for RADIUS."
        }
    return {
        "check_id": "CHK-028",
        "title": "TACACS+/RADIUS Server",
        "severity": "PASS",
        "detail": "A TACACS+ or RADIUS server is configured.",
        "remediation": ""
    }


def check_vty_timeout(config: str, device_type: str) -> dict:
    """Warn if VTY lines have no exec-timeout or timeout is disabled (0 0)."""
    vty_blocks = re.findall(r"line vty.*?(?=line |\Z)", config, re.DOTALL | re.IGNORECASE)
    if not vty_blocks:
        return {
            "check_id": "CHK-029",
            "title": "VTY Session Timeout",
            "severity": "PASS",
            "detail": "No VTY lines found in configuration.",
            "remediation": ""
        }

    has_no_timeout = any(not re.search(r"exec-timeout", b, re.IGNORECASE) for b in vty_blocks)
    has_disabled   = any(re.search(r"exec-timeout 0 0", b, re.IGNORECASE) for b in vty_blocks)

    if has_no_timeout:
        return {
            "check_id": "CHK-029",
            "title": "VTY Session Timeout Not Configured",
            "severity": "WARNING",
            "detail": "One or more VTY line groups have no exec-timeout configured. Idle SSH/Telnet sessions remain open indefinitely and can be hijacked.",
            "remediation": "Set a timeout under each VTY line group: exec-timeout 10 0  (10 minutes)."
        }
    if has_disabled:
        return {
            "check_id": "CHK-029",
            "title": "VTY Session Timeout Disabled",
            "severity": "WARNING",
            "detail": "exec-timeout is explicitly disabled (0 0) on one or more VTY lines. Sessions never expire.",
            "remediation": "Replace exec-timeout 0 0 with a finite value: exec-timeout 10 0."
        }
    return {
        "check_id": "CHK-029",
        "title": "VTY Session Timeout",
        "severity": "PASS",
        "detail": "VTY lines have exec-timeout configured.",
        "remediation": ""
    }


def check_console_timeout(config: str, device_type: str) -> dict:
    """Warn if console line has no exec-timeout or timeout is disabled."""
    console_block = re.search(r"line con 0(.*?)(?=line |\Z)", config, re.DOTALL | re.IGNORECASE)
    if not console_block:
        return {
            "check_id": "CHK-030",
            "title": "Console Session Timeout",
            "severity": "PASS",
            "detail": "No console line block found.",
            "remediation": ""
        }

    block = console_block.group(1)
    if not re.search(r"exec-timeout", block, re.IGNORECASE):
        return {
            "check_id": "CHK-030",
            "title": "Console Session Timeout Not Configured",
            "severity": "WARNING",
            "detail": "Console line (line con 0) has no exec-timeout. Physical console sessions may remain open indefinitely when unattended.",
            "remediation": "Set a timeout under line con 0: exec-timeout 10 0."
        }
    if re.search(r"exec-timeout 0 0", block, re.IGNORECASE):
        return {
            "check_id": "CHK-030",
            "title": "Console Session Timeout Disabled",
            "severity": "WARNING",
            "detail": "Console session timeout is explicitly disabled (exec-timeout 0 0). Physical console sessions never expire.",
            "remediation": "Replace with a finite timeout: exec-timeout 10 0 under line con 0."
        }
    return {
        "check_id": "CHK-030",
        "title": "Console Session Timeout",
        "severity": "PASS",
        "detail": "Console line has exec-timeout configured.",
        "remediation": ""
    }


def check_ospf_authentication(config: str, device_type: str) -> dict:
    """Warn if OSPF is configured without authentication."""
    if not re.search(r"router ospf", config, re.IGNORECASE):
        return {
            "check_id": "CHK-031",
            "title": "OSPF Authentication",
            "severity": "PASS",
            "detail": "OSPF is not configured on this device.",
            "remediation": ""
        }

    has_area_auth  = re.search(r"area \S+ authentication", config, re.IGNORECASE)
    has_iface_auth = re.search(r"ip ospf authentication", config, re.IGNORECASE)

    if not has_area_auth and not has_iface_auth:
        return {
            "check_id": "CHK-031",
            "title": "OSPF Authentication Not Configured",
            "severity": "WARNING",
            "detail": "OSPF is configured but no authentication is set. Without authentication, any device can inject rogue LSAs and poison the routing table.",
            "remediation": "Enable MD5 authentication: area <id> authentication message-digest. Then add ip ospf message-digest-key <id> md5 <key> on each OSPF interface."
        }
    return {
        "check_id": "CHK-031",
        "title": "OSPF Authentication",
        "severity": "PASS",
        "detail": "OSPF authentication appears to be configured.",
        "remediation": ""
    }


def check_bgp_authentication(config: str, device_type: str) -> dict:
    """Warn if BGP neighbors are configured without MD5 authentication."""
    if not re.search(r"router bgp", config, re.IGNORECASE):
        return {
            "check_id": "CHK-032",
            "title": "BGP Authentication",
            "severity": "PASS",
            "detail": "BGP is not configured on this device.",
            "remediation": ""
        }

    neighbors = re.findall(r"neighbor \S+ remote-as", config, re.IGNORECASE)
    if not neighbors:
        return {
            "check_id": "CHK-032",
            "title": "BGP Authentication",
            "severity": "PASS",
            "detail": "No BGP neighbors found.",
            "remediation": ""
        }

    if not re.search(r"neighbor \S+ password", config, re.IGNORECASE):
        return {
            "check_id": "CHK-032",
            "title": "BGP MD5 Authentication Missing",
            "severity": "WARNING",
            "detail": f"BGP is configured with {len(neighbors)} neighbour(s) but no MD5 password is set. Unauthenticated BGP sessions are vulnerable to session hijacking and route injection.",
            "remediation": "Add MD5 authentication for all BGP peers: neighbor <ip> password <key>."
        }
    return {
        "check_id": "CHK-032",
        "title": "BGP Authentication",
        "severity": "PASS",
        "detail": "BGP neighbour authentication appears to be configured.",
        "remediation": ""
    }


def check_hsrp_authentication(config: str, device_type: str) -> dict:
    """Warn if HSRP or VRRP is configured without authentication."""
    has_hsrp = re.search(r"standby \d+ ip", config, re.IGNORECASE)
    has_vrrp = re.search(r"vrrp \d+ ip", config, re.IGNORECASE)

    if not has_hsrp and not has_vrrp:
        return {
            "check_id": "CHK-033",
            "title": "HSRP/VRRP Authentication",
            "severity": "PASS",
            "detail": "HSRP and VRRP do not appear to be configured.",
            "remediation": ""
        }

    has_hsrp_auth = re.search(r"standby \d+ authentication", config, re.IGNORECASE)
    has_vrrp_auth = re.search(r"vrrp \d+ authentication", config, re.IGNORECASE)

    protocol = "HSRP" if has_hsrp else "VRRP"
    if has_hsrp and has_vrrp:
        protocol = "HSRP/VRRP"

    if (has_hsrp and not has_hsrp_auth) or (has_vrrp and not has_vrrp_auth):
        return {
            "check_id": "CHK-033",
            "title": f"{protocol} Authentication Missing",
            "severity": "WARNING",
            "detail": f"{protocol} is configured without authentication. An attacker on the same segment can send crafted {protocol} packets to become the active gateway and intercept traffic.",
            "remediation": "Enable MD5 authentication: standby <group> authentication md5 key-string <key>"
        }
    return {
        "check_id": "CHK-033",
        "title": "HSRP/VRRP Authentication",
        "severity": "PASS",
        "detail": f"{protocol} authentication is configured.",
        "remediation": ""
    }


def check_ip_directed_broadcast(config: str, device_type: str) -> dict:
    """Fail if ip directed-broadcast is explicitly enabled on any interface."""
    # Directed broadcast is disabled by default in IOS 12.0+.
    # Flag only if it's explicitly turned on (without 'no' prefix).
    if re.search(r"^\s*ip directed-broadcast\b", config, re.IGNORECASE | re.MULTILINE):
        return {
            "check_id": "CHK-034",
            "title": "IP Directed Broadcast Enabled",
            "severity": "FAIL",
            "detail": "IP directed broadcast is explicitly enabled on one or more interfaces. This can be abused to amplify DDoS attacks (Smurf attack).",
            "remediation": "Disable on all interfaces: no ip directed-broadcast"
        }
    return {
        "check_id": "CHK-034",
        "title": "IP Directed Broadcast",
        "severity": "PASS",
        "detail": "IP directed broadcast does not appear to be enabled.",
        "remediation": ""
    }


def check_weak_vpn_encryption(config: str, device_type: str) -> dict:
    """Warn if DES or 3DES encryption is used in IPSec/IKE/VPN configurations."""
    # ISAKMP / IKEv1 policy weak encryption
    isakmp_weak = re.search(r"^\s*encryption (des|3des)\b", config, re.IGNORECASE | re.MULTILINE)
    # IPSec transform set weak cipher
    ipsec_weak  = re.search(r"\besp-(des|3des)\b", config, re.IGNORECASE)

    if isakmp_weak or ipsec_weak:
        weak_algos = set()
        if isakmp_weak:
            weak_algos.add(isakmp_weak.group(1).upper())
        if ipsec_weak:
            weak_algos.add(ipsec_weak.group(1).upper())
        return {
            "check_id": "CHK-035",
            "title": "Weak VPN Encryption Algorithm",
            "severity": "WARNING",
            "detail": f"Weak encryption algorithm(s) detected in VPN/IPSec configuration: {', '.join(sorted(weak_algos))}. DES is cryptographically broken; 3DES is deprecated.",
            "remediation": "Replace with AES-256 in ISAKMP policies and AES-256 transform sets. Update IKE proposals to use SHA-256 or higher for hashing."
        }
    return {
        "check_id": "CHK-035",
        "title": "VPN Encryption Strength",
        "severity": "PASS",
        "detail": "No weak VPN encryption algorithms (DES/3DES) detected.",
        "remediation": ""
    }


# ─────────────────────────────────────────────
# New Cisco ASA Checks (CHK-036 to CHK-037)
# ─────────────────────────────────────────────

def check_asa_logging(config: str, device_type: str) -> dict:
    """Warn if logging is not enabled on the ASA."""
    if not re.search(r"logging enable", config, re.IGNORECASE):
        return {
            "check_id": "CHK-036",
            "title": "ASA Logging Not Enabled",
            "severity": "WARNING",
            "detail": "Logging is not enabled on the ASA. Firewall events (connection drops, ACL hits, AAA events) will not be captured or forwarded.",
            "remediation": "Enable logging: logging enable. Then configure a destination: logging host <interface> <syslog-server-ip>."
        }
    return {
        "check_id": "CHK-036",
        "title": "ASA Logging",
        "severity": "PASS",
        "detail": "Logging is enabled on the ASA.",
        "remediation": ""
    }


def check_asa_threat_detection(config: str, device_type: str) -> dict:
    """Warn if basic threat detection is not configured on the ASA."""
    if not re.search(r"threat-detection basic-threat", config, re.IGNORECASE):
        return {
            "check_id": "CHK-037",
            "title": "ASA Threat Detection Not Configured",
            "severity": "WARNING",
            "detail": "Basic threat detection is not enabled. The ASA will not automatically track hosts performing port scans or DoS attacks.",
            "remediation": "Enable threat detection: threat-detection basic-threat. Optionally add: threat-detection statistics for detailed host tracking."
        }
    return {
        "check_id": "CHK-037",
        "title": "ASA Threat Detection",
        "severity": "PASS",
        "detail": "Basic threat detection is configured.",
        "remediation": ""
    }


# ─────────────────────────────────────────────
# New Fortinet Checks (CHK-038 to CHK-039)
# ─────────────────────────────────────────────

def check_fortinet_admin_timeout(config: str, device_type: str) -> dict:
    """Warn if FortiGate admin session timeout is missing or excessively long."""
    timeout_match = re.search(r"set admintimeout (\d+)", config, re.IGNORECASE)
    if not timeout_match:
        return {
            "check_id": "CHK-038",
            "title": "FortiGate Admin Session Timeout Not Set",
            "severity": "WARNING",
            "detail": "Admin session timeout (admintimeout) is not configured. Idle admin sessions may remain active indefinitely.",
            "remediation": "Set a timeout under config system global: set admintimeout 10  (10 minutes recommended)."
        }
    timeout_val = int(timeout_match.group(1))
    if timeout_val > 30:
        return {
            "check_id": "CHK-038",
            "title": "FortiGate Admin Session Timeout Too Long",
            "severity": "WARNING",
            "detail": f"Admin session timeout is set to {timeout_val} minutes. Values above 30 minutes leave unattended sessions exposed.",
            "remediation": "Reduce admintimeout to 10–15 minutes under config system global."
        }
    return {
        "check_id": "CHK-038",
        "title": "FortiGate Admin Session Timeout",
        "severity": "PASS",
        "detail": f"Admin session timeout is set to {timeout_val} minutes.",
        "remediation": ""
    }


def check_fortinet_logging(config: str, device_type: str) -> dict:
    """Warn if FortiGate is not sending logs to FortiAnalyzer or a syslog server."""
    has_fortianalyzer = re.search(r"config log fortianalyzer", config, re.IGNORECASE)
    has_syslog        = re.search(r"config log syslogd", config, re.IGNORECASE)

    if not has_fortianalyzer and not has_syslog:
        return {
            "check_id": "CHK-039",
            "title": "FortiGate Remote Logging Not Configured",
            "severity": "WARNING",
            "detail": "No FortiAnalyzer or syslog logging destination is configured. Firewall logs are stored locally only and are at risk of loss or tampering.",
            "remediation": "Configure remote logging: config log fortianalyzer (or syslogd), set status enable, set server <ip>."
        }
    return {
        "check_id": "CHK-039",
        "title": "FortiGate Remote Logging",
        "severity": "PASS",
        "detail": "Remote logging (FortiAnalyzer or syslog) appears to be configured.",
        "remediation": ""
    }


# ─────────────────────────────────────────────
# New Palo Alto Checks (CHK-040 to CHK-041)
# ─────────────────────────────────────────────

def check_paloalto_zone_protection(config: str, device_type: str) -> dict:
    """Warn if no zone protection profile is configured on Palo Alto."""
    if not re.search(r"zone-protection-profile", config, re.IGNORECASE):
        return {
            "check_id": "CHK-040",
            "title": "Zone Protection Profile Missing",
            "severity": "WARNING",
            "detail": "No zone protection profiles are configured. Zone protection defends against flood attacks (SYN, UDP, ICMP), port scans, and packet-based attacks at the zone level.",
            "remediation": "Create zone protection profiles under Network > Zone Protection and apply them to all zones, especially the untrust zone."
        }
    return {
        "check_id": "CHK-040",
        "title": "Zone Protection Profiles",
        "severity": "PASS",
        "detail": "Zone protection profile(s) are configured.",
        "remediation": ""
    }


def check_paloalto_url_filtering(config: str, device_type: str) -> dict:
    """Warn if no URL filtering profile is configured on Palo Alto."""
    if not re.search(r"url-filtering", config, re.IGNORECASE):
        return {
            "check_id": "CHK-041",
            "title": "URL Filtering Profile Missing",
            "severity": "WARNING",
            "detail": "No URL filtering profile is configured. Users may reach malicious, phishing, or policy-prohibited websites.",
            "remediation": "Create a URL filtering profile under Objects > Security Profiles > URL Filtering and attach it to outbound security policies."
        }
    return {
        "check_id": "CHK-041",
        "title": "URL Filtering",
        "severity": "PASS",
        "detail": "URL filtering profile is configured.",
        "remediation": ""
    }


# ─────────────────────────────────────────────
# New Juniper Checks (CHK-042 to CHK-044)
# ─────────────────────────────────────────────

def check_juniper_ospf_auth(config: str, device_type: str) -> dict:
    """Warn if OSPF is configured on Juniper without authentication."""
    if not re.search(r"protocols\s+ospf", config, re.IGNORECASE):
        return {
            "check_id": "CHK-042",
            "title": "Juniper OSPF Authentication",
            "severity": "PASS",
            "detail": "OSPF is not configured on this device.",
            "remediation": ""
        }

    if not re.search(r"authentication\s+(md5|simple)", config, re.IGNORECASE):
        return {
            "check_id": "CHK-042",
            "title": "Juniper OSPF Authentication Missing",
            "severity": "WARNING",
            "detail": "OSPF is configured but no authentication is set. Rogue devices can inject LSAs and corrupt the routing table.",
            "remediation": "Enable MD5 authentication per interface: set protocols ospf area <id> interface <if> authentication md5 <key-id> key <key>."
        }
    return {
        "check_id": "CHK-042",
        "title": "Juniper OSPF Authentication",
        "severity": "PASS",
        "detail": "OSPF authentication is configured.",
        "remediation": ""
    }


def check_juniper_bgp_auth(config: str, device_type: str) -> dict:
    """Warn if BGP is configured on Juniper without authentication keys."""
    if not re.search(r"protocols\s+bgp", config, re.IGNORECASE):
        return {
            "check_id": "CHK-043",
            "title": "Juniper BGP Authentication",
            "severity": "PASS",
            "detail": "BGP is not configured on this device.",
            "remediation": ""
        }

    if not re.search(r"authentication-key", config, re.IGNORECASE):
        return {
            "check_id": "CHK-043",
            "title": "Juniper BGP Authentication Missing",
            "severity": "WARNING",
            "detail": "BGP is configured but no authentication keys are set. Unauthenticated BGP sessions can be hijacked or used for route injection.",
            "remediation": "Set per-neighbour authentication keys: set protocols bgp group <group> neighbor <ip> authentication-key <key>."
        }
    return {
        "check_id": "CHK-043",
        "title": "Juniper BGP Authentication",
        "severity": "PASS",
        "detail": "BGP authentication key(s) are configured.",
        "remediation": ""
    }


def check_juniper_login_timeout(config: str, device_type: str) -> dict:
    """Warn if no idle-timeout is configured for Juniper login classes."""
    if not re.search(r"idle-timeout", config, re.IGNORECASE):
        return {
            "check_id": "CHK-044",
            "title": "Juniper Session Idle Timeout Not Set",
            "severity": "WARNING",
            "detail": "No idle-timeout is configured on any login class. Interactive SSH and console sessions may remain open indefinitely when unattended.",
            "remediation": "Set an idle timeout on all login classes: set system login class <class> idle-timeout <minutes>."
        }
    return {
        "check_id": "CHK-044",
        "title": "Juniper Session Idle Timeout",
        "severity": "PASS",
        "detail": "Session idle timeout is configured on login class(es).",
        "remediation": ""
    }


# ─────────────────────────────────────────────
# New Huawei Checks (CHK-045 to CHK-046)
# ─────────────────────────────────────────────

def check_huawei_snmpv3(config: str, device_type: str) -> dict:
    """Warn if SNMP is configured on Huawei device but SNMPv3 is not in use."""
    if not re.search(r"snmp-agent", config, re.IGNORECASE):
        return {
            "check_id": "CHK-045",
            "title": "Huawei SNMPv3",
            "severity": "PASS",
            "detail": "SNMP does not appear to be configured.",
            "remediation": ""
        }

    if not re.search(r"snmp-agent (group v3|usm-user v3)", config, re.IGNORECASE):
        return {
            "check_id": "CHK-045",
            "title": "Huawei SNMPv3 Not Configured",
            "severity": "WARNING",
            "detail": "SNMP is configured but SNMPv3 is not in use. SNMPv1/v2c transmit community strings in plaintext and offer no encryption.",
            "remediation": "Configure SNMPv3: snmp-agent group v3 <group> privacy and create a USM user with authentication and privacy settings."
        }
    return {
        "check_id": "CHK-045",
        "title": "Huawei SNMPv3",
        "severity": "PASS",
        "detail": "SNMPv3 is configured.",
        "remediation": ""
    }


def check_huawei_aaa(config: str, device_type: str) -> dict:
    """Warn if AAA is not configured on Huawei device."""
    if not re.search(r"^aaa\s*$", config, re.IGNORECASE | re.MULTILINE):
        return {
            "check_id": "CHK-046",
            "title": "Huawei AAA Not Configured",
            "severity": "WARNING",
            "detail": "AAA configuration block not found. Centralised authentication (RADIUS/TACACS+) and accounting may not be in place.",
            "remediation": "Configure AAA with authentication and accounting schemes, and link to a RADIUS or HWTACACS server group."
        }
    return {
        "check_id": "CHK-046",
        "title": "Huawei AAA",
        "severity": "PASS",
        "detail": "AAA configuration is present.",
        "remediation": ""
    }


# ─────────────────────────────────────────────
# New MikroTik Checks (CHK-047 to CHK-048)
# ─────────────────────────────────────────────

def check_mikrotik_upnp(config: str, device_type: str) -> dict:
    """Warn if UPnP is enabled on MikroTik."""
    if re.search(r'enabled=yes', config, re.IGNORECASE) and \
       re.search(r'/ip upnp', config, re.IGNORECASE):
        return {
            "check_id": "CHK-047",
            "title": "MikroTik UPnP Enabled",
            "severity": "WARNING",
            "detail": "UPnP (Universal Plug and Play) is enabled. UPnP allows LAN devices to automatically open firewall ports without authentication, which is commonly abused by malware.",
            "remediation": "Disable UPnP: /ip upnp set enabled=no"
        }
    return {
        "check_id": "CHK-047",
        "title": "MikroTik UPnP",
        "severity": "PASS",
        "detail": "UPnP does not appear to be enabled.",
        "remediation": ""
    }


def check_mikrotik_winbox(config: str, device_type: str) -> dict:
    """Warn if Winbox management is accessible from any IP address."""
    if not re.search(r"winbox", config, re.IGNORECASE):
        return {
            "check_id": "CHK-048",
            "title": "MikroTik Winbox Access",
            "severity": "PASS",
            "detail": "Winbox service does not appear to be configured.",
            "remediation": ""
        }

    # Flag if address restriction is missing or set to 0.0.0.0/0 (any)
    if re.search(r'winbox.*address=0\.0\.0\.0/0|winbox.*address=""', config, re.IGNORECASE):
        return {
            "check_id": "CHK-048",
            "title": "Winbox Accessible From Any Address",
            "severity": "WARNING",
            "detail": "Winbox management (TCP/8291) is accessible from any IP. Winbox has a history of critical vulnerabilities (e.g. CVE-2018-14847).",
            "remediation": "Restrict Winbox to management hosts: /ip service set winbox address=<mgmt-subnet>/24"
        }
    return {
        "check_id": "CHK-048",
        "title": "MikroTik Winbox Access",
        "severity": "PASS",
        "detail": "Winbox access appears to be restricted to specific addresses.",
        "remediation": ""
    }

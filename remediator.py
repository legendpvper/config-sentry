"""
remediator.py
--------------
Generates vendor-specific CLI remediation scripts from audit findings.
Each FAIL and WARNING finding maps to exact commands the client can
copy-paste directly into their device to fix the issue.

Output is a .txt file saved alongside the audit report.
"""

from datetime import datetime
from pathlib import Path


# ─────────────────────────────────────────────
# Remediation command library
# Keyed by (check_id, vendor_family)
# Falls back to generic if no vendor match
# ─────────────────────────────────────────────

REMEDIATIONS = {

    # ── CHK-001: Telnet Enabled ───────────────────────────────────
    ("CHK-001", "cisco"): """
line vty 0 4
 transport input ssh
line vty 5 15
 transport input ssh""",

    ("CHK-001", "huawei"): """
user-interface vty 0 4
 protocol inbound ssh""",

    ("CHK-001", "cisco_xr"): """
line default
 transport input ssh""",

    # ── CHK-002: SSH Version ──────────────────────────────────────
    ("CHK-002", "cisco"): """
ip ssh version 2""",

    ("CHK-002", "cisco_xr"): """
ssh server v2""",

    ("CHK-002", "arista"): """
management ssh
   idle-timeout 60""",

    # ── CHK-003: Default SNMP Community ──────────────────────────
    ("CHK-003", "cisco"): """
no snmp-server community public
no snmp-server community private
snmp-server community <STRONG-COMMUNITY-STRING> RO
! Replace <STRONG-COMMUNITY-STRING> with a unique value""",

    ("CHK-003", "huawei"): """
undo snmp-agent community read public
undo snmp-agent community write private
snmp-agent community read <STRONG-COMMUNITY-STRING>""",

    # ── CHK-004: SNMP Without ACL ─────────────────────────────────
    ("CHK-004", "cisco"): """
ip access-list standard SNMP-MGMT
 permit <MGMT-HOST-IP>
 deny   any
!
snmp-server community <COMMUNITY> RO SNMP-MGMT
! Replace <MGMT-HOST-IP> with your management station IP""",

    # ── CHK-005: NTP Not Configured ───────────────────────────────
    ("CHK-005", "cisco"): """
ntp server <NTP-SERVER-IP> prefer
ntp server <NTP-SERVER-IP-2>
! Common public NTP: 1.pool.ntp.org / time.google.com""",

    ("CHK-005", "cisco_xr"): """
ntp
 server <NTP-SERVER-IP> prefer
 commit""",

    ("CHK-005", "juniper"): """
set system ntp server <NTP-SERVER-IP> prefer
set system ntp server <NTP-SERVER-IP-2>
commit""",

    ("CHK-005", "huawei"): """
ntp-service unicast-server <NTP-SERVER-IP> preference""",

    ("CHK-005", "fortinet"): """
config system ntp
    set type custom
    set ntpsync enable
    config ntpserver
        edit 1
            set server "pool.ntp.org"
        next
    end
end""",

    # ── CHK-006: Login Banner ─────────────────────────────────────
    ("CHK-006", "cisco"): """
banner motd ^
*************************************************************
* AUTHORISED ACCESS ONLY                                    *
* Unauthorised access is prohibited and may be prosecuted.  *
*************************************************************
^""",

    ("CHK-006", "juniper"): """
set system login message "AUTHORISED ACCESS ONLY. Unauthorised access is prohibited."
commit""",

    ("CHK-006", "huawei"): """
header login information "AUTHORISED ACCESS ONLY. Unauthorised access is prohibited." """,

    # ── CHK-007: Multiple Privilege-15 Users ─────────────────────
    ("CHK-007", "cisco"): """
! Review privilege-15 users — keep only one break-glass account
! For other admins, use lower privilege levels:
username <ADMIN-USER> privilege 5 secret <STRONG-PASSWORD>
privilege exec level 5 show running-config
! Remove unnecessary privilege-15 accounts:
no username <UNNECESSARY-USER>""",

    # ── CHK-008: Console Not Password Protected ───────────────────
    ("CHK-008", "cisco"): """
line con 0
 login local
 exec-timeout 5 0
! Ensure a local user exists:
username admin privilege 15 secret <STRONG-PASSWORD>""",

    ("CHK-008", "huawei"): """
user-interface console 0
 authentication-mode aaa
aaa
 local-user admin password irreversible-cipher <STRONG-PASSWORD>
 local-user admin privilege level 15""",

    # ── CHK-009: VTY Without Access-Class ────────────────────────
    ("CHK-009", "cisco"): """
ip access-list standard MGMT-ACCESS
 permit <MGMT-HOST-IP-OR-SUBNET>
 deny   any log
!
line vty 0 4
 access-class MGMT-ACCESS in
line vty 5 15
 access-class MGMT-ACCESS in
! Replace <MGMT-HOST-IP-OR-SUBNET> with your management network""",

    # ── CHK-010: Password Encryption ─────────────────────────────
    ("CHK-010", "cisco"): """
service password-encryption""",

    # ── CHK-011: HTTP Server ──────────────────────────────────────
    ("CHK-011", "cisco"): """
no ip http server
! If HTTPS management is needed:
ip http secure-server""",

    # ── CHK-012: CDP Enabled ──────────────────────────────────────
    ("CHK-012", "cisco"): """
no cdp run
! Re-enable only on specific trusted interfaces if needed:
! interface GigabitEthernet0/0
!  cdp enable""",

    # ── CHK-013: IP Source Routing ────────────────────────────────
    ("CHK-013", "cisco"): """
no ip source-route""",

    ("CHK-013", "cisco_xr"): """
no ipv4 source-route""",

    # ── CHK-014: ASDM Unrestricted (ASA) ─────────────────────────
    ("CHK-014", "cisco_asa"): """
! Remove unrestricted HTTP access
no http 0.0.0.0 0.0.0.0 <INTERFACE>
! Add restricted access for management hosts only
http <MGMT-HOST-IP> <SUBNET-MASK> <INTERFACE>
! Example: http 192.168.1.10 255.255.255.255 management""",

    # ── CHK-015: ICMP Rate Limit (ASA) ───────────────────────────
    ("CHK-015", "cisco_asa"): """
icmp unreachable rate-limit 1 burst-size 1""",

    # ── CHK-016: FortiGate HTTP Admin ────────────────────────────
    ("CHK-016", "fortinet"): """
config system global
    set admin-http disable
    set admin-https enable
    set admin-sport 443
end""",

    # ── CHK-017: FortiGate Trusted Hosts ─────────────────────────
    ("CHK-017", "fortinet"): """
config system admin
    edit <ADMIN-USERNAME>
        set trusthost1 <MGMT-IP> <SUBNET-MASK>
        ! Example: set trusthost1 192.168.1.10 255.255.255.255
    next
end""",

    # ── CHK-018: Palo Alto Panorama ───────────────────────────────
    ("CHK-018", "paloalto"): """
! Configure Panorama via GUI:
! Device > Setup > Management > Panorama Settings
! Or via CLI:
set deviceconfig system panorama-server <PANORAMA-IP>
set deviceconfig system panorama-server-2 <PANORAMA-IP-2>
commit""",

    # ── CHK-019: Palo Alto Syslog ────────────────────────────────
    ("CHK-019", "paloalto"): """
! Configure via GUI:
! Device > Server Profiles > Syslog > Add
! Name: SIEM-Syslog
! Server: <SIEM-IP>, Port: 514, Facility: LOG_USER
! Then assign to log forwarding profiles under Objects > Log Forwarding""",

    # ── CHK-020: Juniper Root SSH Login ──────────────────────────
    ("CHK-020", "juniper"): """
set system services ssh root-login deny
commit""",

    # ── CHK-021: Juniper NTP ──────────────────────────────────────
    ("CHK-021", "juniper"): """
set system ntp server <NTP-SERVER-IP> prefer
set system ntp server <NTP-SERVER-IP-2>
commit""",

    # ── CHK-022: Huawei Telnet ────────────────────────────────────
    ("CHK-022", "huawei"): """
undo telnet server enable
stelnet server enable
! Ensure SSH is configured as replacement:
rsa local-key-pair create""",

    # ── CHK-023: Huawei SNMP ──────────────────────────────────────
    ("CHK-023", "huawei"): """
undo snmp-agent community read public
undo snmp-agent community write private
snmp-agent community read <STRONG-COMMUNITY-STRING>
! Consider upgrading to SNMPv3:
snmp-agent group v3 <GROUP-NAME> privacy
snmp-agent usm-user v3 <USERNAME> <GROUP-NAME>""",

    # ── CHK-024: MikroTik Default Admin ───────────────────────────
    ("CHK-024", "mikrotik"): """
/user set admin password=<STRONG-PASSWORD>
! Also consider renaming the admin account:
/user add name=<NEW-ADMIN> password=<STRONG-PASSWORD> group=full
/user remove admin""",
}

# Generic fallback for checks without vendor-specific commands
GENERIC_REMEDIATIONS = {
    "CHK-001": "Disable Telnet on all VTY lines and enforce SSH-only access.",
    "CHK-002": "Explicitly configure SSH version 2.",
    "CHK-003": "Remove default SNMP community strings (public/private) and replace with strong unique values.",
    "CHK-004": "Attach an ACL to all SNMP community strings to restrict access to authorised management hosts.",
    "CHK-005": "Configure at least one NTP server for accurate time synchronisation.",
    "CHK-006": "Add a login banner warning that access is authorised only.",
    "CHK-007": "Limit full-privilege accounts to one break-glass user.",
    "CHK-008": "Require authentication on the console line.",
    "CHK-009": "Apply an ACL to all VTY lines restricting SSH to management hosts only.",
    "CHK-010": "Enable password encryption to prevent plaintext passwords in config.",
    "CHK-011": "Disable the unencrypted HTTP management server.",
    "CHK-012": "Disable CDP globally and re-enable only on trusted interfaces.",
    "CHK-013": "Disable IP source routing.",
    "CHK-014": "Restrict ASDM access to specific management host IPs.",
    "CHK-015": "Configure ICMP unreachable rate limiting.",
    "CHK-016": "Disable HTTP admin access and enforce HTTPS only.",
    "CHK-017": "Configure trusted host restrictions on all admin accounts.",
    "CHK-018": "Connect device to Panorama for centralised management.",
    "CHK-019": "Configure a syslog server profile and assign to log forwarding.",
    "CHK-020": "Deny root login via SSH.",
    "CHK-021": "Configure NTP servers for accurate time synchronisation.",
    "CHK-022": "Disable Telnet server and use STelnet (SSH) instead.",
    "CHK-023": "Remove default SNMP community strings.",
    "CHK-024": "Set a strong password on the default admin account.",
}


# ─────────────────────────────────────────────
# Vendor family lookup (mirrors connector.py)
# ─────────────────────────────────────────────

VENDOR_FAMILY = {
    "cisco_ios":         "cisco",
    "cisco_ios_xe":      "cisco",
    "cisco_xr":          "cisco_xr",
    "cisco_nxos":        "cisco",
    "cisco_asa":         "cisco_asa",
    "fortinet":          "fortinet",
    "paloalto_panos":    "paloalto",
    "juniper_junos":     "juniper",
    "arista_eos":        "arista",
    "huawei":            "huawei",
    "huawei_vrp":        "huawei",
    "hp_comware":        "cisco",
    "hp_procurve":       "cisco",
    "dell_os10":         "cisco",
    "dell_powerconnect": "cisco",
    "mikrotik_routeros": "mikrotik",
    "ubiquiti_edge":     "cisco",
}


# ─────────────────────────────────────────────
# Main generator
# ─────────────────────────────────────────────

def generate_remediation_script(
    result: dict,
    device_type: str,
    output_path: str
) -> str:
    """
    Generate a remediation script for a single device audit result.

    Args:
        result:      Audit result dict from auditor.py
        device_type: Netmiko device type string
        output_path: Where to save the .txt script

    Returns:
        Path to the saved script file
    """
    vendor = VENDOR_FAMILY.get(device_type, "cisco")
    findings = result.get("findings", [])
    hostname = result.get("hostname", "Unknown")
    score    = result.get("score", {})

    actionable = [f for f in findings if f["severity"] in ("FAIL", "WARNING")]

    lines = []
    lines.append("!" * 65)
    lines.append(f"! ConfigSentry — Remediation Script")
    lines.append(f"! Device   : {hostname} ({result.get('host', '')})")
    lines.append(f"! Vendor   : {device_type}")
    lines.append(f"! Score    : {score.get('score', '?')}/100 — {score.get('risk_level', '?')}")
    lines.append(f"! Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("!" * 65)
    lines.append("!")
    lines.append("! IMPORTANT: Review all commands before applying.")
    lines.append("! Replace all placeholders in <ANGLE-BRACKETS> with real values.")
    lines.append("! Test in a lab or maintenance window before production use.")
    lines.append("!")

    if not actionable:
        lines.append("! No remediation required — all checks passed.")
    else:
        fails    = [f for f in actionable if f["severity"] == "FAIL"]
        warnings = [f for f in actionable if f["severity"] == "WARNING"]

        if fails:
            lines.append("")
            lines.append("!" + "─" * 63)
            lines.append(f"! CRITICAL FIXES ({len(fails)} items) — Apply immediately")
            lines.append("!" + "─" * 63)
            for finding in fails:
                lines += _format_finding_block(finding, vendor)

        if warnings:
            lines.append("")
            lines.append("!" + "─" * 63)
            lines.append(f"! RECOMMENDED FIXES ({len(warnings)} items) — Apply when possible")
            lines.append("!" + "─" * 63)
            for finding in warnings:
                lines += _format_finding_block(finding, vendor)

    lines.append("")
    lines.append("!" * 65)
    lines.append("! END OF REMEDIATION SCRIPT")
    lines.append("!" * 65)

    content = "\n".join(lines)
    Path(output_path).write_text(content, encoding="utf-8")
    return output_path


def generate_all_remediation_scripts(
    results: list[dict],
    device_types: list[str],
    out_dir: str,
    timestamp: str
) -> list[str]:
    """
    Generate remediation scripts for all audited devices.

    Args:
        results:      List of audit result dicts
        device_types: Matching list of device type strings
        out_dir:      Directory to save scripts
        timestamp:    Timestamp string for filenames

    Returns:
        List of paths to generated script files
    """
    paths = []
    for result, device_type in zip(results, device_types):
        if result["status"] == "UNREACHABLE":
            continue
        actionable = [f for f in result.get("findings", []) if f["severity"] in ("FAIL", "WARNING")]
        if not actionable:
            continue

        safe_name = result["hostname"].replace(" ", "_").replace("/", "-")
        out_path  = str(Path(out_dir) / f"remediation_{safe_name}_{timestamp}.txt")
        generate_remediation_script(result, device_type, out_path)
        paths.append(out_path)
        print(f"[✓] Remediation script saved to: {out_path}")

    return paths


def _format_finding_block(finding: dict, vendor: str) -> list[str]:
    """Format a single finding into comment + command lines."""
    lines = []
    lines.append("")
    lines.append(f"! [{finding['check_id']}] {finding['title']}")
    lines.append(f"! Issue: {finding['detail'][:100]}")
    lines.append("!")

    # Look up vendor-specific commands, fall back to generic note
    commands = REMEDIATIONS.get(
        (finding["check_id"], vendor),
        REMEDIATIONS.get((finding["check_id"], "cisco"), None)
    )

    if commands:
        for line in commands.strip().split("\n"):
            lines.append(line)
    else:
        generic = GENERIC_REMEDIATIONS.get(finding["check_id"], "Refer to vendor documentation.")
        lines.append(f"! ACTION REQUIRED: {generic}")

    return lines

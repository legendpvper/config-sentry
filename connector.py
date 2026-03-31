"""
connector.py
-------------
Handles SSH connections to network devices using Netmiko.
Returns a connection object and the raw running configuration.
"""

import getpass
from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoTimeoutException, NetmikoAuthenticationException


# Commands to pull running config per device type
CONFIG_COMMANDS = {
    # Cisco
    "cisco_ios":        "show running-config",
    "cisco_ios_xe":     "show running-config",
    "cisco_xr":         "show running-config",
    "cisco_nxos":       "show running-config",
    "cisco_asa":        "show running-config",
    # Fortinet
    "fortinet":         "show full-configuration",
    # Palo Alto
    "paloalto_panos":   "show config running",
    # Juniper
    "juniper_junos":    "show configuration",
    # Arista
    "arista_eos":       "show running-config",
    # Huawei
    "huawei":           "display current-configuration",
    "huawei_vrp":       "display current-configuration",
    # HP / HPE
    "hp_comware":       "display current-configuration",
    "hp_procurve":      "show running-config",
    # Dell
    "dell_os10":        "show running-configuration",
    "dell_powerconnect": "show running-config",
    # Mikrotik
    "mikrotik_routeros": "/export",
    # Ubiquiti
    "ubiquiti_edge":    "show configuration",
}

# Vendor family groupings for applying the right checks
VENDOR_FAMILY = {
    "cisco_ios":        "cisco",
    "cisco_ios_xe":     "cisco",
    "cisco_xr":         "cisco_xr",
    "cisco_nxos":       "cisco_nxos",
    "cisco_asa":        "cisco_asa",
    "fortinet":         "fortinet",
    "paloalto_panos":   "paloalto",
    "juniper_junos":    "juniper",
    "arista_eos":       "arista",
    "huawei":           "huawei",
    "huawei_vrp":       "huawei",
    "hp_comware":       "hp_comware",
    "hp_procurve":      "cisco",
    "dell_os10":        "cisco",
    "dell_powerconnect": "cisco",
    "mikrotik_routeros": "mikrotik",
    "ubiquiti_edge":    "cisco",
}


def connect_to_device(device: dict):
    """
    Establish an SSH connection to a network device.

    Args:
        device (dict): Device info with keys:
            - host, username, password, device_type
            - optional: port (default 22), secret (enable password)

    Returns:
        tuple: (connection_object, raw_config_string)
               Returns (None, "") on failure.
    """
    device_type = device.get("device_type", "cisco_ios")
    host = device.get("host")

    # Prompt for password if not supplied (safer than hardcoding)
    password = device.get("password") or getpass.getpass(
        f"  Enter SSH password for {host}: "
    )

    connection_params = {
        "device_type": device_type,
        "host": host,
        "username": device.get("username"),
        "password": password,
        "port": device.get("port", 22),
        "timeout": 15,
        "banner_timeout": 15,
    }

    # Add enable secret if provided (Cisco devices)
    if device.get("secret"):
        connection_params["secret"] = device["secret"]

    try:
        connection = ConnectHandler(**connection_params)

        # Enter enable mode if secret is set
        if device.get("secret"):
            connection.enable()

        # Pull running config
        config_command = CONFIG_COMMANDS.get(device_type, "show running-config")
        raw_config = connection.send_command(config_command)

        return connection, raw_config

    except NetmikoAuthenticationException:
        print(f"  [ERROR] Authentication failed for {host}. Check credentials.")
        return None, ""

    except NetmikoTimeoutException:
        print(f"  [ERROR] Connection timed out for {host}. Check IP and SSH service.")
        return None, ""

    except Exception as e:
        print(f"  [ERROR] Could not connect to {host}: {e}")
        return None, ""

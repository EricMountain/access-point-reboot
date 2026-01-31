#!/usr/bin/env python3

"""Reboot Access Points via SSH."""

import subprocess
import re
import paramiko
import sys
import os
import tomllib
import argparse


# Load configuration from config.toml
def load_config():
    """Load configuration from config.toml file"""
    config_path = os.path.join(os.path.dirname(__file__), "config.toml")

    if not os.path.exists(config_path):
        print("Error: config.toml not found!", file=sys.stderr)
        print("Please create config.toml based on config.example.toml", file=sys.stderr)
        sys.exit(1)

    with open(config_path, 'rb') as f:
        return tomllib.load(f)


def discover_mesh_aps():
    """Discover mesh APs on the network using ARP scan"""
    print("Scanning network for mesh APs...")

    try:
        result = subprocess.run(
            ["arp-scan", "--localnet"],
            capture_output=True,
            text=True,
            timeout=30
        )
        output = result.stdout
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        print(f"arp-scan failed: {e}", file=sys.stderr)
        print("Install with: sudo apt install arp-scan", file=sys.stderr)
        return []

    # Get known APs from config
    known_aps_list = config.get("known_aps", [])

    # Create a lookup dict by MAC for easy access
    known_aps_dict = {ap["mac"].lower(): ap for ap in known_aps_list}

    # Parse IPs and MACs
    discovered = {}  # Use dict to avoid duplicates, keyed by MAC
    lines = output.split('\n')

    for line in lines:
        # Look for AP MAC addresses
        mac_match = re.search(r'([0-9a-fA-F]{2}[:-]){5}([0-9a-fA-F]{2})', line)
        if mac_match:
            mac = mac_match.group(0).lower()

            # Check if it's an AP we care about
            if mac in known_aps_dict:
                # Extract IP
                ip_match = re.search(
                    r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', line)

                if ip_match:
                    ip = ip_match.group(0)
                    ap_config = known_aps_dict.get(mac, {})
                    discovered[mac] = {
                        "ip": ip,
                        "mac": mac,
                        "name": ap_config.get("name", "Unknown"),
                        "username": ap_config.get("username", config.get("default_username", "root")),
                        "password": ap_config.get("password", config.get("default_password", ""))
                    }
                    print(
                        f"Found AP: {ip} ({mac}) - {ap_config.get('name', 'Unknown')}")

    # Return devices in the order specified in config
    ordered_devices = []
    for ap_config in known_aps_list:
        mac = ap_config["mac"].lower()
        if mac in discovered:
            ordered_devices.append(discovered[mac])
            del discovered[mac]

    return ordered_devices


def check_ssh_connectivity(ap):
    """Check SSH connectivity to an AP without rebooting."""
    ip = ap["ip"]
    mac = ap["mac"]
    name = ap.get("name", "Unknown")
    username = ap["username"]
    password = ap["password"]

    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        print(f"Checking SSH to {name} at {ip} ({mac})...")
        ssh.connect(ip, username=username, password=password,
                    timeout=10, allow_agent=False)

        stdin, stdout, stderr = ssh.exec_command("echo SSH_OK", timeout=10)
        out = stdout.read().decode().strip()
        err = stderr.read().decode().strip()
        ssh.close()

        if "SSH_OK" in out:
            print(f"✓ SSH connectivity confirmed for {name} at {ip}")
            return True
        else:
            print(f"✗ SSH command failed for {name} at {ip}. stdout: {out}, stderr: {err}", file=sys.stderr)
            return False

    except Exception as e:
        print(f"✗ SSH connectivity failed for {name} at {ip} ({mac}): {e}", file=sys.stderr)
        return False


def reboot_ap_ssh(ap, dry_run=False):
    """Reboot an AP via SSH or check connectivity in dry-run mode."""
    if dry_run:
        return check_ssh_connectivity(ap)

    ip = ap["ip"]
    mac = ap["mac"]
    name = ap.get("name", "Unknown")
    username = ap["username"]
    password = ap["password"]

    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        print(f"Connecting to {name} at {ip} ({mac})...")
        ssh.connect(ip, username=username, password=password,
                    timeout=10, allow_agent=False)

        stdin, stdout, stderr = ssh.exec_command("reboot")
        print(f"✓ Reboot command sent to {name} at {ip}")

        ssh.close()
        return True

    except Exception as e:
        print(
            f"✗ Failed to reboot {name} at {ip} ({mac}): {e}", file=sys.stderr)
        return False


def main():
    parser = argparse.ArgumentParser(description="Reboot mesh APs or perform a dry-run to confirm discovery and SSH connectivity.")
    parser.add_argument('--dry-run', '-n', action='store_true', help='Do not reboot; only check AP discovery and SSH connectivity')
    args = parser.parse_args()

    aps = discover_mesh_aps()

    if not aps:
        print("\nNo mesh APs discovered!", file=sys.stderr)
        sys.exit(1)

    if args.dry_run:
        print(f"\nFound {len(aps)} AP(s). Performing dry-run (checking SSH connectivity)...")
        results = []
        for ap in aps:
            ok = reboot_ap_ssh(ap, dry_run=True)
            results.append(ok)
        if all(results):
            print("\n✅ Dry-run successful: all APs discovered and SSH reachable.")
            sys.exit(0)
        else:
            print("\n⚠️ Dry-run found connectivity failures. See errors above.", file=sys.stderr)
            sys.exit(2)
    else:
        print(f"\nFound {len(aps)} AP(s). Rebooting them...")
        # Reboot each AP
        for ap in aps:
            reboot_ap_ssh(ap)


if __name__ == "__main__":
    config = load_config()
    main()

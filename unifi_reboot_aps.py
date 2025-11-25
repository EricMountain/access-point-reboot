#!/usr/bin/env python3
import subprocess
import re
import paramiko
import sys
import time
import os

try:
    import tomli as tomllib
except ImportError:
    try:
        import tomllib
    except ImportError:
        print("Error: tomli/tomllib not available!", file=sys.stderr)
        print("Install with: pip install tomli", file=sys.stderr)
        sys.exit(1)

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

# Load configuration
config = load_config()

def discover_mesh_aps():
    """Discover mesh APs on the network using ARP scan"""
    print("Scanning network for mesh APs...")
    
    try:
        result = subprocess.run(
            ["sudo", "arp-scan", "--localnet"],
            capture_output=True,
            text=True,
            timeout=30
        )
        output = result.stdout
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        print(f"arp-scan failed: {e}", file=sys.stderr)
        print("Install with: sudo apt install arp-scan", file=sys.stderr)
        return []
    
    # Get known APs from config (now a list)
    known_aps_list = config.get("known_aps", [])
    
    # Create a lookup dict by MAC for easy access
    known_aps_dict = {ap["mac"].lower(): ap for ap in known_aps_list}
    
    # Parse IPs and MACs
    discovered = {}  # Use dict to avoid duplicates, keyed by MAC
    lines = output.split('\n')
    
    for line in lines:
        # Look for Ubiquiti MAC addresses
        mac_match = re.search(r'([0-9a-fA-F]{2}[:-]){5}([0-9a-fA-F]{2})', line)
        if mac_match:
            mac = mac_match.group(0).lower()
            
            # Check if it's a known AP or Ubiquiti device
            if (not known_aps_dict or mac in known_aps_dict) or \
               mac.startswith('94:2a:6f') or mac.startswith('f4:e2:c6'):
                
                # Extract IP from same line
                ip_match = re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', line)
                
                if ip_match:
                    ip = ip_match.group(0)
                    # Get AP config if available
                    ap_config = known_aps_dict.get(mac, {})
                    discovered[mac] = {
                        "ip": ip,
                        "mac": mac,
                        "name": ap_config.get("name", "Unknown"),
                        "username": ap_config.get("username", config.get("default_username", "root")),
                        "password": ap_config.get("password", config.get("default_password", ""))
                    }
                    print(f"Found AP: {ip} ({mac}) - {ap_config.get('name', 'Unknown')}")
    
    # Return devices in the order specified in config
    ordered_devices = []
    for ap_config in known_aps_list:
        mac = ap_config["mac"].lower()
        if mac in discovered:
            ordered_devices.append(discovered[mac])
            del discovered[mac]  # Remove from dict
    
    return ordered_devices

def reboot_ap_ssh(ap):
    """Reboot an AP via SSH"""
    ip = ap["ip"]
    mac = ap["mac"]
    name = ap.get("name", "Unknown")
    username = ap["username"]
    password = ap["password"]
    
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        print(f"Connecting to {name} at {ip} ({mac})...")
        ssh.connect(ip, username=username, password=password, timeout=10, allow_agent=False)
        
        # Send reboot command
        stdin, stdout, stderr = ssh.exec_command("reboot")
        print(f"✓ Reboot command sent to {name} at {ip}")
        
        ssh.close()
        return True
        
    except Exception as e:
        print(f"✗ Failed to reboot {name} at {ip} ({mac}): {e}", file=sys.stderr)
        return False

def main():
    # Discover APs using arp-scan
    aps = discover_mesh_aps()
    
    if not aps:
        print("\nNo mesh APs discovered!", file=sys.stderr)
        sys.exit(1)
    
    print(f"\nFound {len(aps)} AP(s). Rebooting...")
    
    # Reboot each AP
    for ap in aps:
        reboot_ap_ssh(ap)
        time.sleep(2)  # Brief delay between reboots

if __name__ == "__main__":
    main()

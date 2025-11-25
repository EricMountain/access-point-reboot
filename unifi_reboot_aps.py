#!/usr/bin/env python3
import subprocess
import re
import paramiko
import sys
import time

# Network configuration
NETWORK_SUBNET = "10.0.10.0/24"  # Your network range
SSH_USERNAME = "root"
SSH_PASSWORD = "your_ssh_password"  # Or use SSH_KEY_PATH instead

# Known mesh AP MAC addresses (optional - for filtering)
KNOWN_AP_MACS = [
    "94:2a:6f:16:af:78",  # Kitchen
    "94:2a:6f:16:b6:1c",  # Bedroom
    "94:2a:6f:16:c2:bf",  # Lounge
]

def discover_mesh_aps():
    """Discover mesh APs on the network using ARP scan"""
    print("Scanning network for mesh APs...")
    
    # Use arp-scan or nmap to discover devices
    try:
        # Option 1: Using arp-scan (faster)
        result = subprocess.run(
            ["sudo", "arp-scan", "--localnet"],
            capture_output=True,
            text=True,
            timeout=30
        )
        output = result.stdout
    except (subprocess.TimeoutExpired, FileNotFoundError):
        # Option 2: Fallback to nmap
        result = subprocess.run(
            ["nmap", "-sn", NETWORK_SUBNET],
            capture_output=True,
            text=True,
            timeout=60
        )
        output = result.stdout
    
    # Parse IPs and MACs
    devices = []
    lines = output.split('\n')
    
    for i, line in enumerate(lines):
        # Look for Ubiquiti MAC addresses (starts with common prefixes)
        mac_match = re.search(r'([0-9a-fA-F]{2}[:-]){5}([0-9a-fA-F]{2})', line)
        if mac_match:
            mac = mac_match.group(0).lower()
            
            # Check if it's a known AP or Ubiquiti device
            if (not KNOWN_AP_MACS or mac in [m.lower() for m in KNOWN_AP_MACS]) or \
               mac.startswith('94:2a:6f') or mac.startswith('f4:e2:c6'):
                
                # Extract IP from same line or nearby
                ip_match = re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', line)
                if not ip_match and i > 0:
                    ip_match = re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', lines[i-1])
                
                if ip_match:
                    ip = ip_match.group(0)
                    devices.append({"ip": ip, "mac": mac})
                    print(f"Found AP: {ip} ({mac})")
    
    return devices

def discover_aps_via_arp_table():
    """Alternative: Parse system ARP table"""
    print("Checking ARP table...")
    
    result = subprocess.run(["arp", "-n"], capture_output=True, text=True)
    devices = []
    
    for line in result.stdout.split('\n')[1:]:  # Skip header
        parts = line.split()
        if len(parts) >= 3:
            ip = parts[0]
            mac = parts[2].lower()
            
            if (not KNOWN_AP_MACS or mac in [m.lower() for m in KNOWN_AP_MACS]) or \
               mac.startswith('94:2a:6f') or mac.startswith('f4:e2:c6'):
                devices.append({"ip": ip, "mac": mac})
                print(f"Found AP: {ip} ({mac})")
    
    return devices

def discover_aps_via_hostname():
    """Discover APs by hostname pattern"""
    print("Scanning for UniFi AP hostnames...")
    
    # Common UniFi AP hostname patterns
    hostname_patterns = [
        "u7-pro", "uap", "unifi-ap", "u6-", "uap-ac", "uap6",
        "unifi", "ubnt", "ap-"
    ]
    
    devices = []
    
    try:
        # Use nmap with hostname resolution
        result = subprocess.run(
            ["nmap", "-sn", "-R", NETWORK_SUBNET],
            capture_output=True,
            text=True,
            timeout=60
        )
        
        lines = result.stdout.split('\n')
        current_ip = None
        current_hostname = None
        
        for line in lines:
            # Look for IP address lines
            ip_match = re.search(r'Nmap scan report for (?:(\S+) \()?(\d+\.\d+\.\d+\.\d+)', line)
            if ip_match:
                current_hostname = ip_match.group(1) if ip_match.group(1) else None
                current_ip = ip_match.group(2)
                
                # Check if hostname matches UniFi patterns
                if current_hostname:
                    hostname_lower = current_hostname.lower()
                    if any(pattern in hostname_lower for pattern in hostname_patterns):
                        devices.append({"ip": current_ip, "hostname": current_hostname})
                        print(f"Found AP: {current_ip} ({current_hostname})")
        
        # Also try mDNS/Avahi discovery for .local hostnames
        try:
            avahi_result = subprocess.run(
                ["avahi-browse", "-t", "-r", "_ssh._tcp", "--resolve"],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            for line in avahi_result.stdout.split('\n'):
                for pattern in hostname_patterns:
                    if pattern in line.lower() and "address" in line.lower():
                        ip_match = re.search(r'\[(\d+\.\d+\.\d+\.\d+)\]', line)
                        if ip_match:
                            ip = ip_match.group(1)
                            if not any(d["ip"] == ip for d in devices):
                                devices.append({"ip": ip, "hostname": "discovered via mDNS"})
                                print(f"Found AP via mDNS: {ip}")
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass  # avahi-browse not available
                
    except Exception as e:
        print(f"Hostname scan failed: {e}", file=sys.stderr)
    
    return devices

def reboot_ap_ssh(ip, mac):
    """Reboot an AP via SSH"""
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        print(f"Connecting to {ip} ({mac})...")
        ssh.connect(ip, username=SSH_USERNAME, password=SSH_PASSWORD, timeout=10)
        
        # Send reboot command
        stdin, stdout, stderr = ssh.exec_command("reboot")
        print(f"✓ Reboot command sent to {ip} ({mac})")
        
        ssh.close()
        return True
        
    except Exception as e:
        print(f"✗ Failed to reboot {ip} ({mac}): {e}", file=sys.stderr)
        return False

def main():
    # Try multiple discovery methods
    aps = []
    
    # Method 1: Hostname-based discovery (often most reliable)
    aps = discover_aps_via_hostname()
    
    # Method 2: MAC address scan
    if not aps:
        print("\nNo APs found by hostname. Trying MAC address scan...")
        aps = discover_mesh_aps()
    
    # Method 3: ARP table fallback
    if not aps:
        print("\nNo APs found by MAC. Trying ARP table...")
        aps = discover_aps_via_arp_table()
    
    if not aps:
        print("\nNo mesh APs discovered!", file=sys.stderr)
        sys.exit(1)
    
    print(f"\nFound {len(aps)} AP(s). Rebooting...")
    
    # Reboot each AP
    for ap in aps:
        mac = ap.get("mac", "unknown")
        reboot_ap_ssh(ap["ip"], mac)
        time.sleep(2)  # Brief delay between reboots

if __name__ == "__main__":
    main()

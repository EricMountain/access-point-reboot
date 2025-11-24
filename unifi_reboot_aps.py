#!/usr/bin/env python3
import requests
import sys



session = requests.Session()
session.verify = VERIFY_SSL

def login():
    url = f"{UNIFI_HOST}/api/auth/login"
    payload = {"username": USERNAME, "password": PASSWORD}
    r = session.post(url, json=payload)
    r.raise_for_status()

def get_aps():
    # Get all devices and filter for APs
    url = f"{UNIFI_HOST}/proxy/network/api/s/{SITE}/stat/device"
    r = session.get(url)
    r.raise_for_status()
    data = r.json()["data"]
    aps = [d for d in data if d.get("type") in ("uap", "uap6", "uap-plus")]
    return aps

def reboot_devices(macs):
    url = f"{UNIFI_HOST}/proxy/network/api/s/{SITE}/cmd/devmgr"
    for mac in macs:
        payload = {"cmd": "restart", "mac": mac.lower()}
        r = session.post(url, json=payload)
        if r.status_code == 200:
            print(f"Reboot command sent to {mac}")
        else:
            print(f"Failed to reboot {mac}: {r.status_code} {r.text}", file=sys.stderr)

def main():
    login()

    # OPTION 1: use hard-coded MACS_TO_REBOOT
    if MACS_TO_REBOOT:
        reboot_devices(MACS_TO_REBOOT)
        return

    # OPTION 2: automatically find APs and reboot all
    # aps = get_aps()
    # macs = [ap["mac"] for ap in aps]
    # print("Rebooting APs:", macs)
    # reboot_devices(macs)

if __name__ == "__main__":
    main()

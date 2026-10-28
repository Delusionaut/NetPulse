"""Wi-Fi neighbor scan, local NIC stats, listening ports, top network processes, optional SNMP."""

from __future__ import annotations

import platform
import re
import socket
import subprocess
from collections import defaultdict
from typing import Any

import psutil

WIN = platform.system() == "Windows"
NOWIN = subprocess.CREATE_NO_WINDOW if WIN else 0


def wifi_neighbors() -> dict[str, Any]:
    if not WIN:
        return {"ok": False, "reason": "Wi-Fi neighbor parse is implemented for Windows netsh", "networks": []}
    try:
        proc = subprocess.run(
            ["netsh", "wlan", "show", "networks", "mode=bssid"],
            capture_output=True,
            text=True,
            timeout=20,
            creationflags=NOWIN,
        )
        text = proc.stdout
    except Exception as exc:
        return {"ok": False, "reason": str(exc), "networks": []}
    networks = []
    current: dict[str, Any] | None = None
    bssid: dict[str, Any] | None = None
    for line in text.splitlines():
        ssid_m = re.match(r"\s*SSID\s+\d+\s*:\s*(.*)$", line)
        if ssid_m:
            if current:
                networks.append(current)
            current = {"ssid": ssid_m.group(1).strip(), "auth": "", "encryption": "", "bssids": []}
            bssid = None
            continue
        if not current:
            continue
        auth = re.match(r"\s*Authentication\s*:\s*(.*)$", line)
        enc = re.match(r"\s*Encryption\s*:\s*(.*)$", line)
        bs = re.match(r"\s*BSSID\s+\d+\s*:\s*(.*)$", line)
        sig = re.match(r"\s*Signal\s*:\s*(.*)$", line)
        ch = re.match(r"\s*Channel\s*:\s*(.*)$", line)
        radio = re.match(r"\s*Radio type\s*:\s*(.*)$", line)
        if auth:
            current["auth"] = auth.group(1).strip()
        elif enc:
            current["encryption"] = enc.group(1).strip()
        elif bs:
            bssid = {"bssid": bs.group(1).strip().upper(), "signal": "", "channel": "", "radio": ""}
            current["bssids"].append(bssid)
        elif sig and bssid is not None:
            bssid["signal"] = sig.group(1).strip()
        elif ch and bssid is not None:
            bssid["channel"] = ch.group(1).strip()
        elif radio and bssid is not None:
            bssid["radio"] = radio.group(1).strip()
    if current:
        networks.append(current)

    connected = {"ssid": "", "bssid": ""}
    try:
        iface = subprocess.run(
            ["netsh", "wlan", "show", "interfaces"],
            capture_output=True,
            text=True,
            timeout=10,
            creationflags=NOWIN,
        ).stdout
        sm = re.search(r"^\s*SSID\s*:\s*(.+)$", iface, re.M)
        bm = re.search(r"^\s*BSSID\s*:\s*(.+)$", iface, re.M)
        connected["ssid"] = sm.group(1).strip() if sm else ""
        connected["bssid"] = bm.group(1).strip().upper() if bm else ""
    except Exception:
        pass

    occupancy: dict[str, int] = defaultdict(int)
    unknown_bssid = False
    for net in networks:
        for b in net["bssids"]:
            occupancy[str(b.get("channel") or "?")] += 1
            if connected["ssid"] and net["ssid"] == connected["ssid"]:
                if connected["bssid"] and b["bssid"] != connected["bssid"]:
                    b["same_ssid_other_bssid"] = True
                if connected["bssid"] and b["bssid"] == connected["bssid"]:
                    b["associated"] = True
        if connected["ssid"] and net["ssid"] == connected["ssid"]:
            known = {b["bssid"] for b in net["bssids"]}
            if connected["bssid"] and connected["bssid"] not in known:
                unknown_bssid = True

    return {
        "ok": True,
        "connected": connected,
        "networks": networks,
        "occupancy": dict(occupancy),
        "unknown_bssid_on_ssid": unknown_bssid,
    }


def nic_and_process_report() -> dict[str, Any]:
    pernic = psutil.net_io_counters(pernic=True)
    nics = []
    for name, c in pernic.items():
        nics.append(
            {
                "name": name,
                "bytes_sent": c.bytes_sent,
                "bytes_recv": c.bytes_recv,
                "errin": c.errin,
                "errout": c.errout,
                "dropin": c.dropin,
                "dropout": c.dropout,
            }
        )
    listeners = []
    by_proc: dict[int, dict[str, Any]] = {}
    try:
        conns = psutil.net_connections(kind="inet")
    except Exception:
        conns = []
    for c in conns:
        laddr = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else ""
        raddr = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else ""
        if c.status == "LISTEN":
            listeners.append({"proto": "tcp", "local": laddr, "pid": c.pid, "status": c.status})
        pid = c.pid or 0
        rec = by_proc.setdefault(pid, {"pid": pid, "name": "?", "connections": 0})
        rec["connections"] += 1
    for pid, rec in by_proc.items():
        if pid:
            try:
                rec["name"] = psutil.Process(pid).name()
            except Exception:
                rec["name"] = "?"
        else:
            rec["name"] = "System"
    top = sorted(by_proc.values(), key=lambda r: r["connections"], reverse=True)[:15]
    return {"nics": nics, "listening": listeners[:80], "top_processes": top}


def snmp_sysname(host: str, community: str = "public", timeout: float = 2.0) -> dict[str, Any]:
    """Minimal SNMPv1 GET sysDescr / sysName. Optional — fails closed if the host ignores SNMP."""
    try:
        proc = subprocess.run(
            ["snmpget", "-v1", "-c", community, "-t", "1", host, "1.3.6.1.2.1.1.5.0"],
            capture_output=True,
            text=True,
            timeout=timeout + 1,
            creationflags=NOWIN,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            return {"ok": True, "sysname": proc.stdout.strip(), "via": "snmpget"}
    except Exception:
        pass
    return {"ok": False, "reason": "No SNMP response (install net-snmp tools or enable SNMP on the router)"}

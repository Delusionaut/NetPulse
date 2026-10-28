"""
NetPulse — local LAN analyzer.
Network scanning runs on a dedicated background thread. The desktop UI talks to a localhost API.
"""

from __future__ import annotations

import ipaddress
import os
import platform
import socket
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

import psutil

import api_validate
import connectivity
import inspect_host
import lan_discovery
import notify
import oui_service
import port_scan
import store
import paths
import wifi_local

try:
    import eel
except ImportError:
    class _EelStub:
        """Keeps @eel.expose call sites working when the Eel UI is not installed."""

        def expose(self, fn=None):
            def deco(func):
                return func

            return deco(fn) if fn else deco

        def init(self, *_args, **_kwargs) -> None:
            return None

        def start(self, *_args, **_kwargs) -> None:
            return None

        def __getattr__(self, _name: str):
            def _noop(*_args, **_kwargs):
                return None

            return _noop

    eel = _EelStub()

_state_lock = threading.Lock()
_scan_lock = threading.Lock()
_port_lock = threading.Lock()
_scanning = False
_port_scanning = False
_devices: list[dict[str, Any]] = []
_port_meta: dict[str, Any] = {
    "progress": 0,
    "total": 0,
    "current_ip": None,
    "profile": "common",
    "error": None,
}
_scan_meta: dict[str, Any] = {
    "progress": 0,
    "total": 0,
    "last_scan": None,
    "error": None,
    "method": None,
}
_extra: dict[str, Any] = {
    "mdns": [],
    "ssdp": [],
    "upnp_maps": [],
    "dhcp": {},
    "dhcp_fp": [],
    "wifi": {},
    "local": {},
    "nat": {},
    "ipv6": {},
    "dns": {},
    "traceroute": {},
    "speed": {},
    "ping": {"gateway": {}, "internet": {}},
    "alerts": [],
    "outages": [],
    "topology": [],
    "snmp": {},
    "schedule_minutes": 0,
}
_gateway_mac: str | None = None
_busy: dict[str, bool] = {}

_net_stats: dict[str, Any] = {
    "local_ip": "—",
    "gateway": "—",
    "iface": "—",
    "hostname": socket.gethostname(),
    "cidr": "—",
    "mac": "—",
    "down_bps": 0.0,
    "up_bps": 0.0,
    "bytes_recv": 0,
    "bytes_sent": 0,
}


def _push(name: str, *args) -> None:
    fn = getattr(eel, name, None)
    if not callable(fn):
        return
    try:
        fn(*args)
    except Exception:
        pass


def _normalize_mac(raw: str) -> str:
    hex_chars = "".join(c for c in raw.upper() if c in "0123456789ABCDEF")
    if len(hex_chars) != 12:
        return raw.replace("-", ":").upper()
    return ":".join(hex_chars[i : i + 2] for i in range(0, 12, 2))


def _windows_gateway() -> str | None:
    try:
        completed = subprocess.run(
            ["route", "print", "0.0.0.0"],
            capture_output=True,
            text=True,
            timeout=5,
            creationflags=subprocess.CREATE_NO_WINDOW if platform.system() == "Windows" else 0,
        )
        for line in completed.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 3 and parts[0] == "0.0.0.0":
                candidate = parts[2]
                ipaddress.IPv4Address(candidate)
                return candidate
    except Exception:
        pass
    return None


def _linux_gateway() -> str | None:
    try:
        with open("/proc/net/route", encoding="utf-8") as handle:
            next(handle)
            for line in handle:
                fields = line.split()
                if fields[1] == "00000000":
                    packed = int(fields[2], 16)
                    return socket.inet_ntoa(packed.to_bytes(4, "little"))
    except Exception:
        pass
    return None


def detect_network() -> dict[str, Any]:
    hostname = socket.gethostname()
    local_ip = "127.0.0.1"
    try:
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        probe.settimeout(1)
        probe.connect(("8.8.8.8", 80))
        local_ip = probe.getsockname()[0]
        probe.close()
    except Exception:
        try:
            local_ip = socket.gethostbyname(hostname)
        except Exception:
            pass

    gateway = _windows_gateway() if platform.system() == "Windows" else _linux_gateway()
    iface_name = "—"
    netmask = "255.255.255.0"
    mac = "—"

    for name, addrs in psutil.net_if_addrs().items():
        ipv4 = None
        hw = None
        mask = None
        for addr in addrs:
            if addr.family == socket.AF_INET and addr.address == local_ip:
                ipv4 = addr.address
                mask = addr.netmask
            if addr.family == getattr(psutil, "AF_LINK", object()) or (
                hasattr(socket, "AF_PACKET") and addr.family == socket.AF_PACKET
            ):
                hw = addr.address
            if platform.system() == "Windows" and addr.family == -1:
                hw = addr.address
        if ipv4:
            iface_name = name
            if mask:
                netmask = mask
            if hw:
                mac = _normalize_mac(hw)
            break

    # Cap scans at /24 so a misread /16 does not freeze a home LAN sweep.
    network = api_validate.capped_network(local_ip, netmask)

    info = {
        "local_ip": local_ip,
        "gateway": gateway or "—",
        "iface": iface_name,
        "hostname": hostname,
        "cidr": str(network),
        "mac": mac,
        "prefix": network.prefixlen,
        "hosts": [str(h) for h in network.hosts()],
    }
    with _state_lock:
        _net_stats.update(
            {
                "local_ip": info["local_ip"],
                "gateway": info["gateway"],
                "iface": info["iface"],
                "hostname": info["hostname"],
                "cidr": info["cidr"],
                "mac": info["mac"],
            }
        )
    return info


def _ping_host(ip: str, timeout_ms: int = 400) -> bool:
    system = platform.system()
    if system == "Windows":
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
        flags = subprocess.CREATE_NO_WINDOW
    else:
        seconds = max(1, timeout_ms // 1000)
        cmd = ["ping", "-c", "1", "-W", str(seconds), ip]
        flags = 0
    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=2,
            creationflags=flags,
        )
        return result.returncode == 0
    except Exception:
        return False


def _parse_arp_table() -> dict[str, str]:
    mapping: dict[str, str] = {}
    try:
        result = subprocess.run(
            ["arp", "-a"],
            capture_output=True,
            text=True,
            timeout=8,
            creationflags=subprocess.CREATE_NO_WINDOW if platform.system() == "Windows" else 0,
        )
        for line in result.stdout.splitlines():
            parts = line.split()
            if len(parts) < 2:
                continue
            ip_token = parts[0].strip()
            mac_token = parts[1].strip()
            try:
                ipaddress.IPv4Address(ip_token)
            except Exception:
                continue
            if "incomplete" in mac_token.lower() or mac_token.count("-") + mac_token.count(":") < 5:
                continue
            mapping[ip_token] = _normalize_mac(mac_token)
    except Exception:
        pass
    return mapping


def _reverse_dns(ip: str) -> str:
    try:
        name, _, _ = socket.gethostbyaddr(ip)
        return name
    except Exception:
        return ""


def _try_scapy_arp(network_cidr: str) -> dict[str, str] | None:
    try:
        from scapy.all import ARP, Ether, conf, srp  # type: ignore
    except Exception:
        return None
    try:
        conf.verb = 0
        packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network_cidr)
        answered, _ = srp(packet, timeout=2, retry=1)
        found: dict[str, str] = {}
        for _, recv in answered:
            found[recv.psrc] = _normalize_mac(recv.hwsrc)
        return found
    except Exception:
        return None


def _classify(ip: str, local_ip: str, gateway: str) -> str:
    if ip == local_ip:
        return "This PC"
    if ip == gateway:
        return "Gateway"
    last = int(ip.split(".")[-1])
    if last in (1, 254):
        return "Router / AP"
    return "Host"


def _enrich_lan_services(devices: list[dict[str, Any]]) -> None:
    mdns = []
    ssdp = []
    try:
        mdns = lan_discovery.mdns_browse(2.0)
    except Exception:
        mdns = []
    try:
        ssdp = lan_discovery.ssdp_search(2.0)
    except Exception:
        ssdp = []
    mdns_by = {m["ip"]: m for m in mdns}
    ssdp_by = {s["ip"]: s for s in ssdp}

    def nb(ip: str) -> str:
        return lan_discovery.netbios_name(ip)

    with ThreadPoolExecutor(max_workers=16) as pool:
        futs = {pool.submit(nb, d["ip"]): d for d in devices}
        for fut, d in futs.items():
            try:
                name = fut.result()
            except Exception:
                name = ""
            if name:
                d["netbios"] = name
                if d.get("name") in ("Unknown device", d.get("vendor")):
                    d["name"] = name
    for d in devices:
        if d["ip"] in mdns_by:
            d["mdns"] = mdns_by[d["ip"]]
            names = mdns_by[d["ip"]].get("names") or []
            if names and (not d.get("name") or d["name"] == "Unknown device"):
                d["name"] = names[0]
        if d["ip"] in ssdp_by:
            d["ssdp"] = ssdp_by[d["ip"]]
            fn = ssdp_by[d["ip"]].get("friendly_name")
            if fn:
                d["name"] = fn
                d["nature"] = f"UPnP: {ssdp_by[d['ip']].get('model') or fn}"
    with _state_lock:
        _extra["mdns"] = mdns
        _extra["ssdp"] = ssdp


def _persist_presence(devices: list[dict[str, Any]]) -> None:
    seen = set()
    events = []
    for d in devices:
        info = store.upsert_device(d, present=True)
        seen.add(info["mac"])
        events.extend(info.get("events") or [])
        meta = store.device_meta(info["mac"])
        d.update(
            {
                "trusted": meta.get("trusted"),
                "owned": meta.get("owned"),
                "tags": meta.get("tags") or [],
                "first_seen": meta.get("first_seen"),
                "last_seen": meta.get("last_seen"),
                "notes": meta.get("notes") or "",
                "store_mac": info["mac"],
            }
        )
    events.extend(store.mark_missing(seen))
    hook = store.get_setting("webhook_url")
    for ev in events:
        if hook:
            notify.webhook(hook, ev)
        if ev.get("kind") in {"new-device", "left-network", "ip-change", "new-port"}:
            notify.desktop_toast(ev.get("title") or "NetPulse", ev.get("detail") or "")
    with _state_lock:
        _extra["alerts"] = store.alerts(60)


def _check_arp_anomalies(devices: list[dict[str, Any]], gateway: str, arp_table: dict[str, str]) -> None:
    global _gateway_mac
    gw_mac = None
    for d in devices:
        if d.get("is_gateway"):
            gw_mac = d.get("mac")
    if not gw_mac:
        gw_mac = arp_table.get(gateway)
    if gw_mac and _gateway_mac and gw_mac != _gateway_mac and gw_mac != "—":
        store.add_alert("arp-gateway-mac", "critical", "Gateway MAC changed", f"{_gateway_mac} → {gw_mac}", gateway, gw_mac)
        notify.desktop_toast("Gateway MAC changed", f"{_gateway_mac} → {gw_mac}")
    if gw_mac and gw_mac != "—":
        _gateway_mac = gw_mac
    by_ip: dict[str, list[str]] = {}
    by_mac: dict[str, list[str]] = {}
    for ip, mac in arp_table.items():
        by_ip.setdefault(ip, []).append(mac)
        by_mac.setdefault(mac, []).append(ip)
    for ip, macs in by_ip.items():
        if len(set(macs)) > 1:
            store.add_alert("arp-dup-ip", "critical", f"Duplicate IP {ip}", ", ".join(sorted(set(macs))), ip, "")
    for mac, ips in by_mac.items():
        if len(set(ips)) > 1 and mac and mac != "—":
            store.add_alert("arp-dup-mac", "warn", f"MAC {mac} on multiple IPs", ", ".join(sorted(set(ips))), "", mac)


def _topology(devices: list[dict[str, Any]], net: dict[str, Any]) -> list[dict[str, Any]]:
    nodes = [
        {"id": "internet", "label": "Internet", "kind": "cloud"},
        {"id": "gateway", "label": net.get("gateway") or "Gateway", "kind": "gateway"},
    ]
    edges = [{"from": "internet", "to": "gateway"}]
    for d in devices:
        if d.get("is_gateway"):
            continue
        nodes.append({"id": d["ip"], "label": d.get("name") or d["ip"], "kind": "self" if d.get("is_self") else "host"})
        edges.append({"from": "gateway", "to": d["ip"]})
    return {"nodes": nodes, "edges": edges, "honest": "L3 only: internet → default gateway → LAN hosts. Switches and Wi-Fi APs are not visible without extra L2 data."}


def _scan_worker() -> None:
    global _scanning, _devices
    try:
        net = detect_network()
        hosts = net["hosts"]
        local_ip = net["local_ip"]
        gateway = net["gateway"]
        cidr = net["cidr"]
        total = len(hosts)
        with _state_lock:
            _scan_meta.update({"progress": 0, "total": total, "error": None})

        _push("on_scan_progress", 0, total)

        method = "ICMP + ARP table"
        arp_hits = _try_scapy_arp(cidr)
        if arp_hits:
            method = "ARP (Scapy) + ICMP"

        alive: set[str] = set()
        if local_ip:
            alive.add(local_ip)
        if gateway and gateway != "—":
            alive.add(gateway)
        if arp_hits:
            alive.update(arp_hits.keys())

        done = 0
        workers = 48 if platform.system() == "Windows" else 64
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {pool.submit(_ping_host, ip): ip for ip in hosts}
            for future in as_completed(futures):
                ip = futures[future]
                try:
                    if future.result():
                        alive.add(ip)
                except Exception:
                    pass
                done += 1
                if done % 8 == 0 or done == total:
                    with _state_lock:
                        _scan_meta["progress"] = done
                    _push("on_scan_progress", done, total)

        arp_table = _parse_arp_table()
        if arp_hits:
            arp_table = {**arp_table, **arp_hits}

        with _state_lock:
            previous_ports = {d.get("ip"): d.get("open_ports") for d in _devices if d.get("open_ports")}

        devices: list[dict[str, Any]] = []
        for ip in sorted(alive, key=lambda v: tuple(int(p) for p in v.split("."))):
            mac = arp_table.get(ip, "")
            if ip == local_ip and not mac:
                mac = net.get("mac") or ""
            name = _reverse_dns(ip)
            role = _classify(ip, local_ip, gateway)
            is_self = ip == local_ip
            is_gateway = ip == gateway
            ident = oui_service.identify(
                mac or "",
                hostname=name,
                role=role,
                is_self=is_self,
                is_gateway=is_gateway,
            )
            vendor = ident.get("vendor") or "Unknown"
            display = name or vendor
            if is_self:
                display = net["hostname"] or display
            devices.append(
                {
                    "ip": ip,
                    "mac": mac or "—",
                    "name": display or "Unknown device",
                    "vendor": vendor,
                    "oui_source": ident.get("source") or "none",
                    "oui_prefix": ident.get("prefix") or "",
                    "nature": ident.get("nature") or "Unknown endpoint",
                    "nature_note": ident.get("note") or "",
                    "confidence": ident.get("confidence") or "low",
                    "role": role,
                    "is_self": is_self,
                    "is_gateway": is_gateway,
                    "open_ports": previous_ports.get(ip) or [],
                    "port_scan_state": "idle",
                    "risk": inspect_host.risk_score(previous_ports.get(ip) or []),
                }
            )

        _enrich_lan_services(devices)
        _persist_presence(devices)
        _check_arp_anomalies(devices, gateway, arp_table)
        _extra["topology"] = _topology(devices, net)

        stamp = time.strftime("%H:%M:%S")
        with _state_lock:
            _devices = devices
            _scan_meta.update(
                {
                    "progress": total,
                    "total": total,
                    "last_scan": stamp,
                    "method": method,
                    "error": None,
                }
            )
        _push(
            "on_scan_complete",
            devices,
            {
                "last_scan": stamp,
                "method": method,
                "count": len(devices),
                "oui": oui_service.status(),
                "topology": _extra.get("topology"),
            },
        )
    except Exception as exc:
        with _state_lock:
            _scan_meta["error"] = str(exc)
        _push("on_scan_error", str(exc))
    finally:
        with _scan_lock:
            _scanning = False
        _push("on_scan_state", False)


def _stats_loop() -> None:
    prev = psutil.net_io_counters()
    prev_t = time.time()
    detect_network()
    while True:
        time.sleep(1.0)
        now = time.time()
        counters = psutil.net_io_counters()
        dt = max(now - prev_t, 0.001)
        down = max(0.0, (counters.bytes_recv - prev.bytes_recv) / dt)
        up = max(0.0, (counters.bytes_sent - prev.bytes_sent) / dt)
        prev, prev_t = counters, now
        payload = {
            "down_bps": down,
            "up_bps": up,
            "bytes_recv": counters.bytes_recv,
            "bytes_sent": counters.bytes_sent,
        }
        with _state_lock:
            _net_stats.update(payload)
            snapshot = dict(_net_stats)
            snapshot["scanning"] = _scanning
            snapshot["device_count"] = len(_devices)
            snapshot["last_scan"] = _scan_meta.get("last_scan")
            snapshot["scan_method"] = _scan_meta.get("method")
            snapshot["oui"] = oui_service.status()
            snapshot["port_scanning"] = _port_scanning
            snapshot["port_meta"] = dict(_port_meta)
            snapshot["extra"] = {
                "ping": _extra.get("ping"),
                "alerts": store.alerts(20, unacked_only=True),
            }
        _push("on_net_stats", snapshot)


@eel.expose
def get_snapshot() -> dict[str, Any]:
    with _state_lock:
        return {
            "devices": list(_devices),
            "stats": dict(_net_stats),
            "scanning": _scanning,
            "scan": dict(_scan_meta),
            "oui": oui_service.status(),
            "port_scanning": _port_scanning,
            "port_meta": dict(_port_meta),
            "extra": dict(_extra),
            "alerts": store.alerts(80),
            "outages": store.outages(),
            "speed_history": store.speed_history(),
            "webhook_url": store.get_setting("webhook_url"),
            "schedule_minutes": int(store.get_setting("schedule_minutes", "0") or 0),
        }


@eel.expose
def start_scan() -> dict[str, Any]:
    global _scanning
    with _scan_lock:
        if _scanning:
            return {"ok": False, "reason": "Scan already running"}
        _scanning = True
        worker = threading.Thread(target=_scan_worker, name="netpulse-scan", daemon=True)
        worker.start()
    _push("on_scan_state", True)
    return {"ok": True}


@eel.expose
def get_oui_status() -> dict[str, Any]:
    return oui_service.status()


@eel.expose
def refresh_oui_database() -> dict[str, Any]:
    def work() -> None:
        def progress(msg: str) -> None:
            _push("on_oui_progress", msg)

        result = oui_service.refresh_from_public(force=True, on_progress=progress)
        _push("on_oui_status", result)
        with _state_lock:
            devices = list(_devices)
        if devices:
            enriched = []
            for device in devices:
                ident = oui_service.identify(
                    device.get("mac") or "",
                    hostname=device.get("name") or "",
                    role=device.get("role") or "",
                    is_self=bool(device.get("is_self")),
                    is_gateway=bool(device.get("is_gateway")),
                )
                enriched.append(
                    {
                        **device,
                        "vendor": ident.get("vendor") or device.get("vendor"),
                        "oui_source": ident.get("source") or "",
                        "oui_prefix": ident.get("prefix") or "",
                        "nature": ident.get("nature") or device.get("nature"),
                        "nature_note": ident.get("note") or "",
                        "confidence": ident.get("confidence") or "low",
                    }
                )
            with _state_lock:
                _devices.clear()
                _devices.extend(enriched)
            _push("on_scan_complete", enriched, {"count": len(enriched), "oui": result})

    threading.Thread(target=work, name="netpulse-oui-refresh", daemon=True).start()
    return {"ok": True, "refreshing": True}


def _on_oui_ready(result: dict[str, Any]) -> None:
    _push("on_oui_status", result)


def _busy_run(name: str, fn) -> None:
    _busy[name] = True
    try:
        fn()
    finally:
        _busy[name] = False


@eel.expose
def get_alerts() -> list[dict[str, Any]]:
    return store.alerts(100)


@eel.expose
def ack_alert(alert_id: int) -> dict[str, Any]:
    store.ack_alert(int(alert_id))
    return {"ok": True, "alerts": store.alerts(80)}


@eel.expose
def set_device_meta(mac: str, trusted: bool = False, owned: bool = False, tags: list | None = None, notes: str = "") -> dict[str, Any]:
    store.set_device_flags(mac, trusted=bool(trusted), owned=bool(owned), tags=list(tags or []), notes=notes)
    with _state_lock:
        for d in _devices:
            if d.get("store_mac") == mac.upper() or d.get("mac") == mac:
                d["trusted"] = trusted
                d["owned"] = owned
                d["tags"] = tags or []
                d["notes"] = notes
        snap = list(_devices)
    _push("on_scan_complete", snap, {"count": len(snap)})
    return {"ok": True}


@eel.expose
def wake_host(mac: str) -> dict[str, Any]:
    return inspect_host.wake_on_lan(mac)


@eel.expose
def run_traceroute(host: str = "1.1.1.1") -> dict[str, Any]:
    result = connectivity.traceroute(host)
    with _state_lock:
        _extra["traceroute"] = result
    _push("on_extra", "traceroute", result)
    return result


@eel.expose
def run_dns_check() -> dict[str, Any]:
    result = connectivity.dns_checks()
    with _state_lock:
        _extra["dns"] = result
    _push("on_extra", "dns", result)
    return result


@eel.expose
def run_nat_check() -> dict[str, Any]:
    with _state_lock:
        local = _net_stats.get("local_ip") or ""
        gw = _net_stats.get("gateway") or ""
    result = connectivity.nat_report(local, gw)
    v6 = connectivity.ipv6_report()
    with _state_lock:
        _extra["nat"] = result
        _extra["ipv6"] = v6
    _push("on_extra", "nat", result)
    _push("on_extra", "ipv6", v6)
    return {"nat": result, "ipv6": v6}


@eel.expose
def run_speed_test() -> dict[str, Any]:
    result = connectivity.speed_and_bufferbloat()
    if result.get("ok"):
        store.add_speed(
            result.get("down_mbps") or 0,
            result.get("up_mbps") or 0,
            result.get("idle_ms") or 0,
            result.get("load_ms") or 0,
            result.get("bufferbloat") or "",
        )
    with _state_lock:
        _extra["speed"] = result
    _push("on_extra", "speed", result)
    return result


@eel.expose
def run_wifi_scan() -> dict[str, Any]:
    result = wifi_local.wifi_neighbors()
    with _state_lock:
        _extra["wifi"] = result
    _push("on_extra", "wifi", result)
    return result


@eel.expose
def run_local_report() -> dict[str, Any]:
    result = wifi_local.nic_and_process_report()
    with _state_lock:
        _extra["local"] = result
    _push("on_extra", "local", result)
    return result


@eel.expose
def run_upnp_maps() -> dict[str, Any]:
    maps = lan_discovery.upnp_port_mappings()
    with _state_lock:
        _extra["upnp_maps"] = maps
    _push("on_extra", "upnp_maps", maps)
    return {"ok": True, "mappings": maps}


@eel.expose
def run_dhcp_probe() -> dict[str, Any]:
    result = lan_discovery.dhcp_discover()
    if result.get("rogue"):
        store.add_alert("rogue-dhcp", "critical", "Multiple DHCP servers", ", ".join(result.get("servers") or []))
        notify.desktop_toast("Rogue DHCP?", ", ".join(result.get("servers") or []))
    with _state_lock:
        _extra["dhcp"] = result
        _extra["dhcp_fp"] = lan_discovery.dhcp_fingerprints()
    _push("on_extra", "dhcp", result)
    return result


@eel.expose
def run_snmp(host: str = "", community: str = "public") -> dict[str, Any]:
    if not host:
        with _state_lock:
            host = _net_stats.get("gateway") or ""
    result = wifi_local.snmp_sysname(host, community)
    with _state_lock:
        _extra["snmp"] = result
    _push("on_extra", "snmp", result)
    return result


@eel.expose
def run_default_creds(ip: str, confirm: bool = False) -> dict[str, Any]:
    if not confirm:
        return {"ok": False, "reason": "Refused: default-credential checks are user-gated. Pass confirm=true after you opt in."}
    with _state_lock:
        device = next((d for d in _devices if d.get("ip") == ip), None)
    if not device:
        return {"ok": False, "reason": "Host is not in the current LAN list"}
    if not device.get("owned") and not device.get("trusted"):
        return {"ok": False, "reason": "Mark the device as owned (or trusted) first. This check only runs on your own gear."}
    ports = {int(p["port"]) for p in (device.get("open_ports") or [])}
    http_ports = [p for p in (80, 8080, 8000) if p in ports] or [80]
    result = inspect_host.check_default_http(ip, http_ports[0])
    store.add_alert("cred-check", "info", f"Default-cred check {ip}", json_detail(result), ip, device.get("mac") or "")
    return result


def json_detail(obj: Any) -> str:
    import json as _json
    return _json.dumps(obj)[:500]


@eel.expose
def set_webhook(url: str) -> dict[str, Any]:
    store.set_setting("webhook_url", url or "")
    return {"ok": True}


@eel.expose
def set_schedule(minutes: int) -> dict[str, Any]:
    store.set_setting("schedule_minutes", str(int(minutes)))
    with _state_lock:
        _extra["schedule_minutes"] = int(minutes)
    return {"ok": True}


@eel.expose
def export_inventory() -> dict[str, Any]:
    return {"devices": store.export_devices(), "alerts": store.alerts(200), "outages": store.outages(50)}


@eel.expose
def presence_for(mac: str) -> list[dict[str, Any]]:
    return store.presence_history(mac)


def _ping_watch() -> None:
    internet_down = False
    while True:
        time.sleep(3)
        with _state_lock:
            gw = _net_stats.get("gateway") or ""
        gw_r = connectivity.ping_once(gw) if gw and gw != "—" else {"ok": False, "ms": None}
        net_r = connectivity.ping_once("1.1.1.1")
        if gw and gw != "—":
            store.add_ping("gateway", gw_r.get("ms"), bool(gw_r.get("ok")))
        store.add_ping("internet", net_r.get("ms"), bool(net_r.get("ok")))
        if not net_r.get("ok"):
            if not internet_down:
                internet_down = True
                store.open_outage("internet", "Ping to 1.1.1.1 failed")
                store.add_alert("outage", "critical", "Internet outage", "1.1.1.1 unreachable")
                notify.desktop_toast("Internet outage", "1.1.1.1 unreachable")
        else:
            if internet_down:
                internet_down = False
                store.close_outage("internet")
                store.add_alert("outage-end", "info", "Internet restored", "")
        with _state_lock:
            _extra["ping"] = {
                "gateway": {**gw_r, **store.ping_stats("gateway")},
                "internet": {**net_r, **store.ping_stats("internet")},
            }
            _extra["outages"] = store.outages()
        _push("on_extra", "ping", _extra["ping"])


def _scheduler() -> None:
    last = 0.0
    while True:
        time.sleep(15)
        try:
            minutes = int(store.get_setting("schedule_minutes", "0") or 0)
        except Exception:
            minutes = 0
        if minutes <= 0:
            continue
        if time.time() - last >= minutes * 60:
            last = time.time()
            start_scan()


def _refresh_local_loop() -> None:
    while True:
        try:
            with _state_lock:
                _extra["local"] = wifi_local.nic_and_process_report()
                _extra["dhcp_fp"] = lan_discovery.dhcp_fingerprints()
        except Exception:
            pass
        time.sleep(8)


def _known_ips() -> set[str]:
    with _state_lock:
        return {d["ip"] for d in _devices if d.get("ip")}


def _apply_ports(ip: str, opened: list[dict[str, Any]], state: str = "done") -> list[dict[str, Any]]:
    extra = {}
    if state == "done" and opened:
        extra = inspect_host.enrich_from_ports(ip, opened)
        extra["risk"] = inspect_host.risk_score(opened)
    with _state_lock:
        for device in _devices:
            if device.get("ip") == ip:
                device["open_ports"] = opened
                device["port_scan_state"] = state
                if extra.get("http"):
                    device["http"] = extra["http"]
                if extra.get("tls"):
                    device["tls"] = extra["tls"]
                if extra.get("risk"):
                    device["risk"] = extra["risk"]
                break
        snapshot = list(_devices)
    _push("on_host_ports", ip, opened, state)
    return snapshot


def _port_worker(targets: list[str], profile: str) -> None:
    global _port_scanning
    try:
        allowed = _known_ips()
        hosts = [ip for ip in targets if ip in allowed]
        if not hosts:
            _push("on_port_error", "No discovered hosts to scan. Run a network scan first.")
            return
        if profile not in port_scan.PROFILES:
            profile = "common"
        with _state_lock:
            _port_meta.update({"progress": 0, "total": 0, "current_ip": None, "profile": profile, "error": None})
            for device in _devices:
                if device.get("ip") in hosts:
                    device["port_scan_state"] = "queued"
            queued = list(_devices)
        _push("on_scan_complete", queued, {"count": len(queued), "oui": oui_service.status()})

        def on_progress(done: int, total: int) -> None:
            with _state_lock:
                _port_meta.update({"progress": done, "total": total})
            _push("on_port_progress", done, total, _port_meta.get("current_ip"))

        def on_host(ip: str, opened: list[dict], index: int, total_hosts: int) -> None:
            with _state_lock:
                _port_meta["current_ip"] = ip
            _apply_ports(ip, opened, "done")
            _push("on_port_host_done", ip, index, total_hosts, opened)

        port_scan.scan_hosts(hosts, profile=profile, on_host=on_host, on_progress=on_progress)
        with _state_lock:
            snapshot = list(_devices)
        _push("on_port_scan_complete", snapshot)
    except Exception as exc:
        with _state_lock:
            _port_meta["error"] = str(exc)
        _push("on_port_error", str(exc))
    finally:
        with _port_lock:
            _port_scanning = False
        _push("on_port_scan_state", False)


@eel.expose
def start_port_scan(ip: str | None = None, profile: str = "common") -> dict[str, Any]:
    global _port_scanning
    with _port_lock:
        if _port_scanning:
            return {"ok": False, "reason": "Port scan already running"}
        with _state_lock:
            if ip:
                targets = [ip] if any(d.get("ip") == ip for d in _devices) else []
            else:
                targets = [d["ip"] for d in _devices if d.get("ip")]
        if not targets:
            return {"ok": False, "reason": "No discovered hosts to scan"}
        _port_scanning = True
        worker = threading.Thread(
            target=_port_worker,
            args=(targets, profile or "common"),
            name="netpulse-ports",
            daemon=True,
        )
        worker.start()
    _push("on_port_scan_state", True)
    return {"ok": True, "hosts": len(targets), "profile": profile or "common"}


def _static_dir() -> Path | None:
    env = os.environ.get("NETPULSE_STATIC", "").strip()
    if env.lower() in {"none", "0"}:
        return None
    if env:
        candidate = Path(env)
        return candidate if candidate.is_dir() else None
    bundled = paths.resource_dir() / "ui" / "dist"
    return bundled if bundled.is_dir() else None


def main() -> None:
    store.init()
    try:
        with _state_lock:
            _extra["schedule_minutes"] = int(store.get_setting("schedule_minutes", "0") or 0)
    except Exception:
        pass
    oui_service.ensure_loaded_async(on_done=_on_oui_ready)
    lan_discovery.dhcp_passive_start()
    threading.Thread(target=_stats_loop, name="netpulse-stats", daemon=True).start()
    threading.Thread(target=_ping_watch, name="netpulse-ping", daemon=True).start()
    threading.Thread(target=_scheduler, name="netpulse-sched", daemon=True).start()
    threading.Thread(target=_refresh_local_loop, name="netpulse-local", daemon=True).start()
    # A scan still starts from the UI on launch, same as the previous dashboard.
    import api_server

    port = int(os.environ.get("NETPULSE_PORT", "8765"))
    api_server.serve("127.0.0.1", port, _static_dir())


if __name__ == "__main__":
    main()

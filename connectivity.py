"""Ping, traceroute, DNS, NAT/STUN, IPv6, speed test, bufferbloat."""

from __future__ import annotations

import ipaddress
import platform
import socket
import statistics
import struct
import subprocess
import time
import urllib.request
from typing import Any

WIN = platform.system() == "Windows"
NOWIN = subprocess.CREATE_NO_WINDOW if WIN else 0


def ping_once(host: str, timeout_ms: int = 1000) -> dict[str, Any]:
    if WIN:
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), host]
    else:
        cmd = ["ping", "-c", "1", "-W", str(max(1, timeout_ms // 1000)), host]
    t0 = time.perf_counter()
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_ms / 1000 + 2, creationflags=NOWIN)
        ms = (time.perf_counter() - t0) * 1000
        ok = proc.returncode == 0
        import re
        m = re.search(r"time[=<]?\s*(\d+(?:\.\d+)?)\s*ms", proc.stdout, re.I)
        if m:
            ms = float(m.group(1))
        return {"ok": ok, "ms": round(ms, 1) if ok else None, "host": host}
    except Exception as exc:
        return {"ok": False, "ms": None, "host": host, "error": str(exc)}


def traceroute(host: str, max_hops: int = 15) -> dict[str, Any]:
    if WIN:
        cmd = ["tracert", "-d", "-h", str(max_hops), "-w", "800", host]
    else:
        cmd = ["traceroute", "-n", "-m", str(max_hops), "-w", "1", host]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=45, creationflags=NOWIN)
        hops = []
        for line in proc.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            hops.append(line)
        return {"ok": True, "host": host, "hops": hops, "raw": proc.stdout}
    except Exception as exc:
        return {"ok": False, "host": host, "error": str(exc), "hops": []}


def system_resolvers() -> list[str]:
    resolvers = []
    if WIN:
        try:
            proc = subprocess.run(["ipconfig", "/all"], capture_output=True, text=True, timeout=8, creationflags=NOWIN)
            for line in proc.stdout.splitlines():
                if "DNS Servers" in line or (resolvers and line.strip()[:1].isdigit()):
                    parts = line.split(":")
                    cand = parts[-1].strip() if parts else line.strip()
                    try:
                        ipaddress.ip_address(cand)
                        resolvers.append(cand)
                    except Exception:
                        pass
        except Exception:
            pass
    else:
        try:
            for line in open("/etc/resolv.conf", encoding="utf-8"):
                if line.startswith("nameserver"):
                    resolvers.append(line.split()[1])
        except Exception:
            pass
    return list(dict.fromkeys(resolvers))


def dns_checks(name: str = "dns.google") -> dict[str, Any]:
    resolvers = system_resolvers()
    t0 = time.perf_counter()
    addrs: list[str] = []
    try:
        infos = socket.getaddrinfo(name, 443, proto=socket.IPPROTO_TCP)
        addrs = list(dict.fromkeys(i[4][0] for i in infos))
    except Exception as exc:
        return {"ok": False, "error": str(exc), "resolvers": resolvers}
    latency = (time.perf_counter() - t0) * 1000
    expected = {"8.8.8.8", "8.8.4.4", "2001:4860:4860::8888", "2001:4860:4860::8844"}
    hijack = False
    if name == "dns.google" and addrs and not (set(addrs) & expected):
        hijack = True
    nx_ok = False
    try:
        socket.getaddrinfo(f"netpulse-nxdomain-{int(time.time())}.invalid", 80)
    except socket.gaierror:
        nx_ok = True
    except Exception:
        nx_ok = True
    if not nx_ok:
        hijack = True
    return {
        "ok": True,
        "query": name,
        "answers": addrs,
        "latency_ms": round(latency, 1),
        "resolvers": resolvers,
        "hijack_suspected": hijack,
        "nxdomain_correct": nx_ok,
    }


def public_ip() -> dict[str, Any]:
    urls = ("https://api.ipify.org", "https://ifconfig.me/ip", "https://icanhazip.com")
    for url in urls:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "NetPulse/1.0"})
            with urllib.request.urlopen(req, timeout=5) as resp:
                ip = resp.read(64).decode().strip()
            ipaddress.ip_address(ip)
            return {"ok": True, "ip": ip}
        except Exception:
            continue
    return {"ok": False, "ip": None}


def _stun_mapped(server: str = "stun.l.google.com", port: int = 19302, timeout: float = 2.5) -> str | None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        trans = b"NETPULSESTUNTEST1"
        # STUN binding request
        msg = struct.pack("!HHI", 0x0001, 0, 0x2112A442) + trans
        sock.sendto(msg, (socket.gethostbyname(server), port))
        data, _ = sock.recvfrom(1024)
        if len(data) < 20:
            return None
        pos = 20
        length = struct.unpack("!H", data[2:4])[0]
        end = 20 + length
        while pos + 4 <= end and pos + 4 <= len(data):
            atype, alen = struct.unpack("!HH", data[pos : pos + 4])
            val = data[pos + 4 : pos + 4 + alen]
            pos += 4 + alen
            pos += (4 - (alen % 4)) % 4
            if atype in (0x0001, 0x0020) and len(val) >= 8:
                xor = atype == 0x0020
                port_v = struct.unpack("!H", val[2:4])[0]
                ip_b = val[4:8]
                if xor:
                    port_v ^= 0x2112
                    magic = struct.pack("!I", 0x2112A442)
                    ip_b = bytes(a ^ b for a, b in zip(ip_b, magic))
                return socket.inet_ntoa(ip_b)
        return None
    except Exception:
        return None
    finally:
        sock.close()


def nat_report(local_ip: str, gateway: str) -> dict[str, Any]:
    pub = public_ip()
    mapped = _stun_mapped()
    public = pub.get("ip")
    cgnat = False
    double_nat = False
    nat_type = "unknown"
    try:
        loc = ipaddress.ip_address(local_ip)
        private = loc.is_private
        cgnat = loc in ipaddress.ip_network("100.64.0.0/10")
    except Exception:
        private = True
    if public and local_ip and public == local_ip:
        nat_type = "public / no NAT"
    elif cgnat:
        nat_type = "CGNAT (RFC 6598)"
    elif private and public:
        nat_type = "NAT (private LAN, distinct public IP)"
    if mapped and public and mapped != public:
        double_nat = True
        nat_type = "possible double NAT (STUN mapped ≠ public IP)"
    if mapped and local_ip and mapped == local_ip:
        nat_type = "open / no NAT (STUN matches local)"
    # extra: private hops in traceroute to public
    return {
        "local_ip": local_ip,
        "gateway": gateway,
        "public_ip": public,
        "stun_mapped": mapped,
        "cgnat": cgnat,
        "double_nat": double_nat,
        "nat_type": nat_type,
        "public_lookup_ok": bool(pub.get("ok")),
    }


def ipv6_report() -> dict[str, Any]:
    import psutil

    addrs = []
    global_ok = []
    for name, items in psutil.net_if_addrs().items():
        for a in items:
            if a.family != socket.AF_INET6:
                continue
            ip = a.address.split("%")[0]
            try:
                obj = ipaddress.IPv6Address(ip)
            except Exception:
                continue
            kind = "link-local" if obj.is_link_local else "ula" if obj.is_private else "global" if obj.is_global else "other"
            rec = {"iface": name, "ip": ip, "kind": kind}
            addrs.append(rec)
            if obj.is_global:
                global_ok.append(ip)
    exposed = False
    if global_ok:
        try:
            s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            s.settimeout(2)
            s.connect(("2001:4860:4860::8888", 53))
            exposed = True
            s.close()
        except Exception:
            exposed = False
    return {
        "addresses": addrs,
        "has_global": bool(global_ok),
        "outbound_v6": exposed,
        "note": "Global IPv6 plus outbound success means this host can reach the IPv6 internet; inbound exposure still depends on firewall/router.",
    }


def speed_and_bufferbloat(bytes_down: int = 4_000_000) -> dict[str, Any]:
    idle_samples = [ping_once("1.1.1.1")["ms"] for _ in range(5)]
    idle = [s for s in idle_samples if s is not None]
    idle_avg = statistics.mean(idle) if idle else None
    url = f"https://speed.cloudflare.com/__down?bytes={bytes_down}"
    t0 = time.perf_counter()
    loaded = []
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "NetPulse/1.0"})
        with urllib.request.urlopen(req, timeout=25) as resp:
            got = 0
            while got < bytes_down:
                chunk = resp.read(64_000)
                if not chunk:
                    break
                got += len(chunk)
                if len(loaded) < 8:
                    p = ping_once("1.1.1.1", timeout_ms=800)
                    if p["ms"] is not None:
                        loaded.append(p["ms"])
        elapsed = max(time.perf_counter() - t0, 0.001)
        down_mbps = (got * 8) / elapsed / 1_000_000
    except Exception as exc:
        return {"ok": False, "error": str(exc)}
    load_avg = statistics.mean(loaded) if loaded else None
    delta = (load_avg - idle_avg) if idle_avg is not None and load_avg is not None else None
    if delta is None:
        grade = "n/a"
    elif delta < 5:
        grade = "A (negligible)"
    elif delta < 20:
        grade = "B"
    elif delta < 50:
        grade = "C"
    else:
        grade = "F (severe bufferbloat)"
    return {
        "ok": True,
        "down_mbps": round(down_mbps, 2),
        "up_mbps": None,
        "idle_ms": round(idle_avg, 1) if idle_avg else None,
        "load_ms": round(load_avg, 1) if load_avg else None,
        "delta_ms": round(delta, 1) if delta is not None else None,
        "bufferbloat": grade,
        "bytes": got,
    }

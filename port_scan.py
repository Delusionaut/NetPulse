"""TCP connect port scanner for already-discovered LAN hosts."""

from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, Iterable

COMMON_PORTS: dict[int, str] = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    80: "HTTP",
    88: "Kerberos",
    110: "POP3",
    111: "RPC",
    123: "NTP",
    135: "MSRPC",
    139: "NetBIOS",
    143: "IMAP",
    161: "SNMP",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    500: "IKE",
    514: "Syslog",
    548: "AFP",
    554: "RTSP",
    587: "Submission",
    631: "IPP",
    636: "LDAPS",
    853: "DoT",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle",
    1723: "PPTP",
    1883: "MQTT",
    1900: "SSDP",
    2049: "NFS",
    2375: "Docker",
    2376: "Docker TLS",
    3000: "Dev HTTP",
    3306: "MySQL",
    3389: "RDP",
    3478: "STUN",
    5000: "UPnP / Flask",
    5353: "mDNS",
    5432: "PostgreSQL",
    5672: "AMQP",
    5900: "VNC",
    6379: "Redis",
    8000: "HTTP-alt",
    8080: "HTTP-proxy",
    8081: "HTTP-alt",
    8443: "HTTPS-alt",
    8888: "HTTP-alt",
    9000: "Dev",
    9090: "Prometheus",
    9100: "JetDirect",
    9443: "HTTPS-alt",
    11211: "Memcached",
    27017: "MongoDB",
    32400: "Plex",
}

EXTENDED_EXTRA: dict[int, str] = {
    69: "TFTP",
    79: "Finger",
    119: "NNTP",
    162: "SNMP trap",
    179: "BGP",
    311: "Apple Server",
    443: "HTTPS",
    515: "LPD",
    873: "rsync",
    1080: "SOCKS",
    1194: "OpenVPN",
    1293: "IPSec",
    1701: "L2TP",
    1812: "RADIUS",
    2082: "cPanel",
    2083: "cPanel SSL",
    2222: "SSH-alt",
    2323: "Telnet-alt",
    3128: "Squid",
    3689: "DAAP",
    3690: "SVN",
    4443: "HTTPS-alt",
    4500: "IPSec NAT-T",
    5060: "SIP",
    5061: "SIP TLS",
    5222: "XMPP",
    5357: "WSDAPI",
    5800: "VNC HTTP",
    5985: "WinRM",
    5986: "WinRM TLS",
    6667: "IRC",
    8008: "HTTP-alt",
    8010: "HTTP-alt",
    8088: "HTTP-alt",
    8096: "Jellyfin",
    8123: "Home Assistant",
    8200: "MiniDLNA",
    8291: "Winbox",
    8500: "Consul",
    8530: "WSUS",
    8883: "MQTT TLS",
    9200: "Elasticsearch",
    9418: "git",
    10000: "Webmin",
    25565: "Minecraft",
    49152: "Windows RPC",
}

PROFILES: dict[str, dict[int, str]] = {
    "common": COMMON_PORTS,
    "extended": {**COMMON_PORTS, **EXTENDED_EXTRA},
}


def service_name(port: int, profile: str = "common") -> str:
    table = PROFILES.get(profile) or COMMON_PORTS
    return table.get(port) or COMMON_PORTS.get(port) or EXTENDED_EXTRA.get(port) or "unknown"


def _probe(ip: str, port: int, timeout: float) -> dict | None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((ip, port))
        banner = ""
        try:
            sock.settimeout(0.25)
            if port in {21, 22, 25, 110, 143, 220, 587}:
                data = sock.recv(96)
                banner = data.decode("utf-8", errors="replace").strip().splitlines()[0][:80]
            elif port in {80, 8080, 8000, 8888, 3000}:
                sock.sendall(b"HEAD / HTTP/1.0\r\nHost: %s\r\n\r\n" % ip.encode("ascii", "ignore"))
                data = sock.recv(120)
                text = data.decode("utf-8", errors="replace")
                for line in text.splitlines():
                    if line.lower().startswith("server:"):
                        banner = line.split(":", 1)[1].strip()[:80]
                        break
        except Exception:
            banner = ""
        return {
            "port": port,
            "proto": "tcp",
            "service": service_name(port),
            "banner": banner,
        }
    except OSError:
        return None
    finally:
        try:
            sock.close()
        except Exception:
            pass


def scan_host(
    ip: str,
    profile: str = "common",
    timeout: float = 0.4,
    workers: int = 64,
    on_progress: Callable[[int, int], None] | None = None,
) -> list[dict]:
    ports = sorted((PROFILES.get(profile) or COMMON_PORTS).keys())
    total = len(ports)
    open_ports: list[dict] = []
    done = 0
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(_probe, ip, port, timeout): port for port in ports}
        for future in as_completed(futures):
            done += 1
            try:
                hit = future.result()
            except Exception:
                hit = None
            if hit:
                open_ports.append(hit)
            if on_progress and (done % 4 == 0 or done == total):
                on_progress(done, total)
    open_ports.sort(key=lambda item: item["port"])
    return open_ports


def scan_hosts(
    ips: Iterable[str],
    profile: str = "common",
    timeout: float = 0.4,
    on_host: Callable[[str, list[dict], int, int], None] | None = None,
    on_progress: Callable[[int, int], None] | None = None,
) -> dict[str, list[dict]]:
    hosts = list(ips)
    grand_total = max(1, len(hosts) * len(PROFILES.get(profile) or COMMON_PORTS))
    completed_units = 0
    results: dict[str, list[dict]] = {}
    for index, ip in enumerate(hosts, start=1):
        def host_progress(done: int, total: int, ip=ip, index=index) -> None:
            nonlocal completed_units
            completed_units = (index - 1) * total + done
            if on_progress:
                on_progress(completed_units, grand_total)

        opened = scan_host(ip, profile=profile, timeout=timeout, on_progress=host_progress)
        results[ip] = opened
        if on_host:
            on_host(ip, opened, index, len(hosts))
    return results

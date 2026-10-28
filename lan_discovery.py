"""mDNS/DNS-SD, SSDP/UPnP, NetBIOS, DHCP fingerprint, UPnP IGD, rogue DHCP."""

from __future__ import annotations

import ipaddress
import re
import socket
import struct
import threading
import time
import urllib.request
import xml.etree.ElementTree as ET
from typing import Any

SSDP_ADDR = ("239.255.255.250", 1900)
MDNS_ADDR = ("224.0.0.251", 5353)


def _udp(timeout: float = 1.5) -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.settimeout(timeout)
    return sock


def netbios_name(ip: str, timeout: float = 1.0) -> str:
    payload = bytes.fromhex("A200000100000000000020434B4141414141414141414141414141414141414141414141414141410000210001")
    sock = _udp(timeout)
    try:
        sock.sendto(payload, (ip, 137))
        data, _ = sock.recvfrom(512)
    except OSError:
        return ""
    finally:
        sock.close()
    if len(data) < 57:
        return ""
    names = []
    try:
        count = data[56]
        pos = 57
        for _ in range(count):
            raw = data[pos : pos + 15]
            flags = data[pos + 15]
            pos += 18
            label = raw.decode("ascii", errors="ignore").strip()
            if label and (flags & 0x80) == 0:
                names.append(label)
    except Exception:
        return ""
    return names[0] if names else ""


def _parse_mdns_labels(data: bytes, offset: int) -> tuple[str, int]:
    labels = []
    jumped = False
    end = offset
    seen = 0
    while offset < len(data) and seen < 20:
        length = data[offset]
        if length == 0:
            offset += 1
            if not jumped:
                end = offset
            break
        if length & 0xC0 == 0xC0:
            ptr = ((length & 0x3F) << 8) | data[offset + 1]
            if not jumped:
                end = offset + 2
            offset = ptr
            jumped = True
            seen += 1
            continue
        offset += 1
        labels.append(data[offset : offset + length].decode("utf-8", errors="replace"))
        offset += length
        seen += 1
    return ".".join(labels), end


def mdns_browse(timeout: float = 2.5) -> list[dict[str, Any]]:
    query = bytes.fromhex("000000000001000000000000")
    qname = b"\x09_services\x07_dns-sd\x04_udp\x05local\x00"
    query += qname + struct.pack("!HH", 12, 1)
    sock = _udp(timeout)
    results: list[dict[str, Any]] = []
    try:
        sock.bind(("", 5353))
    except OSError:
        try:
            sock.bind(("", 0))
        except OSError:
            sock.close()
            return results
    try:
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        sock.sendto(query, MDNS_ADDR)
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                data, addr = sock.recvfrom(2048)
            except OSError:
                break
            if len(data) < 12:
                continue
            name, _ = _parse_mdns_labels(data, 12) if data[4:6] != b"\x00\x00" else ("", 12)
            # Walk answers loosely: collect printable names
            text = re.findall(rb"[\x20-\x7e]{4,}", data)
            names = [t.decode("ascii", errors="ignore") for t in text if b"local" in t or t.startswith(b"_")]
            results.append(
                {
                    "ip": addr[0],
                    "names": list(dict.fromkeys(names))[:8],
                    "raw_hint": name,
                }
            )
    finally:
        sock.close()
    # Dedup by IP
    by_ip: dict[str, dict[str, Any]] = {}
    for item in results:
        cur = by_ip.setdefault(item["ip"], {"ip": item["ip"], "names": [], "services": []})
        for n in item["names"]:
            if n.startswith("_"):
                cur["services"].append(n)
            else:
                cur["names"].append(n)
        cur["names"] = list(dict.fromkeys(cur["names"]))
        cur["services"] = list(dict.fromkeys(cur["services"]))
    return list(by_ip.values())


def ssdp_search(timeout: float = 2.5) -> list[dict[str, Any]]:
    msg = (
        "M-SEARCH * HTTP/1.1\r\n"
        "HOST: 239.255.255.250:1900\r\n"
        "MAN: \"ssdp:discover\"\r\n"
        "MX: 2\r\n"
        "ST: ssdp:all\r\n\r\n"
    ).encode()
    sock = _udp(timeout)
    found: dict[str, dict[str, Any]] = {}
    try:
        sock.sendto(msg, SSDP_ADDR)
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                data, addr = sock.recvfrom(4096)
            except OSError:
                break
            text = data.decode("utf-8", errors="replace")
            headers = {}
            for line in text.split("\r\n"):
                if ":" in line:
                    k, v = line.split(":", 1)
                    headers[k.strip().lower()] = v.strip()
            loc = headers.get("location", "")
            usn = headers.get("usn", "")
            st = headers.get("st") or headers.get("nt", "")
            server = headers.get("server", "")
            rec = found.setdefault(addr[0], {"ip": addr[0], "location": loc, "server": server, "services": [], "usn": usn})
            if st and st not in rec["services"]:
                rec["services"].append(st)
            if loc and not rec.get("location"):
                rec["location"] = loc
            if loc:
                desc = _fetch_upnp_desc(loc)
                if desc:
                    rec.update(desc)
    finally:
        sock.close()
    return list(found.values())


def _fetch_upnp_desc(url: str) -> dict[str, Any]:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "NetPulse/1.0"})
        with urllib.request.urlopen(req, timeout=2) as resp:
            xml = resp.read(200_000)
        root = ET.fromstring(xml)
        ns = {"u": "urn:schemas-upnp-org:device-1-0"}
        def txt(path: str) -> str:
            node = root.find(path, ns) or root.find(path.replace("u:", ""))
            return (node.text or "").strip() if node is not None else ""
        return {
            "friendly_name": txt(".//u:friendlyName") or txt(".//friendlyName"),
            "manufacturer": txt(".//u:manufacturer") or txt(".//manufacturer"),
            "model": txt(".//u:modelName") or txt(".//modelName"),
            "model_number": txt(".//u:modelNumber") or txt(".//modelNumber"),
        }
    except Exception:
        return {}


def upnp_port_mappings(control_hints: list[str] | None = None, timeout: float = 2.0) -> list[dict[str, Any]]:
    """Try common IGD control URLs on the default gateway via SSDP first."""
    mappings: list[dict[str, Any]] = []
    devices = ssdp_search(timeout)
    urls = []
    for d in devices:
        loc = d.get("location") or ""
        if loc:
            urls.append(loc)
    for loc in urls[:8]:
        mappings.extend(_igd_mappings_from_desc(loc))
    return mappings


def _igd_mappings_from_desc(desc_url: str) -> list[dict[str, Any]]:
    try:
        req = urllib.request.Request(desc_url, headers={"User-Agent": "NetPulse/1.0"})
        with urllib.request.urlopen(req, timeout=2) as resp:
            xml = resp.read(300_000)
        text = xml.decode("utf-8", errors="replace")
        ctrl = re.findall(r"<controlURL>([^<]+)</controlURL>", text)
        types = re.findall(r"<serviceType>([^<]+)</serviceType>", text)
        pairs = list(zip(types, ctrl))
        wan = [p for p in pairs if "WANIPConnection" in p[0] or "WANPPPConnection" in p[0]]
        if not wan:
            return []
        service_type, control = wan[0]
        if not control.startswith("http"):
            from urllib.parse import urljoin, urlparse
            control = urljoin(desc_url, control)
        return _igd_list(control, service_type)
    except Exception:
        return []


def _igd_list(control_url: str, service_type: str) -> list[dict[str, Any]]:
    out = []
    for index in range(32):
        body = f"""<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
 <s:Body>
  <u:GetGenericPortMappingEntry xmlns:u="{service_type}">
   <NewPortMappingIndex>{index}</NewPortMappingIndex>
  </u:GetGenericPortMappingEntry>
 </s:Body>
</s:Envelope>"""
        req = urllib.request.Request(
            control_url,
            data=body.encode(),
            headers={
                "Content-Type": "text/xml; charset=utf-8",
                "SOAPAction": f'"{service_type}#GetGenericPortMappingEntry"',
                "User-Agent": "NetPulse/1.0",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=2) as resp:
                xml = resp.read().decode("utf-8", errors="replace")
        except Exception:
            break
        def tag(name: str) -> str:
            m = re.search(rf"<New{name}>([^<]*)</New{name}>", xml)
            return m.group(1) if m else ""
        if not tag("ExternalPort"):
            break
        out.append(
            {
                "external_port": tag("ExternalPort"),
                "protocol": tag("Protocol"),
                "internal_ip": tag("InternalClient"),
                "internal_port": tag("InternalPort"),
                "enabled": tag("Enabled"),
                "description": tag("PortMappingDescription"),
            }
        )
    return out


def dhcp_discover(timeout: float = 3.0) -> dict[str, Any]:
    """Broadcast DHCP discover; collect offers (rogue detection + option fingerprints)."""
    try:
        from scapy.all import BOOTP, DHCP, IP, UDP, Ether, conf, srp  # type: ignore
    except Exception:
        return {"ok": False, "reason": "Scapy/Npcap required for DHCP discover", "offers": []}
    try:
        conf.verb = 0
        xid = int(time.time()) & 0xFFFFFFFF
        pkt = (
            Ether(dst="ff:ff:ff:ff:ff:ff")
            / IP(src="0.0.0.0", dst="255.255.255.255")
            / UDP(sport=68, dport=67)
            / BOOTP(chaddr=b"\xde\xad\xbe\xef\x00\x01", xid=xid, flags=0x8000)
            / DHCP(options=[("message-type", "discover"), "end"])
        )
        answered, _ = srp(pkt, timeout=timeout, multi=True)
        offers = []
        servers = set()
        for _, recv in answered:
            bootp = recv.getlayer(BOOTP)
            dhcp = recv.getlayer(DHCP)
            opts = {}
            if dhcp:
                for opt in dhcp.options:
                    if isinstance(opt, tuple) and len(opt) >= 2:
                        opts[str(opt[0])] = str(opt[1])
            server = opts.get("server_id") or (bootp.siaddr if bootp else "")
            servers.add(str(server))
            offers.append(
                {
                    "server": str(server),
                    "yiaddr": str(getattr(bootp, "yiaddr", "")),
                    "vendor_class": opts.get("vendor_class_id") or opts.get("vendor_class"),
                    "lease": opts.get("lease_time"),
                    "router": opts.get("router"),
                    "name_server": opts.get("name_server"),
                    "options": opts,
                }
            )
        rogue = len(servers) > 1
        return {"ok": True, "offers": offers, "servers": list(servers), "rogue": rogue}
    except Exception as exc:
        return {"ok": False, "reason": str(exc), "offers": []}


_dhcp_seen: list[dict[str, Any]] = []
_dhcp_lock = threading.Lock()


def dhcp_passive_start() -> str:
    try:
        from scapy.all import DHCP, sniff  # type: ignore
    except Exception:
        return "scapy-missing"

    def _cb(pkt) -> None:
        try:
            dhcp = pkt.getlayer(DHCP)
            if not dhcp:
                return
            opts = {str(o[0]): str(o[1]) for o in dhcp.options if isinstance(o, tuple) and len(o) >= 2}
            rec = {
                "ts": time.time(),
                "src": pkt.sprintf("%IP.src%") if pkt.haslayer("IP") else "",
                "message": opts.get("message-type"),
                "vendor_class": opts.get("vendor_class_id") or opts.get("vendor_class"),
                "hostname": opts.get("hostname"),
                "param_req": opts.get("param_req_list"),
                "client_id": opts.get("client_id"),
            }
            with _dhcp_lock:
                _dhcp_seen.append(rec)
                del _dhcp_seen[:-80]
        except Exception:
            pass

    t = threading.Thread(
        target=lambda: sniff(filter="udp and (port 67 or port 68)", prn=_cb, store=False, timeout=None),
        name="netpulse-dhcp",
        daemon=True,
    )
    t.start()
    return "started"


def dhcp_fingerprints() -> list[dict[str, Any]]:
    with _dhcp_lock:
        return list(_dhcp_seen)

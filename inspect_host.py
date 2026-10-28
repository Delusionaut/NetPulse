"""HTTP titles, favicon hashes, TLS certs, banners, risk score, WOL, default-cred (gated)."""

from __future__ import annotations

import hashlib
import html
import re
import socket
import ssl
import struct
import time
import urllib.request
from datetime import datetime, timezone
from typing import Any

RISK_PORTS = {
    21: ("high", "FTP often uses cleartext passwords"),
    23: ("critical", "Telnet is unencrypted"),
    135: ("high", "MSRPC exposed on LAN"),
    139: ("medium", "NetBIOS session"),
    445: ("high", "SMB file sharing"),
    1433: ("high", "MSSQL"),
    3306: ("high", "MySQL"),
    3389: ("high", "RDP"),
    5432: ("high", "PostgreSQL"),
    5900: ("high", "VNC"),
    6379: ("critical", "Redis often unauthenticated"),
    9200: ("high", "Elasticsearch"),
    27017: ("high", "MongoDB"),
    2375: ("critical", "Docker API without TLS"),
    11211: ("high", "Memcached"),
}


def http_probe(ip: str, port: int = 80, tls: bool = False, timeout: float = 2.5) -> dict[str, Any]:
    scheme = "https" if tls else "http"
    url = f"{scheme}://{ip}:{port}/"
    ctx = ssl._create_unverified_context() if tls else None
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "NetPulse/1.0"})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            raw = resp.read(80_000)
            headers = {k.lower(): v for k, v in resp.headers.items()}
        text = raw.decode("utf-8", errors="replace")
        title_m = re.search(r"<title[^>]*>(.*?)</title>", text, re.I | re.S)
        title = html.unescape(re.sub(r"\s+", " ", title_m.group(1)).strip()) if title_m else ""
        fav = ""
        fav_hash = ""
        icon = re.search(r'<link[^>]+rel=["\'][^"\']*icon[^"\']*["\'][^>]*>', text, re.I)
        href = None
        if icon:
            hm = re.search(r'href=["\']([^"\']+)["\']', icon.group(0), re.I)
            href = hm.group(1) if hm else None
        if not href:
            href = "/favicon.ico"
        if href.startswith("//"):
            href = scheme + ":" + href
        elif href.startswith("/"):
            href = f"{scheme}://{ip}:{port}{href}"
        elif not href.startswith("http"):
            href = f"{scheme}://{ip}:{port}/{href.lstrip('/')}"
        try:
            ireq = urllib.request.Request(href, headers={"User-Agent": "NetPulse/1.0"})
            with urllib.request.urlopen(ireq, timeout=2, context=ctx) as iresp:
                blob = iresp.read(64_000)
            fav_hash = hashlib.md5(blob).hexdigest()
            fav = href
        except Exception:
            pass
        return {
            "ok": True,
            "url": url,
            "status": getattr(resp, "status", None),
            "server": headers.get("server", ""),
            "title": title,
            "favicon": fav,
            "favicon_md5": fav_hash,
        }
    except Exception as exc:
        return {"ok": False, "url": url, "error": str(exc)}


def tls_probe(ip: str, port: int = 443, timeout: float = 2.5) -> dict[str, Any]:
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((ip, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=ip) as ssock:
                cert = ssock.getpeercert()
                der = ssock.getpeercert(binary_form=True) or b""
                cipher = ssock.cipher()
        # unverified getpeercert often empty; parse DER via ssl._ssl if needed
        info = _parse_der_cert(der) if der else {}
        subject = _name_from_cert(cert, "subject") if cert else info.get("cn")
        issuer = _name_from_cert(cert, "issuer") if cert else info.get("issuer")
        not_after = cert.get("notAfter") if cert else info.get("not_after")
        expiry = None
        if not_after:
            try:
                expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc).isoformat()
            except Exception:
                expiry = str(not_after)
        self_signed = bool(subject and issuer and subject == issuer)
        return {
            "ok": True,
            "cn": subject or info.get("cn") or "",
            "issuer": issuer or info.get("issuer") or "",
            "expiry": expiry,
            "self_signed": self_signed or info.get("self_signed", False),
            "cipher": cipher[0] if cipher else "",
            "fp_sha256": hashlib.sha256(der).hexdigest() if der else "",
        }
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def _name_from_cert(cert: dict, field: str) -> str:
    try:
        tuples = cert.get(field) or ()
        for rdn in tuples:
            for k, v in rdn:
                if k == "commonName":
                    return v
        for rdn in tuples:
            for k, v in rdn:
                if k == "organizationName":
                    return v
    except Exception:
        pass
    return ""


def _parse_der_cert(der: bytes) -> dict[str, Any]:
    # Best-effort CN extraction without extra deps
    try:
        text = der.decode("latin-1", errors="ignore")
        cns = re.findall(r"[\x00]CN[\x00]?[=\s]*([\x20-\x7e]{2,64})", text)
        return {"cn": cns[0] if cns else "", "issuer": cns[1] if len(cns) > 1 else "", "self_signed": len(set(cns[:2])) == 1 and bool(cns)}
    except Exception:
        return {}


def enrich_from_ports(ip: str, ports: list[dict[str, Any]]) -> dict[str, Any]:
    http = None
    tls = None
    numbers = {int(p["port"]) for p in ports}
    if 443 in numbers:
        tls = tls_probe(ip, 443)
        http = http_probe(ip, 443, tls=True)
    elif 8443 in numbers:
        tls = tls_probe(ip, 8443)
        http = http_probe(ip, 8443, tls=True)
    if http is None or not http.get("ok"):
        for p in (80, 8080, 8000, 8888, 3000, 5000):
            if p in numbers:
                http = http_probe(ip, p, tls=False)
                if http.get("ok"):
                    break
    return {"http": http, "tls": tls}


def risk_score(ports: list[dict[str, Any]]) -> dict[str, Any]:
    score = 0
    findings = []
    for p in ports:
        port = int(p.get("port") or 0)
        sev, why = RISK_PORTS.get(port, (None, None))
        if sev == "critical":
            score += 35
        elif sev == "high":
            score += 20
        elif sev == "medium":
            score += 10
        if sev:
            findings.append({"port": port, "severity": sev, "reason": why, "service": p.get("service")})
    score = min(100, score)
    if score >= 70:
        grade = "critical"
    elif score >= 40:
        grade = "high"
    elif score >= 15:
        grade = "medium"
    else:
        grade = "low"
    return {"score": score, "grade": grade, "findings": findings}


def wake_on_lan(mac: str, broadcast: str = "255.255.255.255", port: int = 9) -> dict[str, Any]:
    hx = "".join(c for c in mac.upper() if c in "0123456789ABCDEF")
    if len(hx) != 12:
        return {"ok": False, "reason": "MAC must be 12 hex digits"}
    payload = bytes.fromhex("FF" * 6 + hx * 16)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.sendto(payload, (broadcast, port))
        return {"ok": True, "mac": ":".join(hx[i : i + 2] for i in range(0, 12, 2))}
    except Exception as exc:
        return {"ok": False, "reason": str(exc)}
    finally:
        sock.close()


DEFAULT_PAIRS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", ""),
    ("root", "root"),
    ("user", "user"),
    ("guest", "guest"),
]


def check_default_http(ip: str, port: int, pairs: list[tuple[str, str]] | None = None, timeout: float = 2.0) -> dict[str, Any]:
    """User-gated HTTP basic-auth probe. Does not brute-force beyond a tiny well-known list."""
    import base64

    pairs = pairs or DEFAULT_PAIRS
    url = f"http://{ip}:{port}/"
    hits = []
    unprotected = False
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "NetPulse/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status < 400:
                unprotected = True
    except Exception:
        pass
    for user, password in pairs:
        token = base64.b64encode(f"{user}:{password}".encode()).decode()
        req = urllib.request.Request(url, headers={"Authorization": f"Basic {token}", "User-Agent": "NetPulse/1.0"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                if resp.status < 400:
                    hits.append({"user": user, "password": password, "status": resp.status})
                    break
        except Exception:
            continue
    return {"ok": True, "unprotected": unprotected, "default_hits": hits}

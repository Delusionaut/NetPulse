"""
Public OUI lookup and device-nature inference.

Sources (downloaded and cached locally):
  - IEEE MA-L  https://standards-oui.ieee.org/oui/oui.txt
  - IEEE MA-M  https://standards-oui.ieee.org/oui28/mam.txt
  - IEEE MA-S  https://standards-oui.ieee.org/oui36/oui36.txt
  - Wireshark manuf  https://www.wireshark.org/download/automated/data/manuf

Lookups never block the UI thread. Refresh runs on a background thread.
"""

from __future__ import annotations

import json
import re
import threading
import time
import urllib.request
from typing import Any, Callable

import paths
from vendor_oui import lookup_vendor as bundled_lookup

CACHE_DIR = paths.cache_dir()
CACHE_FILE = CACHE_DIR / "oui_index.json"
CACHE_MAX_AGE_S = 7 * 24 * 3600

SOURCES = (
    ("IEEE MA-L", "https://standards-oui.ieee.org/oui/oui.txt"),
    ("IEEE MA-M", "https://standards-oui.ieee.org/oui28/mam.txt"),
    ("IEEE MA-S", "https://standards-oui.ieee.org/oui36/oui36.txt"),
    ("Wireshark manuf", "https://www.wireshark.org/download/automated/data/manuf"),
)

_IEEE_HEX = re.compile(
    r"^([0-9A-Fa-f]{2}[-:][0-9A-Fa-f]{2}[-:][0-9A-Fa-f]{2}(?:[-:][0-9A-Fa-f]{2}){0,3})\s+\(hex\)\s+(.+)$"
)
_MANUF = re.compile(
    r"^([0-9A-Fa-f:.\-]+)(?:/(\d+))?\s+(\S+)(?:\s+#\s*(.+))?$"
)

_lock = threading.Lock()
_index: dict[str, dict[str, str]] = {}
_status: dict[str, Any] = {
    "ready": False,
    "entries": 0,
    "source": "bundled fallback",
    "updated_at": None,
    "refreshing": False,
    "error": None,
    "feeds": [],
}

_UA = "NetPulse/1.0 (local network analyzer; OUI cache)"


def _mac_hex(mac: str) -> str:
    return "".join(c for c in mac.upper() if c in "0123456789ABCDEF")


def _is_locally_administered(mac: str) -> bool:
    hx = _mac_hex(mac)
    if len(hx) < 2:
        return False
    return bool(int(hx[0:2], 16) & 0x02)


def _is_multicast(mac: str) -> bool:
    hx = _mac_hex(mac)
    if len(hx) < 2:
        return False
    return bool(int(hx[0:2], 16) & 0x01)


def _store(prefix_hex: str, vendor: str, source: str) -> None:
    vendor = vendor.strip().strip('"')
    if not vendor or vendor.upper() in {"UNKNOWN", "<UNKNOWN>"}:
        return
    key = prefix_hex.upper()
    existing = _index.get(key)
    if existing and existing.get("source", "").startswith("IEEE") and source.startswith("Wireshark"):
        return
    _index[key] = {"vendor": vendor, "source": source}


def _ingest_ieee(text: str, source: str) -> int:
    added = 0
    for line in text.splitlines():
        match = _IEEE_HEX.match(line.strip())
        if not match:
            continue
        prefix = _mac_hex(match.group(1))
        if len(prefix) not in (6, 7, 9):
            if len(prefix) >= 6:
                prefix = prefix[:6]
            else:
                continue
        _store(prefix, match.group(2), source)
        added += 1
    return added


def _ingest_manuf(text: str, source: str) -> int:
    added = 0
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        match = _MANUF.match(line)
        if not match:
            continue
        prefix = _mac_hex(match.group(1))
        bits = int(match.group(2) or 24)
        need = max(6, (bits + 3) // 4)
        prefix = prefix[:need]
        if len(prefix) < 6:
            continue
        short = match.group(3)
        comment = (match.group(4) or "").strip()
        vendor = comment or short.replace("_", " ")
        _store(prefix, vendor, source)
        added += 1
    return added


def _download(url: str, timeout: int = 45) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": _UA})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = resp.read()
    return data.decode("utf-8", errors="replace")


def _persist() -> None:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    payload = {
        "updated_at": time.time(),
        "entries": _index,
        "feeds": list(_status.get("feeds") or []),
    }
    tmp = CACHE_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(payload), encoding="utf-8")
    tmp.replace(CACHE_FILE)


def _load_cache() -> bool:
    if not CACHE_FILE.exists():
        return False
    try:
        payload = json.loads(CACHE_FILE.read_text(encoding="utf-8"))
        entries = payload.get("entries") or {}
        if not isinstance(entries, dict) or not entries:
            return False
        _index.clear()
        _index.update(entries)
        age = time.time() - float(payload.get("updated_at") or 0)
        _status.update(
            {
                "ready": True,
                "entries": len(_index),
                "source": "IEEE + Wireshark (cached)",
                "updated_at": payload.get("updated_at"),
                "feeds": payload.get("feeds") or [],
                "error": None,
                "stale": age > CACHE_MAX_AGE_S,
            }
        )
        return True
    except Exception:
        return False


def refresh_from_public(force: bool = False, on_progress: Callable[[str], None] | None = None) -> dict[str, Any]:
    global _index
    with _lock:
        if _status.get("refreshing"):
            return dict(_status)
        _status["refreshing"] = True
        _status["error"] = None

    try:
        if not force and _load_cache() and not _status.get("stale"):
            return status()

        feeds: list[dict[str, Any]] = []
        with _lock:
            _index = {}

        for name, url in SOURCES:
            if on_progress:
                on_progress(f"Downloading {name}")
            try:
                body = _download(url)
                if "IEEE" in name:
                    count = _ingest_ieee(body, name)
                else:
                    count = _ingest_manuf(body, name)
                feeds.append({"name": name, "url": url, "ok": True, "records": count})
            except Exception as exc:
                feeds.append({"name": name, "url": url, "ok": False, "error": str(exc)})

        if on_progress:
            on_progress("Writing local OUI cache")
        with _lock:
            _status["feeds"] = feeds
            _status["entries"] = len(_index)
            _status["ready"] = len(_index) > 0
            _status["source"] = "IEEE + Wireshark" if _index else "bundled fallback"
            _status["updated_at"] = time.time()
            _status["stale"] = False
            if not _index:
                _status["error"] = "Public OUI feeds were unreachable; using bundled prefixes."
            try:
                _persist()
            except Exception as exc:
                _status["error"] = f"Cache write failed: {exc}"
        return status()
    finally:
        with _lock:
            _status["refreshing"] = False


def ensure_loaded_async(on_done: Callable[[dict[str, Any]], None] | None = None) -> None:
    def worker() -> None:
        result = refresh_from_public(force=False)
        if on_done:
            on_done(result)

    threading.Thread(target=worker, name="netpulse-oui", daemon=True).start()


def lookup(mac: str) -> dict[str, str]:
    hx = _mac_hex(mac)
    if len(hx) < 6:
        bundled = bundled_lookup(mac)
        return {
            "vendor": bundled,
            "source": "bundled" if bundled != "Unknown" else "none",
            "prefix": "",
        }
    with _lock:
        for length in (9, 7, 6):
            key = hx[:length]
            hit = _index.get(key)
            if hit:
                return {
                    "vendor": hit["vendor"],
                    "source": hit["source"],
                    "prefix": ":".join(key[i : i + 2] for i in range(0, len(key), 2)),
                }
    bundled = bundled_lookup(mac)
    return {
        "vendor": bundled,
        "source": "bundled fallback" if bundled != "Unknown" else "none",
        "prefix": ":".join(hx[i : i + 2] for i in range(0, 6, 2)),
    }


_NATURE_RULES: list[tuple[str, tuple[str, ...]]] = [
    (
        "Virtual machine / hypervisor NIC",
        ("vmware", "virtualbox", "hyper-v", "microsoft hyper", "parallels", "qemu", "xen", "virtio", "innotek"),
    ),
    (
        "Network infrastructure (router, switch, AP, firewall)",
        (
            "cisco",
            "juniper",
            "aruba",
            "ubiquiti",
            "mikrotik",
            "fortinet",
            "palo alto",
            "tp-link",
            "tplink",
            "netgear",
            "d-link",
            "dlink",
            "asus",
            "asustek",
            "linksys",
            "belkin",
            "zyxel",
            "huawei technologies",
            "meraki",
            "ruckus",
            "extreme networks",
            "brocade",
            "aruba",
            "cambium",
            "eero",
            "orbi",
        ),
    ),
    (
        "Single-board computer / maker hardware",
        ("raspberry pi", "espressif", "esp32", "arduino", "beagle", "nvidia", "odroid", "pine64"),
    ),
    (
        "Phone, tablet, or wearable",
        ("oneplus", "xiaomi", "redmi", "oppo", "vivo", "realme", "motorola", "lg electronics", "htc", "nothing tech"),
    ),
    (
        "Apple computer, phone, tablet, or accessory",
        ("apple",),
    ),
    (
        "Samsung phone, TV, or appliance",
        ("samsung",),
    ),
    (
        "Google / Nest / Chromecast device",
        ("google", "nest labs"),
    ),
    (
        "PC, laptop, or NIC (Intel / Realtek / Broadcom)",
        (
            "intel",
            "realtek",
            "broadcom",
            "qualcomm",
            "atheros",
            "marvell",
            "killer",
            "dell",
            "hewlett packard",
            "hp inc",
            "lenovo",
            "acer",
            "asus",
            "gigabyte",
            "micro-star",
            "msi ",
            "hon hai",
            "foxconn",
            "liteon",
            "azurewave",
        ),
    ),
    (
        "Printer or imaging device",
        ("hewlett-packard", "canon", "epson", "brother", "xerox", "ricoh", "kyocera", "lexmark"),
    ),
    (
        "Smart TV, streaming stick, or set-top",
        ("roku", "vizio", "lg electronics", "sony", "tcl", "hisense", "amazon technologies", "fire tv", "skyworth"),
    ),
    (
        "Game console",
        ("nintendo", "sony interactive", "microsoft", "xbox"),
    ),
    (
        "IoT, camera, or smart-home node",
        (
            "tuya",
            "wyze",
            "ring",
            "blink",
            "hikvision",
            "dahua",
            "amcrest",
            "philips lighting",
            "signify",
            "hue",
            "sonos",
            "ecobee",
            "schlage",
            "yale",
            "aqara",
            "shelly",
            "tasmota",
            "espressif",
        ),
    ),
]


def infer_nature(
    *,
    mac: str,
    vendor: str,
    hostname: str = "",
    role: str = "",
    is_self: bool = False,
    is_gateway: bool = False,
) -> dict[str, str]:
    vendor_l = (vendor or "").lower()
    host_l = (hostname or "").lower()
    hay = f"{vendor_l} {host_l}"

    if is_self:
        return {
            "nature": "This workstation",
            "confidence": "high",
            "note": "Address matches the adapter NetPulse is using.",
        }
    if is_gateway or role == "Gateway":
        return {
            "nature": "Default gateway / router",
            "confidence": "high",
            "note": "This IP is the current IPv4 default route.",
        }
    if _is_multicast(mac):
        return {
            "nature": "Multicast / group address",
            "confidence": "high",
            "note": "I/G bit is set on the MAC.",
        }
    if _is_locally_administered(mac):
        return {
            "nature": "Privacy MAC (phone, tablet, or randomized NIC)",
            "confidence": "medium",
            "note": "Locally administered bit is set; OUI vendor is often hidden. Common on iOS, Android, and Windows random hardware addresses.",
        }

    for nature, needles in _NATURE_RULES:
        if any(n in hay for n in needles):
            conf = "high" if any(n in vendor_l for n in needles) else "medium"
            return {
                "nature": nature,
                "confidence": conf,
                "note": f"Matched public OUI vendor “{vendor}”.",
            }

    if vendor and vendor != "Unknown":
        return {
            "nature": f"Client hardware from {vendor}",
            "confidence": "medium",
            "note": "Vendor comes from a public IEEE/Wireshark OUI record; exact product class is not in the registry.",
        }
    return {
        "nature": "Unknown endpoint",
        "confidence": "low",
        "note": "No OUI assignment matched this MAC.",
    }


def identify(mac: str, hostname: str = "", role: str = "", is_self: bool = False, is_gateway: bool = False) -> dict[str, str]:
    hit = lookup(mac)
    nature = infer_nature(
        mac=mac,
        vendor=hit["vendor"],
        hostname=hostname,
        role=role,
        is_self=is_self,
        is_gateway=is_gateway,
    )
    return {**hit, **nature}


def status() -> dict[str, Any]:
    with _lock:
        payload = dict(_status)
    updated = payload.get("updated_at")
    if isinstance(updated, (int, float)) and updated:
        payload["updated_label"] = time.strftime("%Y-%m-%d %H:%M", time.localtime(updated))
        payload["age_hours"] = round((time.time() - updated) / 3600, 1)
    else:
        payload["updated_label"] = "never"
        payload["age_hours"] = None
    return payload

"""Pure request checks for the localhost API. No network I/O."""

from __future__ import annotations

import ipaddress
import re
from pathlib import Path
from typing import Any

_HOST_RE = re.compile(r"^[A-Za-z0-9.\-]{1,253}$")
_COMMUNITY_RE = re.compile(r"^[A-Za-z0-9_.:@\-]{1,64}$")
_PROFILES = {"common", "extended"}


def capped_network(local_ip: str, netmask: str) -> ipaddress.IPv4Network:
    """Scan prefix is never wider than /24."""
    network = ipaddress.IPv4Network(f"{local_ip}/{netmask}", strict=False)
    if network.prefixlen < 24:
        network = ipaddress.IPv4Network(f"{local_ip}/24", strict=False)
    return network


def safe_join(root: Path, *parts: str) -> Path:
    """Join path parts and refuse anything that leaves root."""
    base = root.resolve()
    candidate = base.joinpath(*parts).resolve()
    if candidate != base and base not in candidate.parents:
        raise ValueError("path escapes root")
    return candidate


def parse_host(value: Any, default: str = "1.1.1.1") -> str:
    host = default if value is None or value == "" else str(value).strip()
    if not _HOST_RE.match(host) or ".." in host:
        raise ValueError("invalid host")
    return host


def parse_ipv4(value: Any) -> str:
    try:
        return str(ipaddress.IPv4Address(str(value).strip()))
    except Exception as exc:
        raise ValueError("invalid IPv4 address") from exc


def parse_mac(value: Any) -> str:
    raw = str(value or "")
    hex_chars = "".join(c for c in raw.upper() if c in "0123456789ABCDEF")
    if len(hex_chars) != 12:
        raise ValueError("MAC must be 12 hex digits")
    return ":".join(hex_chars[i : i + 2] for i in range(0, 12, 2))


def parse_profile(value: Any) -> str:
    profile = str(value or "common").strip().lower()
    if profile not in _PROFILES:
        raise ValueError("profile must be common or extended")
    return profile


def parse_schedule_minutes(value: Any) -> int:
    try:
        minutes = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError("minutes must be an integer") from exc
    if minutes < 0 or minutes > 24 * 60:
        raise ValueError("minutes must be between 0 and 1440")
    return minutes


def parse_webhook(value: Any) -> str:
    url = str(value or "").strip()
    if not url:
        return ""
    if not url.startswith(("http://", "https://")) or len(url) > 500:
        raise ValueError("webhook must be an http(s) URL")
    if any(c in url for c in (" ", "\n", "\r")):
        raise ValueError("webhook must be an http(s) URL")
    return url


def parse_community(value: Any) -> str:
    community = "public" if value is None or value == "" else str(value).strip()
    if not _COMMUNITY_RE.match(community):
        raise ValueError("invalid SNMP community")
    return community


def parse_confirm(value: Any) -> bool:
    if value is True:
        return True
    raise ValueError("confirm must be true")


def parse_tags(value: Any) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise ValueError("tags must be a list")
    tags: list[str] = []
    for item in value[:12]:
        text = str(item).strip()
        if not text or len(text) > 32:
            raise ValueError("each tag must be 1–32 characters")
        tags.append(text)
    return tags


def parse_notes(value: Any) -> str:
    notes = str(value or "")
    if len(notes) > 500:
        raise ValueError("notes must be 500 characters or fewer")
    return notes


def parse_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    raise ValueError("expected a boolean")


def parse_alert_id(value: Any) -> int:
    try:
        alert_id = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError("alert id must be an integer") from exc
    if alert_id < 1:
        raise ValueError("alert id must be an integer")
    return alert_id

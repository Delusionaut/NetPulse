"""Unit tests for path joins and API validation."""

import ipaddress
from pathlib import Path

import pytest

import api_validate
import paths


def test_capped_network_limits_wide_prefixes() -> None:
    wide = api_validate.capped_network("10.1.2.3", "255.0.0.0")
    assert wide.prefixlen == 24
    assert wide == ipaddress.IPv4Network("10.1.2.0/24")
    small = api_validate.capped_network("192.168.1.10", "255.255.255.240")
    assert small.prefixlen == 28


def test_safe_join_stays_inside_root(tmp_path: Path) -> None:
    root = tmp_path / "ui"
    root.mkdir()
    target = api_validate.safe_join(root, "assets", "icon.png")
    assert target == (root / "assets" / "icon.png").resolve()
    with pytest.raises(ValueError):
        api_validate.safe_join(root, "..", "secret.txt")


def test_cache_dir_is_under_writable(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(paths, "writable_dir", lambda: tmp_path)
    cache = paths.cache_dir()
    assert cache == tmp_path / "cache"
    assert cache.is_dir()


def test_webhook_and_schedule_validation() -> None:
    assert api_validate.parse_webhook("") == ""
    assert api_validate.parse_webhook("https://example.test/hook") == "https://example.test/hook"
    with pytest.raises(ValueError):
        api_validate.parse_webhook("ftp://example.test/hook")
    assert api_validate.parse_schedule_minutes("15") == 15
    with pytest.raises(ValueError):
        api_validate.parse_schedule_minutes(-1)
    with pytest.raises(ValueError):
        api_validate.parse_schedule_minutes(2000)


def test_host_mac_confirm_and_profile() -> None:
    assert api_validate.parse_host("1.1.1.1") == "1.1.1.1"
    assert api_validate.parse_host(None) == "1.1.1.1"
    with pytest.raises(ValueError):
        api_validate.parse_host("1.1.1.1;whoami")
    assert api_validate.parse_mac("aa-bb-cc-dd-ee-ff") == "AA:BB:CC:DD:EE:FF"
    with pytest.raises(ValueError):
        api_validate.parse_confirm(False)
    with pytest.raises(ValueError):
        api_validate.parse_confirm("true")
    assert api_validate.parse_confirm(True) is True
    assert api_validate.parse_profile("extended") == "extended"
    with pytest.raises(ValueError):
        api_validate.parse_profile("all")
    assert api_validate.parse_tags(["lan", "iot"]) == ["lan", "iot"]
    with pytest.raises(ValueError):
        api_validate.parse_ipv4("not-an-ip")

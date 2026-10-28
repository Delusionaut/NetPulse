"""API routing rejects bad input before any scan work."""

import api_server


def test_unknown_route() -> None:
    status, body = api_server.dispatch("GET", "/api/nope", {}, {})
    assert status == 404
    assert body["ok"] is False


def test_creds_require_real_confirm() -> None:
    status, body = api_server.dispatch("POST", "/api/creds", {}, {"ip": "192.168.1.1", "confirm": "true"})
    assert status == 400
    assert "confirm" in body["reason"]


def test_port_profile_rejected() -> None:
    status, body = api_server.dispatch("POST", "/api/ports", {}, {"profile": "aggressive"})
    assert status == 400
    assert body["ok"] is False

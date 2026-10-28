"""Localhost-only JSON API in front of the NetPulse engine."""

from __future__ import annotations

import json
import mimetypes
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable
from urllib.parse import parse_qs, urlparse

import api_validate

Handler = Callable[[dict[str, Any]], Any]

_MIME = {
    ".html": "text/html; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".svg": "image/svg+xml",
    ".png": "image/png",
    ".ico": "image/x-icon",
    ".json": "application/json; charset=utf-8",
    ".woff2": "font/woff2",
}


def _engine():
    import app

    return app


def dispatch(method: str, path: str, query: dict[str, list[str]], body: dict[str, Any]) -> tuple[int, Any]:
    """Route one API call. Validation failures become HTTP 400."""
    try:
        return _dispatch(method, path, query, body)
    except ValueError as exc:
        return 400, {"ok": False, "reason": str(exc)}


def _dispatch(method: str, path: str, query: dict[str, list[str]], body: dict[str, Any]) -> tuple[int, Any]:
    eng = _engine()
    if method == "GET" and path == "/api/health":
        return 200, {"ok": True, "name": "NetPulse"}
    if method == "GET" and path == "/api/snapshot":
        return 200, eng.get_snapshot()
    if method == "POST" and path == "/api/scan":
        return 200, eng.start_scan()
    if method == "GET" and path == "/api/oui":
        return 200, eng.get_oui_status()
    if method == "POST" and path == "/api/oui/refresh":
        return 200, eng.refresh_oui_database()
    if method == "GET" and path == "/api/alerts":
        return 200, eng.get_alerts()
    if method == "POST" and path == "/api/alerts/ack":
        return 200, eng.ack_alert(api_validate.parse_alert_id(body.get("id")))
    if method == "POST" and path == "/api/device/meta":
        mac = api_validate.parse_mac(body.get("mac"))
        return 200, eng.set_device_meta(
            mac,
            api_validate.parse_bool(body.get("trusted")),
            api_validate.parse_bool(body.get("owned")),
            api_validate.parse_tags(body.get("tags")),
            api_validate.parse_notes(body.get("notes")),
        )
    if method == "POST" and path == "/api/wol":
        return 200, eng.wake_host(api_validate.parse_mac(body.get("mac")))
    if method == "POST" and path == "/api/traceroute":
        return 200, eng.run_traceroute(api_validate.parse_host(body.get("host"), "1.1.1.1"))
    if method == "POST" and path == "/api/dns":
        return 200, eng.run_dns_check()
    if method == "POST" and path == "/api/nat":
        return 200, eng.run_nat_check()
    if method == "POST" and path == "/api/speed":
        return 200, eng.run_speed_test()
    if method == "POST" and path == "/api/wifi":
        return 200, eng.run_wifi_scan()
    if method == "POST" and path == "/api/local":
        return 200, eng.run_local_report()
    if method == "POST" and path == "/api/upnp":
        return 200, eng.run_upnp_maps()
    if method == "POST" and path == "/api/dhcp":
        return 200, eng.run_dhcp_probe()
    if method == "POST" and path == "/api/snmp":
        host = str(body.get("host") or "").strip()
        if host:
            host = api_validate.parse_host(host, "")
        return 200, eng.run_snmp(host, api_validate.parse_community(body.get("community")))
    if method == "POST" and path == "/api/creds":
        return 200, eng.run_default_creds(
            api_validate.parse_ipv4(body.get("ip")),
            api_validate.parse_confirm(body.get("confirm")),
        )
    if method == "POST" and path == "/api/webhook":
        return 200, eng.set_webhook(api_validate.parse_webhook(body.get("url")))
    if method == "POST" and path == "/api/schedule":
        return 200, eng.set_schedule(api_validate.parse_schedule_minutes(body.get("minutes")))
    if method == "GET" and path == "/api/export":
        return 200, eng.export_inventory()
    if method == "GET" and path == "/api/presence":
        mac = api_validate.parse_mac((query.get("mac") or [""])[0])
        return 200, eng.presence_for(mac)
    if method == "POST" and path == "/api/ports":
        ip = body.get("ip")
        parsed_ip = api_validate.parse_ipv4(ip) if ip else None
        return 200, eng.start_port_scan(parsed_ip, api_validate.parse_profile(body.get("profile")))
    return 404, {"ok": False, "reason": "Not found"}


class ApiServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, host: str, port: int, static_dir: Path | None) -> None:
        self.static_dir = static_dir
        super().__init__((host, port), ApiHandler)


class ApiHandler(BaseHTTPRequestHandler):
    server: ApiServer
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args: Any) -> None:
        return

    def _cors(self) -> None:
        origin = self.headers.get("Origin", "")
        if origin.startswith("http://127.0.0.1:") or origin.startswith("http://localhost:"):
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")

    def _send(self, status: int, payload: Any, content_type: str = "application/json; charset=utf-8") -> None:
        if isinstance(payload, (dict, list)):
            raw = json.dumps(payload).encode("utf-8")
        elif isinstance(payload, bytes):
            raw = payload
        else:
            raw = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self._cors()
        self.end_headers()
        self.wfile.write(raw)

    def _read_json(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length") or 0)
        if length > 65536:
            raise ValueError("body too large")
        if length <= 0:
            return {}
        data = self.rfile.read(length)
        parsed = json.loads(data.decode("utf-8"))
        if not isinstance(parsed, dict):
            raise ValueError("JSON body must be an object")
        return parsed

    def do_OPTIONS(self) -> None:  # noqa: N802
        self.send_response(204)
        self.send_header("Content-Length", "0")
        self._cors()
        self.end_headers()

    def do_GET(self) -> None:  # noqa: N802
        self._route("GET")

    def do_POST(self) -> None:  # noqa: N802
        self._route("POST")

    def _route(self, method: str) -> None:
        parsed = urlparse(self.path)
        if parsed.path.startswith("/api/"):
            try:
                body = self._read_json() if method == "POST" else {}
                status, payload = dispatch(method, parsed.path, parse_qs(parsed.query), body)
            except ValueError as exc:
                status, payload = 400, {"ok": False, "reason": str(exc)}
            except json.JSONDecodeError:
                status, payload = 400, {"ok": False, "reason": "invalid JSON"}
            except Exception as exc:  # engine errors stay visible to the UI
                status, payload = 500, {"ok": False, "reason": str(exc)}
            self._send(status, payload)
            return
        self._static(parsed.path)

    def _static(self, url_path: str) -> None:
        root = self.server.static_dir
        if root is None:
            self._send(404, {"ok": False, "reason": "UI bundle not found"})
            return
        rel = "index.html" if url_path in ("", "/") else url_path.lstrip("/")
        if ".." in rel.split("/"):
            self._send(400, {"ok": False, "reason": "bad path"})
            return
        try:
            target = api_validate.safe_join(root, *rel.split("/"))
        except ValueError as exc:
            self._send(400, {"ok": False, "reason": str(exc)})
            return
        if target.is_dir():
            target = api_validate.safe_join(target, "index.html")
        if not target.is_file():
            # SPA fallback for client routes
            try:
                target = api_validate.safe_join(root, "index.html")
            except ValueError:
                self._send(404, {"ok": False, "reason": "Not found"})
                return
        data = target.read_bytes()
        mime = _MIME.get(target.suffix.lower()) or mimetypes.guess_type(target.name)[0] or "application/octet-stream"
        self._send(200, data, mime)


def serve(host: str = "127.0.0.1", port: int = 8765, static_dir: Path | None = None) -> None:
    if host not in {"127.0.0.1", "localhost"}:
        raise ValueError("API binds to localhost only")
    httpd = ApiServer(host, port, static_dir)
    thread_name = threading.current_thread().name
    print(f"NetPulse API on http://{host}:{port}/  ({thread_name})", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()

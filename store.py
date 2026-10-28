"""SQLite history for devices, alerts, pings, outages, speed tests, settings."""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from typing import Any

import paths

DB_PATH = paths.cache_dir() / "netpulse.db"
_lock = threading.Lock()


def _conn() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(DB_PATH, check_same_thread=False)
    con.row_factory = sqlite3.Row
    return con


def init() -> None:
    with _lock, _conn() as con:
        con.executescript(
            """
            CREATE TABLE IF NOT EXISTS devices (
                mac TEXT PRIMARY KEY,
                ip TEXT,
                name TEXT,
                vendor TEXT,
                nature TEXT,
                first_seen REAL,
                last_seen REAL,
                present INTEGER,
                trusted INTEGER DEFAULT 0,
                owned INTEGER DEFAULT 0,
                tags TEXT DEFAULT '[]',
                notes TEXT DEFAULT '',
                open_ports TEXT DEFAULT '[]',
                extra TEXT DEFAULT '{}'
            );
            CREATE TABLE IF NOT EXISTS presence (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                mac TEXT,
                ip TEXT,
                event TEXT,
                ts REAL
            );
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                kind TEXT,
                severity TEXT,
                title TEXT,
                detail TEXT,
                ip TEXT,
                mac TEXT,
                ts REAL,
                acked INTEGER DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS ping_samples (
                ts REAL,
                target TEXT,
                latency_ms REAL,
                ok INTEGER
            );
            CREATE TABLE IF NOT EXISTS outages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                started REAL,
                ended REAL,
                target TEXT,
                detail TEXT
            );
            CREATE TABLE IF NOT EXISTS speed_tests (
                ts REAL,
                down_mbps REAL,
                up_mbps REAL,
                idle_ms REAL,
                load_ms REAL,
                bufferbloat TEXT
            );
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(ts DESC);
            CREATE INDEX IF NOT EXISTS idx_ping_ts ON ping_samples(ts);
            """
        )


def get_setting(key: str, default: str = "") -> str:
    with _lock, _conn() as con:
        row = con.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
        return row["value"] if row else default


def set_setting(key: str, value: str) -> None:
    with _lock, _conn() as con:
        con.execute(
            "INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, value),
        )


def upsert_device(dev: dict[str, Any], present: bool = True) -> dict[str, Any]:
    mac = (dev.get("mac") or "").upper()
    if not mac or mac == "—":
        mac = f"IP:{dev.get('ip')}"
    now = time.time()
    with _lock, _conn() as con:
        prev = con.execute("SELECT * FROM devices WHERE mac=?", (mac,)).fetchone()
        events: list[dict[str, Any]] = []
        if prev is None:
            con.execute(
                """INSERT INTO devices(mac,ip,name,vendor,nature,first_seen,last_seen,present,open_ports,extra)
                   VALUES(?,?,?,?,?,?,?,1,?,?)""",
                (
                    mac,
                    dev.get("ip"),
                    dev.get("name"),
                    dev.get("vendor"),
                    dev.get("nature"),
                    now,
                    now,
                    json.dumps(dev.get("open_ports") or []),
                    json.dumps({k: dev.get(k) for k in ("mdns", "ssdp", "netbios", "http", "tls", "dhcp") if dev.get(k)}),
                ),
            )
            events.append({"kind": "new-device", "severity": "info", "title": f"New device {dev.get('ip')}", "detail": dev.get("name") or mac, "ip": dev.get("ip"), "mac": mac})
        else:
            if prev["present"] == 0:
                events.append({"kind": "returned", "severity": "info", "title": f"Device returned {dev.get('ip')}", "detail": prev["name"] or mac, "ip": dev.get("ip"), "mac": mac})
            if prev["ip"] and dev.get("ip") and prev["ip"] != dev.get("ip"):
                events.append({"kind": "ip-change", "severity": "warn", "title": f"IP change {prev['ip']} → {dev.get('ip')}", "detail": mac, "ip": dev.get("ip"), "mac": mac})
            old_ports = {p.get("port") for p in json.loads(prev["open_ports"] or "[]")}
            new_ports = {p.get("port") for p in (dev.get("open_ports") or [])}
            added = new_ports - old_ports
            if added:
                events.append({"kind": "new-port", "severity": "warn", "title": f"New open ports on {dev.get('ip')}", "detail": ", ".join(str(p) for p in sorted(added)), "ip": dev.get("ip"), "mac": mac})
            extra = json.loads(prev["extra"] or "{}")
            extra.update({k: dev.get(k) for k in ("mdns", "ssdp", "netbios", "http", "tls", "dhcp") if dev.get(k)})
            con.execute(
                """UPDATE devices SET ip=?, name=?, vendor=?, nature=?, last_seen=?, present=1,
                   open_ports=?, extra=? WHERE mac=?""",
                (
                    dev.get("ip") or prev["ip"],
                    dev.get("name") or prev["name"],
                    dev.get("vendor") or prev["vendor"],
                    dev.get("nature") or prev["nature"],
                    now,
                    json.dumps(dev.get("open_ports") or json.loads(prev["open_ports"] or "[]")),
                    json.dumps(extra),
                    mac,
                ),
            )
        for ev in events:
            con.execute(
                "INSERT INTO alerts(kind,severity,title,detail,ip,mac,ts) VALUES(?,?,?,?,?,?,?)",
                (ev["kind"], ev["severity"], ev["title"], ev["detail"], ev.get("ip"), mac, now),
            )
            con.execute(
                "INSERT INTO presence(mac,ip,event,ts) VALUES(?,?,?,?)",
                (mac, ev.get("ip"), ev["kind"], now),
            )
    return {"mac": mac, "events": events}


def mark_missing(seen_macs: set[str]) -> list[dict[str, Any]]:
    now = time.time()
    events: list[dict[str, Any]] = []
    with _lock, _conn() as con:
        rows = con.execute("SELECT * FROM devices WHERE present=1").fetchall()
        for row in rows:
            if row["mac"] not in seen_macs:
                con.execute("UPDATE devices SET present=0 WHERE mac=?", (row["mac"],))
                ev = {"kind": "left-network", "severity": "warn", "title": f"Left network {row['ip']}", "detail": row["name"] or row["mac"], "ip": row["ip"], "mac": row["mac"]}
                con.execute(
                    "INSERT INTO alerts(kind,severity,title,detail,ip,mac,ts) VALUES(?,?,?,?,?,?,?)",
                    (ev["kind"], ev["severity"], ev["title"], ev["detail"], row["ip"], row["mac"], now),
                )
                con.execute("INSERT INTO presence(mac,ip,event,ts) VALUES(?,?,?,?)", (row["mac"], row["ip"], "left-network", now))
                events.append(ev)
    return events


def device_meta(mac: str) -> dict[str, Any]:
    mac = (mac or "").upper()
    with _lock, _conn() as con:
        row = con.execute("SELECT * FROM devices WHERE mac=?", (mac,)).fetchone()
        if not row:
            return {"trusted": False, "owned": False, "tags": [], "notes": "", "first_seen": None, "last_seen": None, "present": False}
        return {
            "trusted": bool(row["trusted"]),
            "owned": bool(row["owned"]),
            "tags": json.loads(row["tags"] or "[]"),
            "notes": row["notes"] or "",
            "first_seen": row["first_seen"],
            "last_seen": row["last_seen"],
            "present": bool(row["present"]),
        }


def set_device_flags(mac: str, trusted: bool | None = None, owned: bool | None = None, tags: list[str] | None = None, notes: str | None = None) -> None:
    mac = mac.upper()
    with _lock, _conn() as con:
        row = con.execute("SELECT * FROM devices WHERE mac=?", (mac,)).fetchone()
        if not row:
            return
        t = int(row["trusted"] if trusted is None else trusted)
        o = int(row["owned"] if owned is None else owned)
        tg = json.dumps(tags if tags is not None else json.loads(row["tags"] or "[]"))
        n = row["notes"] if notes is None else notes
        con.execute("UPDATE devices SET trusted=?, owned=?, tags=?, notes=? WHERE mac=?", (t, o, tg, n, mac))


def alerts(limit: int = 80, unacked_only: bool = False) -> list[dict[str, Any]]:
    q = "SELECT * FROM alerts"
    if unacked_only:
        q += " WHERE acked=0"
    q += " ORDER BY ts DESC LIMIT ?"
    with _lock, _conn() as con:
        rows = con.execute(q, (limit,)).fetchall()
        return [dict(r) for r in rows]


def ack_alert(alert_id: int) -> None:
    with _lock, _conn() as con:
        con.execute("UPDATE alerts SET acked=1 WHERE id=?", (alert_id,))


def add_alert(kind: str, severity: str, title: str, detail: str = "", ip: str = "", mac: str = "") -> None:
    with _lock, _conn() as con:
        con.execute(
            "INSERT INTO alerts(kind,severity,title,detail,ip,mac,ts) VALUES(?,?,?,?,?,?,?)",
            (kind, severity, title, detail, ip, mac, time.time()),
        )


def add_ping(target: str, latency_ms: float | None, ok: bool) -> None:
    with _lock, _conn() as con:
        con.execute(
            "INSERT INTO ping_samples(ts,target,latency_ms,ok) VALUES(?,?,?,?)",
            (time.time(), target, latency_ms, int(ok)),
        )
        cutoff = time.time() - 86400
        con.execute("DELETE FROM ping_samples WHERE ts<?", (cutoff,))


def ping_stats(target: str, window_s: float = 300) -> dict[str, Any]:
    since = time.time() - window_s
    with _lock, _conn() as con:
        rows = con.execute(
            "SELECT latency_ms, ok FROM ping_samples WHERE target=? AND ts>=? ORDER BY ts",
            (target, since),
        ).fetchall()
    if not rows:
        return {"loss": 0, "avg": None, "jitter": None, "samples": 0}
    oks = [r["latency_ms"] for r in rows if r["ok"] and r["latency_ms"] is not None]
    loss = 1 - (len(oks) / len(rows))
    avg = sum(oks) / len(oks) if oks else None
    jitter = None
    if len(oks) > 1:
        diffs = [abs(oks[i] - oks[i - 1]) for i in range(1, len(oks))]
        jitter = sum(diffs) / len(diffs)
    return {"loss": round(loss * 100, 1), "avg": round(avg, 1) if avg is not None else None, "jitter": round(jitter, 1) if jitter is not None else None, "samples": len(rows)}


def open_outage(target: str, detail: str) -> None:
    with _lock, _conn() as con:
        open_row = con.execute("SELECT id FROM outages WHERE target=? AND ended IS NULL", (target,)).fetchone()
        if open_row:
            return
        con.execute("INSERT INTO outages(started,ended,target,detail) VALUES(?,?,?,?)", (time.time(), None, target, detail))


def close_outage(target: str) -> None:
    with _lock, _conn() as con:
        con.execute("UPDATE outages SET ended=? WHERE target=? AND ended IS NULL", (time.time(), target))


def outages(limit: int = 40) -> list[dict[str, Any]]:
    with _lock, _conn() as con:
        rows = con.execute("SELECT * FROM outages ORDER BY started DESC LIMIT ?", (limit,)).fetchall()
        return [dict(r) for r in rows]


def add_speed(down: float, up: float, idle_ms: float, load_ms: float, grade: str) -> None:
    with _lock, _conn() as con:
        con.execute(
            "INSERT INTO speed_tests(ts,down_mbps,up_mbps,idle_ms,load_ms,bufferbloat) VALUES(?,?,?,?,?,?)",
            (time.time(), down, up, idle_ms, load_ms, grade),
        )


def speed_history(limit: int = 20) -> list[dict[str, Any]]:
    with _lock, _conn() as con:
        rows = con.execute("SELECT * FROM speed_tests ORDER BY ts DESC LIMIT ?", (limit,)).fetchall()
        return [dict(r) for r in rows]


def presence_history(mac: str, limit: int = 40) -> list[dict[str, Any]]:
    with _lock, _conn() as con:
        rows = con.execute("SELECT * FROM presence WHERE mac=? ORDER BY ts DESC LIMIT ?", (mac.upper(), limit)).fetchall()
        return [dict(r) for r in rows]


def export_devices() -> list[dict[str, Any]]:
    with _lock, _conn() as con:
        rows = con.execute("SELECT * FROM devices ORDER BY last_seen DESC").fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["tags"] = json.loads(d.get("tags") or "[]")
            d["open_ports"] = json.loads(d.get("open_ports") or "[]")
            d["extra"] = json.loads(d.get("extra") or "{}")
            out.append(d)
        return out

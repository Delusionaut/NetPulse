"""Webhooks and desktop notifications."""

from __future__ import annotations

import json
import subprocess
import urllib.request
from typing import Any


def webhook(url: str, payload: dict[str, Any]) -> dict[str, Any]:
    if not url:
        return {"ok": False, "reason": "No webhook URL"}
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json", "User-Agent": "NetPulse/1.0"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=6) as resp:
            return {"ok": True, "status": resp.status}
    except Exception as exc:
        return {"ok": False, "reason": str(exc)}


def desktop_toast(title: str, body: str) -> None:
    title = title.replace("'", "''")
    body = body.replace("'", "''")
    ps = (
        "[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] > $null; "
        "$t = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02); "
        "$t.GetElementsByTagName('text').Item(0).AppendChild($t.CreateTextNode('%s')) > $null; "
        "$t.GetElementsByTagName('text').Item(1).AppendChild($t.CreateTextNode('%s')) > $null; "
        "$toast = [Windows.UI.Notifications.ToastNotification]::new($t); "
        "[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('NetPulse').Show($toast);"
        % (title, body)
    )
    try:
        subprocess.Popen(
            ["powershell", "-NoProfile", "-Command", ps],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
    except Exception:
        pass

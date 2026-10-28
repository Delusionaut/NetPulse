"""Resolve bundled resources vs writable cache for source and frozen .exe."""

from __future__ import annotations

import sys
from pathlib import Path


def resource_dir() -> Path:
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        return Path(sys._MEIPASS)
    return Path(__file__).resolve().parent


def writable_dir() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


def cache_dir() -> Path:
    path = writable_dir() / "cache"
    path.mkdir(parents=True, exist_ok=True)
    return path

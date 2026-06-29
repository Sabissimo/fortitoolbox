"""Local address book — a tiny CSV of FortiGate addresses.

Lets the operator pick a saved "contact" in the connect dialog instead of
re-typing the host every time. By design this stores **only the address**
(an optional friendly label + host[:port]) — never a username, never a
password. Secrets are typed fresh on every connect, consistent with the
"never log, store, or transmit credentials" rule.

The file lives outside the repo, in the user's home dir, so it is per-machine
and never committed.
"""
from __future__ import annotations

import csv
from pathlib import Path
from typing import Dict, List

BOOK_DIR = Path.home() / ".fortitoolbox"
BOOK_PATH = BOOK_DIR / "addressbook.csv"

_FIELDS = ("name", "host")


def _norm(s: str) -> str:
    return (s or "").strip()


def load() -> List[Dict[str, str]]:
    """Return saved contacts as [{'name':..., 'host':...}], sorted by name.

    Missing/malformed rows are skipped silently — the book is best-effort and
    must never block connecting.
    """
    if not BOOK_PATH.exists():
        return []
    out: List[Dict[str, str]] = []
    try:
        with BOOK_PATH.open("r", encoding="utf-8", newline="") as fh:
            for row in csv.DictReader(fh):
                host = _norm(row.get("host"))
                if not host:
                    continue
                out.append({"name": _norm(row.get("name")) or host, "host": host})
    except (OSError, csv.Error):
        return []
    out.sort(key=lambda c: c["name"].lower())
    return out


def save(contacts: List[Dict[str, str]]) -> None:
    """Overwrite the book with `contacts` (deduped by host, last write wins)."""
    seen: Dict[str, Dict[str, str]] = {}
    for c in contacts:
        host = _norm(c.get("host"))
        if not host:
            continue
        seen[host] = {"name": _norm(c.get("name")) or host, "host": host}
    BOOK_DIR.mkdir(parents=True, exist_ok=True)
    with BOOK_PATH.open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=_FIELDS)
        w.writeheader()
        for c in sorted(seen.values(), key=lambda c: c["name"].lower()):
            w.writerow(c)


def add(host: str, name: str = "") -> List[Dict[str, str]]:
    """Add (or relabel) a contact and persist. Returns the updated book."""
    host = _norm(host)
    if not host:
        return load()
    contacts = [c for c in load() if c["host"] != host]
    contacts.append({"name": _norm(name) or host, "host": host})
    save(contacts)
    return load()


def remove(host: str) -> List[Dict[str, str]]:
    """Drop the contact with this host and persist. Returns the updated book."""
    host = _norm(host)
    contacts = [c for c in load() if c["host"] != host]
    save(contacts)
    return load()

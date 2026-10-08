"""One source of wall-clock time for the engine.

Every timestamp the engine writes comes from here.

**Why a module and not a ``datetime.now()`` call at each site.** ``datetime.now()``
returns a *naive local* time: on a machine in any timezone but UTC it records the
wrong instant, and the string is not comparable with the tz-aware instants the
rest of the engine produces. A single helper is the only way to guarantee the
format does not drift between the DSSE payload, the SQLite records and the
scrapers.

**Why UTC.** An evidence bundle is anchored and counter-signed, so the instant it
records must mean the same thing to a reader in any timezone.

The format is deliberately the engine's existing one — ``datetime.isoformat()``
on a UTC-aware value, e.g. ``2026-10-08T23:10:50.123456+00:00``. It round-trips
through ``datetime.fromisoformat`` on the project's Python floor, and changing it
would move the bytes of every anchored bundle, so it is not changed here.
"""

from __future__ import annotations

from datetime import datetime, timezone


def utc_now() -> datetime:
    """The current instant, timezone-aware and in UTC.

    Pass the result of this (or a fixed instant) wherever a timestamp is needed;
    never call ``datetime.now()`` directly.
    """
    return datetime.now(timezone.utc)


def utc_now_iso() -> str:
    """The current instant, rendered in the engine's stored format."""
    return utc_now().isoformat()

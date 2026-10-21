"""whois_lookup.py - WHOIS data collection and domain age calculation."""

import logging
from datetime import datetime, timezone

import whois

# The whois library logs low-level socket errors; keep the output clean.
logging.getLogger("whois").setLevel(logging.CRITICAL)


def _first(value):
    """WHOIS fields can be a single value or a list; return the first item."""
    if isinstance(value, (list, tuple)):
        return value[0] if value else None
    return value


def _to_utc(date_value):
    """Convert a WHOIS date to a timezone-aware UTC datetime (or None)."""
    date_value = _first(date_value)
    if not isinstance(date_value, datetime):
        return None
    if date_value.tzinfo is None:
        return date_value.replace(tzinfo=timezone.utc)
    return date_value.astimezone(timezone.utc)


def _short_error(exc):
    """Keep only the first line of an error so long WHOIS text is not shown."""
    lines = str(exc).strip().splitlines()
    return lines[0] if lines else exc.__class__.__name__


def get_whois_info(domain):
    """Return a dict with WHOIS details. Never raises; errors go in 'error'."""
    result = {
        "registrar": None,
        "creation_date": None,
        "expiration_date": None,
        "name_servers": [],
        "domain_age_days": None,
        "error": None,
    }

    try:
        data = whois.whois(domain)
    except Exception as exc:
        result["error"] = f"WHOIS lookup failed: {_short_error(exc)}"
        return result

    created = _to_utc(data.get("creation_date"))
    expires = _to_utc(data.get("expiration_date"))

    result["registrar"] = _first(data.get("registrar"))
    result["creation_date"] = created.strftime("%Y-%m-%d") if created else None
    result["expiration_date"] = expires.strftime("%Y-%m-%d") if expires else None

    name_servers = data.get("name_servers") or []
    if isinstance(name_servers, str):
        name_servers = [name_servers]
    result["name_servers"] = sorted({ns.lower() for ns in name_servers})

    if created:
        result["domain_age_days"] = (datetime.now(timezone.utc) - created).days

    return result
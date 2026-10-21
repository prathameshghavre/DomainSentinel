"""ip_lookup.py - Geolocation and network owner details for a public IP."""

import ipaddress

import requests

GEO_API = "https://ipwho.is/{ip}"
TIMEOUT_SECONDS = 5


def get_ip_info(ip_address):
    """Return location and network owner details. Never raises."""
    result = {
        "ip": ip_address,
        "country": None,
        "region": None,
        "city": None,
        "isp": None,
        "organization": None,
        "asn": None,
        "error": None,
    }

    # Only public IPs are looked up; private/internal ranges are refused.
    try:
        ip_obj = ipaddress.ip_address(ip_address)
    except ValueError:
        result["error"] = "Not a valid IP address."
        return result
    if not ip_obj.is_global:
        result["error"] = "Not a public IP address. Lookup skipped."
        return result

    try:
        response = requests.get(GEO_API.format(ip=ip_address), timeout=TIMEOUT_SECONDS)
        response.raise_for_status()
        data = response.json()
    except requests.RequestException as exc:
        result["error"] = f"IP lookup request failed: {exc}"
        return result
    except ValueError:
        result["error"] = "IP lookup returned an unreadable response."
        return result

    if not data.get("success", False):
        result["error"] = f"IP lookup failed: {data.get('message', 'unknown reason')}"
        return result

    connection = data.get("connection") or {}
    result.update(
        country=data.get("country"),
        region=data.get("region"),
        city=data.get("city"),
        isp=connection.get("isp"),
        organization=connection.get("org"),
        asn=connection.get("asn"),
    )
    return result
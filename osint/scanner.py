"""scanner.py - Runs every module for one domain and returns a single report."""

from datetime import datetime, timezone

from osint.validator import validate_domain
from osint.whois_lookup import get_whois_info
from osint.dns_lookup import get_dns_records
from osint.email_security import get_email_security
from osint.ip_lookup import get_ip_info
from osint.risk_engine import calculate_risk


def _not_applicable_email_result():
    """Used when the domain does not exist, so email checks make no sense."""
    note = "Not applicable: the domain does not exist."
    return {
        "spf": {"found": False, "record": None, "policy": "n/a", "note": note},
        "dmarc": {"found": False, "record": None, "policy": "n/a", "note": note,
                  "error": None},
    }


def scan_domain(raw_domain):
    """Validate the input, run all lookups and return one report dict.

    Never raises. If the input is invalid, 'ok' is False and 'error' explains why.
    """
    ok, cleaned = validate_domain(raw_domain)
    if not ok:
        return {"ok": False, "domain": None, "error": cleaned}

    whois_data = get_whois_info(cleaned)
    dns_data = get_dns_records(cleaned)

    if dns_data["domain_exists"]:
        email_data = get_email_security(cleaned, dns_data["TXT"], dns_data["error"])
    else:
        email_data = _not_applicable_email_result()

    ip_data = None
    if dns_data["A"]:
        ip_data = get_ip_info(dns_data["A"][0])

    risk = calculate_risk(whois_data, dns_data, email_data)

    return {
        "ok": True,
        "domain": cleaned,
        "scanned_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
        "whois": whois_data,
        "dns": dns_data,
        "email_security": email_data,
        "ip": ip_data,
        "risk": risk,
        "error": None,
    }
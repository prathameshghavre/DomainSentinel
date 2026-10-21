"""dns_lookup.py - Collect common DNS records for a domain."""

import dns.exception
import dns.resolver

RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT"]

# Fixed public resolvers so results are the same on every network.
PUBLIC_RESOLVERS = ["8.8.8.8", "1.1.1.1"]


def _make_resolver():
    """Resolver with fixed public DNS servers and short timeouts."""
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = PUBLIC_RESOLVERS
    resolver.timeout = 3
    resolver.lifetime = 5
    return resolver


def _format_record(record_type, record):
    """Turn a DNS record object into a clean readable string."""
    if record_type == "MX":
        return f"{record.preference} {record.exchange.to_text().rstrip('.')}"
    if record_type == "NS":
        return record.target.to_text().rstrip(".")
    if record_type == "TXT":
        return b"".join(record.strings).decode("utf-8", "replace")
    return record.to_text()


def get_dns_records(domain):
    """Return a dict of DNS records. Never raises; problems go in 'error'."""
    result = {rtype: [] for rtype in RECORD_TYPES}
    result["domain_exists"] = True
    result["error"] = None

    resolver = _make_resolver()

    for rtype in RECORD_TYPES:
        try:
            answers = resolver.resolve(domain, rtype)
            result[rtype] = [_format_record(rtype, r) for r in answers]
        except dns.resolver.NXDOMAIN:
            result["domain_exists"] = False
            result["error"] = "Domain does not exist (NXDOMAIN)."
            break
        except dns.resolver.NoAnswer:
            continue  # This record type simply does not exist for the domain.
        except dns.exception.Timeout:
            result["error"] = f"DNS timeout while querying {rtype} records."
        except Exception as exc:
            result["error"] = f"DNS error: {exc}"

    return result
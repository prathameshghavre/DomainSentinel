"""email_security.py - Check SPF and DMARC email authentication records."""

import dns.exception
import dns.resolver

from osint.dns_lookup import _make_resolver


def check_spf(txt_records):
    """Analyse the SPF record found in the domain's TXT records."""
    spf_records = [r for r in txt_records if r.lower().startswith("v=spf1")]

    if not spf_records:
        return {
            "found": False,
            "record": None,
            "policy": "missing",
            "note": "No SPF record. Anyone can try to send mail pretending to be this domain.",
        }

    record = spf_records[0]
    last_token = record.lower().split()[-1]

    policies = {
        "-all": ("strict", "Strict SPF: unauthorized senders are rejected."),
        "~all": ("softfail", "Soft-fail SPF: unauthorized mail is accepted but marked suspicious."),
        "?all": ("neutral", "Neutral SPF: gives no protection against spoofing."),
        "+all": ("allow_all", "Dangerous SPF: every server is allowed to send mail."),
    }
    policy, note = policies.get(
        last_token, ("unknown", "SPF record found but its ending is not standard.")
    )

    if len(spf_records) > 1:
        policy, note = "invalid", "Multiple SPF records found. This is a misconfiguration."

    return {"found": True, "record": record, "policy": policy, "note": note}


def check_dmarc(domain):
    """Look up and analyse the DMARC record at _dmarc.<domain>."""
    result = {
        "found": False,
        "record": None,
        "policy": "missing",
        "note": "No DMARC record. Spoofed mail is not blocked based on domain policy.",
        "error": None,
    }

    try:
        answers = _make_resolver().resolve(f"_dmarc.{domain}", "TXT")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return result
    except dns.exception.Timeout:
        result.update(
            policy="error",
            note="DMARC lookup timed out. Result unknown.",
            error="DNS timeout while checking DMARC.",
        )
        return result
    except Exception as exc:
        result.update(
            policy="error",
            note="DMARC lookup failed. Result unknown.",
            error=f"DNS error: {exc}",
        )
        return result

    for answer in answers:
        text = b"".join(answer.strings).decode("utf-8", "replace")
        if not text.lower().startswith("v=dmarc1"):
            continue

        tags = {}
        for part in text.split(";"):
            if "=" in part:
                key, value = part.split("=", 1)
                tags[key.strip().lower()] = value.strip()

        policy = tags.get("p", "").lower()
        notes = {
            "none": "DMARC in monitor-only mode: spoofed mail is not blocked.",
            "quarantine": "DMARC quarantine: spoofed mail goes to spam.",
            "reject": "DMARC reject: spoofed mail is blocked. Strongest setting.",
        }
        result.update(
            found=True,
            record=text,
            policy=policy if policy in notes else "unknown",
            note=notes.get(policy, "DMARC record found but policy is not valid."),
        )
        return result

    return result


def get_email_security(domain, txt_records, dns_error=None):
    """Run both checks and return the combined result."""
    spf = check_spf(txt_records)
    if not txt_records and dns_error:
        spf = {
            "found": False,
            "record": None,
            "policy": "error",
            "note": "TXT lookup failed, so SPF could not be checked.",
        }
    return {"spf": spf, "dmarc": check_dmarc(domain)}
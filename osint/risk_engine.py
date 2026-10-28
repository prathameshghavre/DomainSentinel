"""risk_engine.py - Explainable risk scoring for a domain.

Every point added to the score comes with a reason, so the result can be
explained and audited. Data that could not be collected is listed as
'unknown' and is never counted as risk.

NOTE: The weights below are heuristic values chosen for this project.
They are indicators only, not an industry standard or a final verdict.
"""

SEVERITY_LEVELS = [(75, "Critical"), (50, "High"), (25, "Medium"), (0, "Low")]

SPF_POINTS = {
    "missing": (15, "No SPF record, so the domain's email is easy to spoof."),
    "softfail": (5, "SPF is soft-fail, which gives only weak spoofing protection."),
    "neutral": (15, "SPF is neutral and gives no protection against spoofing."),
    "allow_all": (20, "SPF allows every server to send mail for this domain."),
    "invalid": (10, "SPF is misconfigured (multiple records)."),
    "unknown": (5, "SPF record has a non-standard ending."),
}

DMARC_POINTS = {
    "missing": (15, "No DMARC record, so spoofed mail is not blocked by policy."),
    "none": (10, "DMARC is monitor-only and does not block spoofed mail."),
    "unknown": (5, "DMARC record found but its policy is not valid."),
}


def _severity(score):
    for threshold, label in SEVERITY_LEVELS:
        if score >= threshold:
            return label
    return "Low"


def _add(findings, points, factor, why):
    findings.append({"points": points, "factor": factor, "why": why})


def calculate_risk(whois_data, dns_data, email_data, lookalike=None):
    """Return score (0-100), severity, scored findings and unknown items."""
    findings = []
    unknown = []

    # 1. Domain age: attackers often register fresh domains for phishing.
    age = whois_data.get("domain_age_days")
    if age is None:
        reason = whois_data.get("error") or "Creation date not available."
        unknown.append(f"Domain age unknown. {reason}")
    elif age < 30:
        _add(findings, 35, f"Domain is very new ({age} days old)",
             "Newly registered domains are commonly used in phishing campaigns.")
    elif age < 90:
        _add(findings, 20, f"Domain is new ({age} days old)",
             "Young domains have little reputation and deserve extra caution.")
    elif age < 365:
        _add(findings, 10, f"Domain is less than a year old ({age} days)",
             "Domains under a year old carry slightly higher risk.")

    # 2. Look-alike of a well-known brand (brand impersonation).
    if lookalike and lookalike.get("points"):
        _add(findings, lookalike["points"],
             f"Look-alike domain ({lookalike['technique']}): "
             f"resembles {lookalike['suspected_brand']}",
             lookalike["why"])

    # 3. Does the domain resolve at all?
    if not dns_data.get("domain_exists", True):
        _add(findings, 30, "Domain does not exist (NXDOMAIN)",
             "A domain that does not resolve cannot be verified or trusted.")
    else:
        if dns_data.get("error"):
            unknown.append(f"DNS data incomplete. {dns_data['error']}")
        else:
            if not dns_data.get("A") and not dns_data.get("AAAA"):
                _add(findings, 15, "No IP address records",
                     "A domain with no A or AAAA record does not point to any server.")
            if not dns_data.get("MX"):
                _add(findings, 5, "No mail (MX) records",
                     "The domain is not set up to receive email.")

        # 4. Email authentication (SPF and DMARC).
        spf = email_data["spf"]
        dmarc = email_data["dmarc"]

        if spf["policy"] == "error":
            unknown.append("SPF could not be checked because the TXT lookup failed.")
        elif spf["policy"] in SPF_POINTS:
            points, why = SPF_POINTS[spf["policy"]]
            _add(findings, points, f"SPF: {spf['policy']}", why)

        if dmarc["policy"] == "error":
            unknown.append(f"DMARC could not be checked. {dmarc.get('error')}")
        elif dmarc["policy"] in DMARC_POINTS:
            points, why = DMARC_POINTS[dmarc["policy"]]
            _add(findings, points, f"DMARC: {dmarc['policy']}", why)

    score = min(100, sum(item["points"] for item in findings))

    return {
        "score": score,
        "severity": _severity(score),
        "findings": findings,
        "unknown": unknown,
        "data_complete": not unknown,
    }
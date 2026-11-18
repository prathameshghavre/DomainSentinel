"""extractor.py - Pull domain names out of pasted text (for example a phishing email).

Everything here is text processing only. No link is opened and no website is contacted.
"""

import re

from osint.validator import validate_domain

MAX_DOMAINS = 15

# Words like 'report.pdf' look like domains, so plain-text names are accepted only
# when they end in one of these common endings. Links and email addresses are
# clearly domains, so they are accepted with any valid ending.
COMMON_TLDS = {
    "com", "net", "org", "in", "co", "io", "info", "biz", "xyz", "top", "online",
    "site", "shop", "app", "dev", "edu", "gov", "uk", "us", "ru", "cn", "de",
    "fr", "au", "ca", "me", "cc", "club", "live", "store", "tech", "link", "click",
}

URL_RE = re.compile(r"https?://([^\s/?#<>\"'(),;\[\]]+)", re.IGNORECASE)
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)")
BARE_RE = re.compile(r"(?<![@\w.-])((?:[a-z0-9-]{1,63}\.)+[a-z]{2,24})(?![\w@-])",
                     re.IGNORECASE)


def _refang(text):
    """Undo the 'defanging' that analysts use to make links harmless in reports."""
    text = re.sub(r"hxxp", "http", text, flags=re.IGNORECASE)
    text = re.sub(r"\[\s*\.\s*\]|\(\s*\.\s*\)|\{\s*\.\s*\}", ".", text)
    text = re.sub(r"\[\s*dot\s*\]|\(\s*dot\s*\)", ".", text, flags=re.IGNORECASE)
    text = re.sub(r"\[\s*at\s*\]|\(\s*at\s*\)", "@", text, flags=re.IGNORECASE)
    return text.replace("[://]", "://").replace("[:]", ":")


def _clean_host(host):
    """Keep only the real host of a link (drops user info and port)."""
    host = host.split("@")[-1]   # https://paypal.com@evil.com really goes to evil.com
    host = host.split(":")[0]
    return host.strip(".").lower()


def extract_domains(text, limit=MAX_DOMAINS):
    """Return {'domains': [{'domain', 'sources'}], 'truncated': number skipped}."""
    text = _refang(text or "")
    found = {}

    def add(raw, source):
        host = _clean_host(raw)
        if host.startswith("www."):
            host = host[4:]
        ok, cleaned = validate_domain(host)
        if not ok:
            return
        sources = found.setdefault(cleaned, [])
        if source not in sources:
            sources.append(source)

    for match in URL_RE.finditer(text):
        add(match.group(1), "link")
    for match in EMAIL_RE.finditer(text):
        add(match.group(1), "email address")
    for match in BARE_RE.finditer(text):
        name = match.group(1)
        if name.lower().rsplit(".", 1)[-1] in COMMON_TLDS:
            add(name, "text")

    items = [{"domain": d, "sources": s} for d, s in found.items()]
    return {"domains": items[:limit], "truncated": max(0, len(items) - limit)}


def analyze_headers(text):
    """Compare the domains in the From, Reply-To and Return-Path headers.

    A difference is only a hint: newsletters and mailing services often use
    different domains for good reasons.
    """
    text = _refang(text or "")
    domains = {}
    for name in ("From", "Reply-To", "Return-Path"):
        match = re.search(rf"^{name}:\s*(.+)$", text, re.IGNORECASE | re.MULTILINE)
        if match:
            email = EMAIL_RE.search(match.group(1))
            if email:
                domains[name] = email.group(1).lower()

    findings = []
    sender = domains.get("From")
    if sender:
        reply = domains.get("Reply-To")
        bounce = domains.get("Return-Path")
        if reply and reply != sender:
            findings.append({
                "header": "Reply-To",
                "message": f"Replies go to {reply}, not to the sender's domain {sender}. "
                           "Scammers use this to receive victims' replies.",
            })
        if bounce and bounce != sender:
            findings.append({
                "header": "Return-Path",
                "message": f"The bounce address uses {bounce}, not {sender}. "
                           "This is common for newsletters, so treat it as a hint only.",
            })
    return {"domains": domains, "findings": findings}
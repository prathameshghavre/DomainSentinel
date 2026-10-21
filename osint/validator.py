"""validator.py - Input validation for the OSINT tool.

Only well-formed public domain names are accepted. This protects the tool
from malformed or malicious input before any lookup is performed.
"""

import re

# A domain label: letters, digits, hyphen; cannot start or end with a hyphen.
LABEL_REGEX = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
TLD_REGEX = re.compile(r"^([a-z]{2,24}|xn--[a-z0-9-]{1,59})$")

BLOCKED_NAMES = {"localhost"}
BLOCKED_SUFFIXES = (".local", ".internal", ".lan", ".localdomain")


def validate_domain(raw_input):
    """Return (True, cleaned_domain) or (False, error_message)."""
    if not isinstance(raw_input, str):
        return False, "Input must be text."

    domain = raw_input.strip().lower().rstrip(".")

    if not domain:
        return False, "Domain cannot be empty."
    if len(domain) > 253:
        return False, "Domain is too long."
    if any(ch in domain for ch in (" ", "/", ":", "@", "\\")):
        return False, "Enter only a domain name (no URL, port or spaces)."
    if domain in BLOCKED_NAMES or domain.endswith(BLOCKED_SUFFIXES):
        return False, "Internal or local names are not allowed."

    labels = domain.split(".")
    if len(labels) < 2:
        return False, "Domain must contain a dot, like example.com."
    if not all(LABEL_REGEX.match(label) for label in labels):
        return False, "Domain contains invalid characters or format."
    if not TLD_REGEX.match(labels[-1]):
        return False, "Invalid top-level domain (IP addresses not allowed)."

    return True, domain
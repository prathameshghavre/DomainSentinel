"""lookalike.py - Detect look-alike (brand impersonation) domain names.

The main name of a domain is compared with a small list of well-known brands.
This is a heuristic: it can raise false alarms and can miss attacks. The brand
list and the points are choices made for this project, not a standard.
"""

# Brand name -> its official domains. Official domains are never flagged.
BRANDS = {
    "google": {"google.com", "google.co.in"},
    "paypal": {"paypal.com"},
    "amazon": {"amazon.com", "amazon.in", "amazon.co.in"},
    "microsoft": {"microsoft.com"},
    "facebook": {"facebook.com"},
    "instagram": {"instagram.com"},
    "netflix": {"netflix.com"},
    "linkedin": {"linkedin.com"},
    "github": {"github.com"},
    "whatsapp": {"whatsapp.com"},
    "youtube": {"youtube.com"},
    "apple": {"apple.com"},
    "flipkart": {"flipkart.com"},
    "paytm": {"paytm.com"},
    "hdfcbank": {"hdfcbank.com"},
    "icicibank": {"icicibank.com"},
    "dropbox": {"dropbox.com"},
}

# Domain endings like .co.in or .com.au have two parts.
SECOND_LEVEL = {"co", "com", "org", "net", "gov", "ac", "edu"}

# Words often added to a brand name in phishing domains.
KEYWORDS = ("login", "signin", "secure", "verify", "account", "update",
            "support", "service", "bank", "wallet", "payment", "billing")

# Characters attackers use instead of letters.
LEET = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a",
                      "5": "s", "7": "t", "$": "s"})


def _registered_parts(domain):
    """Return (main_label, registered_domain), e.g. ('google', 'google.co.in')."""
    labels = domain.split(".")
    if len(labels) >= 3 and len(labels[-1]) == 2 and labels[-2] in SECOND_LEVEL:
        return labels[-3], ".".join(labels[-3:])
    return labels[-2], ".".join(labels[-2:])


def _edit_distance(a, b):
    """Number of single-character changes needed to turn a into b.

    Insert, delete, replace and swapping two neighbouring letters count as one.
    """
    rows, cols = len(a) + 1, len(b) + 1
    table = [[0] * cols for _ in range(rows)]
    for i in range(rows):
        table[i][0] = i
    for j in range(cols):
        table[0][j] = j
    for i in range(1, rows):
        for j in range(1, cols):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            table[i][j] = min(table[i - 1][j] + 1,
                              table[i][j - 1] + 1,
                              table[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                table[i][j] = min(table[i][j], table[i - 2][j - 2] + 1)
    return table[-1][-1]


def _swap_variants(text):
    """Undo common character tricks. '1' can mean 'l' or 'i', so return both."""
    text = text.replace("rn", "m").replace("vv", "w")
    return {text.translate(LEET), text.replace("1", "i").translate(LEET)}


def _check_brand(label, registered, brand):
    """Compare one domain name with one brand. Return (points, technique, why) or None."""
    compact = label.replace("-", "")

    if label == brand:
        return (10, "Brand name on a different domain",
                f"Uses the name '{brand}', but '{registered}' is not its official domain.")
    if compact != brand and brand in _swap_variants(compact):
        return (30, "Character swap",
                f"'{label}' looks like '{brand}' with look-alike characters "
                f"swapped in (for example 0 instead of o).")
    if compact == brand:
        return (25, "Hyphens inserted",
                f"'{label}' is '{brand}' with hyphens added.")
    if len(brand) >= 6 and _edit_distance(compact, brand) == 1:
        return (25, "Typo of brand name",
                f"'{label}' is one typing mistake away from '{brand}'.")

    tokens = label.split("-")
    has_brand = brand in tokens or label.startswith(brand) or label.endswith(brand)
    has_extra = "-" in label or any(word in label for word in KEYWORDS)
    if has_brand and has_extra:
        return (20, "Brand name with extra words",
                f"'{label}' uses '{brand}' together with extra words, "
                f"a common phishing pattern.")
    return None


def check_lookalike(domain):
    """Check one (already validated) domain. Never raises."""
    label, registered = _registered_parts(domain)
    result = {
        "checked": True,
        "suspected_brand": None,
        "technique": None,
        "points": 0,
        "why": "No look-alike pattern found.",
    }

    for brand, official in BRANDS.items():
        if registered in official:
            result["why"] = f"Official domain of {brand}."
            return result

    best = None
    for brand in BRANDS:
        match = _check_brand(label, registered, brand)
        if match and (best is None or match[0] > best[0]):
            best = match + (brand,)

    if best:
        points, technique, why, brand = best
        result.update(suspected_brand=brand, technique=technique,
                      points=points, why=why)
    return result
"""test_osint.py - Offline tests (no internet needed) for input validation
and risk scoring. The risk tests use SIMULATED data, not real domains."""

import unittest

from osint.validator import validate_domain
from osint.risk_engine import calculate_risk


def make_inputs(age=5000, has_ip=True, has_mx=True, spf="strict",
                dmarc="reject", dmarc_error=None):
    """Build simulated WHOIS, DNS and email-security results."""
    whois_data = {
        "domain_age_days": age,
        "error": None if age is not None else "WHOIS data not available.",
    }
    dns_data = {
        "domain_exists": True,
        "error": None,
        "A": ["203.0.113.10"] if has_ip else [],
        "AAAA": [],
        "MX": ["10 mail.example.com"] if has_mx else [],
        "NS": ["ns1.example.com"],
        "TXT": [],
    }
    email_data = {
        "spf": {"policy": spf},
        "dmarc": {"policy": dmarc, "error": dmarc_error},
    }
    return whois_data, dns_data, email_data


class TestValidator(unittest.TestCase):
    def test_valid_domain_is_accepted(self):
        self.assertEqual(validate_domain("example.com"), (True, "example.com"))

    def test_input_is_cleaned(self):
        self.assertEqual(validate_domain("  GOOGLE.com "), (True, "google.com"))

    def test_bad_inputs_are_rejected(self):
        bad_inputs = [
            "localhost", "192.168.1.1", "http://example.com", "bad_domain.com",
            "", "-abc.com", "example..com", "internal.local",
            "example.com/path", "user@example.com", "a" * 64 + ".com",
            "example.com'; DROP TABLE scans;--",
            "<script>alert(1)</script>.com", None,
        ]
        for value in bad_inputs:
            with self.subTest(value=value):
                ok, _ = validate_domain(value)
                self.assertFalse(ok)


class TestRiskEngine(unittest.TestCase):
    def test_well_configured_old_domain_is_low(self):
        risk = calculate_risk(*make_inputs())
        self.assertEqual(risk["score"], 0)
        self.assertEqual(risk["severity"], "Low")

    def test_new_domain_with_weak_email_is_high(self):
        risk = calculate_risk(*make_inputs(
            age=5, has_mx=False, spf="missing", dmarc="missing"))
        self.assertEqual(risk["score"], 70)
        self.assertEqual(risk["severity"], "High")

    def test_new_domain_with_no_ip_is_critical(self):
        risk = calculate_risk(*make_inputs(
            age=5, has_ip=False, has_mx=False, spf="missing", dmarc="missing"))
        self.assertEqual(risk["score"], 85)
        self.assertEqual(risk["severity"], "Critical")

    def test_unknown_domain_age_is_not_counted_as_risk(self):
        risk = calculate_risk(*make_inputs(age=None))
        self.assertEqual(risk["score"], 0)
        self.assertFalse(risk["data_complete"])
        self.assertTrue(any("Domain age unknown" in n for n in risk["unknown"]))

    def test_failed_dmarc_lookup_is_unknown_not_missing(self):
        risk = calculate_risk(*make_inputs(
            dmarc="error", dmarc_error="DNS timeout while checking DMARC."))
        self.assertEqual(risk["score"], 0)
        self.assertFalse(risk["data_complete"])


if __name__ == "__main__":
    unittest.main()

    
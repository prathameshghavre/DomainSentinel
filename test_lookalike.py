"""test_lookalike.py - Offline tests for the look-alike check (no internet)."""

import unittest

from osint.lookalike import check_lookalike
from osint.risk_engine import calculate_risk
from test_osint import make_inputs


class TestLookalike(unittest.TestCase):
    def test_official_domains_are_not_flagged(self):
        for name in ["google.com", "mail.google.com", "google.co.in",
                     "paypal.com", "amazon.co.in"]:
            with self.subTest(name=name):
                self.assertEqual(check_lookalike(name)["points"], 0)

    def test_character_swap(self):
        cases = {"g00gle.com": "google", "paypa1.com": "paypal",
                 "rnicrosoft.com": "microsoft", "l1nkedin.com": "linkedin"}
        for name, brand in cases.items():
            with self.subTest(name=name):
                result = check_lookalike(name)
                self.assertEqual(result["suspected_brand"], brand)
                self.assertEqual(result["technique"], "Character swap")
                self.assertEqual(result["points"], 30)

    def test_typo_and_transposition(self):
        cases = {"gooogle.com": "google", "googel.com": "google",
                 "amazonn.com": "amazon"}
        for name, brand in cases.items():
            with self.subTest(name=name):
                result = check_lookalike(name)
                self.assertEqual(result["suspected_brand"], brand)
                self.assertEqual(result["technique"], "Typo of brand name")
                self.assertEqual(result["points"], 25)

    def test_hyphen_split(self):
        result = check_lookalike("pay-pal.com")
        self.assertEqual(result["suspected_brand"], "paypal")
        self.assertEqual(result["technique"], "Hyphens inserted")
        self.assertEqual(result["points"], 25)

    def test_brand_with_extra_words(self):
        cases = {"paypal-secure-login.com": "paypal",
                 "hdfcbank-login.com": "hdfcbank",
                 "secure-amazon.com": "amazon"}
        for name, brand in cases.items():
            with self.subTest(name=name):
                result = check_lookalike(name)
                self.assertEqual(result["suspected_brand"], brand)
                self.assertEqual(result["technique"], "Brand name with extra words")
                self.assertEqual(result["points"], 20)

    def test_brand_on_unofficial_domain(self):
        result = check_lookalike("paypal.xyz")
        self.assertEqual(result["technique"], "Brand name on a different domain")
        self.assertEqual(result["points"], 10)

    def test_unrelated_domains_are_not_flagged(self):
        for name in ["example.com", "pineapple-shop.com", "openai.com",
                     "wikipedia.org", "mycompany.in"]:
            with self.subTest(name=name):
                self.assertEqual(check_lookalike(name)["points"], 0)


class TestRiskWithLookalike(unittest.TestCase):
    def test_new_lookalike_domain_is_high(self):
        lookalike = check_lookalike("paypa1.com")
        risk = calculate_risk(*make_inputs(age=5), lookalike)
        self.assertEqual(risk["score"], 65)   # 35 (very new) + 30 (look-alike)
        self.assertEqual(risk["severity"], "High")

    def test_old_lookalike_domain_is_medium(self):
        lookalike = check_lookalike("paypa1.com")
        risk = calculate_risk(*make_inputs(), lookalike)
        self.assertEqual(risk["score"], 30)
        self.assertEqual(risk["severity"], "Medium")


if __name__ == "__main__":
    unittest.main()
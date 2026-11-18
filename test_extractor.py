"""test_extractor.py - Offline tests for domain extraction and header checks."""

import unittest

from osint.extractor import MAX_DOMAINS, analyze_headers, extract_domains


def names(result):
    return [item["domain"] for item in result["domains"]]


class TestExtractDomains(unittest.TestCase):
    def test_defanged_link_is_restored(self):
        result = extract_domains("Click hxxps://evil[.]com/login now")
        self.assertEqual(names(result), ["evil.com"])
        self.assertIn("link", result["domains"][0]["sources"])

    def test_email_address_domain(self):
        result = extract_domains("Write to support@paypa1.com")
        self.assertEqual(names(result), ["paypa1.com"])
        self.assertIn("email address", result["domains"][0]["sources"])

    def test_defanged_email(self):
        result = extract_domains("mail help[at]evil[.]com please")
        self.assertEqual(names(result), ["evil.com"])

    def test_plain_names_need_a_common_ending(self):
        result = extract_domains("see example.com and report.pdf")
        self.assertEqual(names(result), ["example.com"])

    def test_user_info_trick_uses_real_host(self):
        result = extract_domains("https://paypal.com@evil.com/x")
        self.assertEqual(names(result), ["evil.com"])

    def test_www_removed_and_duplicates_merged(self):
        result = extract_domains("https://www.example.com/a and http://example.com/b")
        self.assertEqual(names(result), ["example.com"])

    def test_limit_and_truncated_count(self):
        text = " ".join(f"https://site{i}.com" for i in range(20))
        result = extract_domains(text)
        self.assertEqual(len(result["domains"]), MAX_DOMAINS)
        self.assertEqual(result["truncated"], 20 - MAX_DOMAINS)

    def test_internal_and_ip_hosts_are_skipped(self):
        result = extract_domains("http://localhost/x http://192.168.1.1/x")
        self.assertEqual(names(result), [])


class TestHeaders(unittest.TestCase):
    def test_reply_to_mismatch_is_reported(self):
        text = "From: Bank <a@bank.com>\nReply-To: scam@evil.com\nSubject: hi"
        result = analyze_headers(text)
        self.assertEqual(result["domains"]["From"], "bank.com")
        self.assertEqual([f["header"] for f in result["findings"]], ["Reply-To"])

    def test_same_domain_has_no_findings(self):
        text = "From: A <a@x.com>\nReply-To: b@x.com"
        self.assertEqual(analyze_headers(text)["findings"], [])


if __name__ == "__main__":
    unittest.main()
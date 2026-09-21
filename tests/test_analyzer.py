"""Tests for the PhishScope analyzer heuristics."""

import unittest

from phishscope.analyzer import analyze, fold_homoglyphs, registered_domain
from phishscope.data import BRANDS


class CleanUrlTests(unittest.TestCase):
    def test_real_brand_domain_is_clean(self):
        report = analyze("https://www.paypal.com/signin")
        self.assertEqual(report.verdict, "CLEAN")
        self.assertEqual(report.score, 0)

    def test_multipart_tld_brand_domain_is_clean(self):
        report = analyze("https://www.paytm.co.in/offer")
        self.assertEqual(report.verdict, "CLEAN")
        self.assertFalse(report.is_suspicious)

    def test_localhost_is_clean(self):
        report = analyze("http://localhost:8000/dev")
        self.assertEqual(report.verdict, "CLEAN")  # local dev hosts are exempt


class LookalikeTests(unittest.TestCase):
    def test_brand_in_subdomain(self):
        report = analyze("https://paypal.com.evil.tk/verify")
        names = {f.name for f in report.flags}
        self.assertIn("brand-in-subdomain", names)
        self.assertGreaterEqual(report.score, 40)

    def test_embedded_brand_lookalike(self):
        report = analyze("https://secure-paypal.tk/login")
        names = {f.name for f in report.flags}
        self.assertIn("brand-lookalike-domain", names)

    def test_digit_homoglyph_impersonation(self):
        report = analyze("https://paypa1.com/login")
        names = {f.name for f in report.flags}
        self.assertIn("homoglyph-impersonation", names)
        self.assertGreaterEqual(report.score, 40)

    def test_unicode_homoglyph(self):
        # 'а' is Cyrillic, folds to 'paypal.com'
        report = analyze("https://pаypаl.com/login")
        names = {f.name for f in report.flags}
        self.assertTrue(names & {"homoglyph-impersonation", "non-ascii-host"})


class TrickTests(unittest.TestCase):
    def test_userinfo_at_trick(self):
        report = analyze("https://paypal.com@evil-example.tk/login")
        names = {f.name for f in report.flags}
        self.assertIn("userinfo-trick", names)
        self.assertIn("brand-in-userinfo", names)

    def test_punycode_host(self):
        report = analyze("https://xn--pypal-4ve.com/login")
        names = {f.name for f in report.flags}
        self.assertIn("punycode-host", names)

    def test_raw_ip_with_apk(self):
        report = analyze("http://203.0.113.9/files/kyc-update.apk")
        names = {f.name for f in report.flags}
        self.assertIn("raw-ip-host", names)
        self.assertIn("executable-download", names)
        self.assertIn("no-tls", names)
        self.assertEqual(report.verdict, "CRITICAL")

    def test_suspicious_tld(self):
        report = analyze("https://secure-login-verify.xyz/account/unlock")
        names = {f.name for f in report.flags}
        self.assertIn("suspicious-tld", names)
        self.assertIn("phishing-keyword", names)
        self.assertIn("hyphenated-domain", names)

    def test_url_shortener(self):
        report = analyze("https://bit.ly/3xYzAbc")
        names = {f.name for f in report.flags}
        self.assertIn("url-shortener", names)

    def test_deep_subdomains(self):
        report = analyze("https://a.b.c.d.evil-example.tk/login")
        names = {f.name for f in report.flags}
        self.assertIn("deep-subdomains", names)


class EdgeCaseTests(unittest.TestCase):
    def test_empty_input(self):
        report = analyze("")
        self.assertEqual(report.verdict, "CLEAN")

    def test_no_host(self):
        report = analyze("http://")
        self.assertEqual(report.verdict, "MEDIUM")
        self.assertTrue(report.is_suspicious)

    def test_score_is_clamped(self):
        report = analyze(
            "http://user:pw@203.0.113.9:8080/kyc-update.apk"
            "?q=free-recharge-cashback-claim-lottery-win"
        )
        self.assertLessEqual(report.score, 100)
        self.assertEqual(report.verdict, "CRITICAL")

    def test_json_round_trip(self):
        report = analyze("https://paypa1.com")
        d = report.to_dict()
        self.assertEqual(d["url"], "https://paypa1.com")
        self.assertIsInstance(d["flags"], list)


class HelperTests(unittest.TestCase):
    def test_fold_homoglyphs(self):
        self.assertEqual(fold_homoglyphs("Pаypa1.com"), "paypal.com")

    def test_registered_domain_multipart(self):
        self.assertEqual(registered_domain("www.paytm.co.in"), "paytm.co.in")
        self.assertEqual(registered_domain("paypal.com.evil.tk"), "evil.tk")

    def test_brand_list_has_india_brands(self):
        for brand in ("paytm", "phonepe", "hdfcbank", "aadhaar"):
            self.assertIn(brand, BRANDS)


if __name__ == "__main__":
    unittest.main()

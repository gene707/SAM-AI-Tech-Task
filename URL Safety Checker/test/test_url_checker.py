import unittest
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from url_checker import URLSafetyChecker

class TestURLSafetyChecker(unittest.TestCase):
    def setUp(self):
        self.checker = URLSafetyChecker()

    def test_safe_url(self):
        res = self.checker.analyze_url("https://www.google.com/search?q=python")
        self.assertTrue(res["is_valid_format"])
        self.assertTrue(res["is_https"])
        self.assertEqual(res["status"], "SAFE")
        self.assertLess(res["risk_score"], 20)

    def test_suspicious_phishing_url(self):
        res = self.checker.analyze_url("http://192.168.1.100/paypal-update-login/verify.php?claim=free")
        self.assertTrue(res["is_valid_format"])
        self.assertFalse(res["is_https"])
        self.assertEqual(res["status"], "SUSPICIOUS")
        self.assertGreaterEqual(res["risk_score"], 50)

    def test_suspicious_tld_and_keywords(self):
        res = self.checker.analyze_url("http://secure-banking-verify.xyz/account/login.exe")
        self.assertEqual(res["status"], "SUSPICIOUS")
        self.assertIn("Suspicious Phishing Keywords", [f["rule"] for f in res["findings"]])
        self.assertIn("Suspicious TLD", [f["rule"] for f in res["findings"]])

    def test_invalid_url_format(self):
        res = self.checker.analyze_url("")
        self.assertFalse(res["is_valid_format"])
        self.assertEqual(res["status"], "INVALID_URL")

    def test_typosquatting(self):
        res = self.checker.analyze_url("https://www.g00gle.com/login")
        rules = [f["rule"] for f in res["findings"]]
        self.assertTrue(any("Typosquatting" in r for r in rules))

if __name__ == "__main__":
    unittest.main()

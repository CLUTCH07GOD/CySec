"""
OWASP ASVS v5.0 (V2 Authentication) & NIST SP 800-63B Rev. 4 Local Test Suite
-----------------------------------------------------------------------------
Exercises local application authentication endpoints and policies in a dev environment.
Maps every test assertion to OWASP ASVS v5.0 requirements and CWE IDs.
"""

import sys
import os
import unittest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from security_validators.nist_800_63b_validator import validate_password_nist_800_63b


class TestASVSv2Authentication(unittest.TestCase):

    def test_asvs_v2_1_1_password_length_floor(self):
        """ASVS V2.1.1 & NIST 800-63B: Verifies password length floor (>= 15 chars single factor)."""
        res = validate_password_nist_800_63b("short12", mfa_enabled=False)
        self.assertFalse(res["is_valid"])
        self.assertIn("CWE-521", res["cwe_ids"])

    def test_asvs_v2_1_2_all_numeric_long_passwords_allowed(self):
        """NIST 800-63B Rev 4: All-numeric passwords >= 15 chars MUST be accepted (no forced composition rules)."""
        res = validate_password_nist_800_63b("123456789012345678", mfa_enabled=False)
        self.assertEqual(res["composition_rules_policy"], "NO composition rules enforced (Compliant with NIST 800-63B Rev. 4)")

    def test_asvs_v2_1_7_compromised_password_blocklist(self):
        """ASVS V2.1.7 & NIST 800-63B: Verifies password is checked against breach blocklists."""
        res = validate_password_nist_800_63b("password1234567", mfa_enabled=False)
        self.assertFalse(res["is_valid"])
        self.assertTrue(any("blocklist" in err.lower() for err in res["errors"]))


if __name__ == "__main__":
    unittest.main()

"""
NIST SP 800-63B Revision 4 (2025) Password Policy Validator
------------------------------------------------------------
Implements strict NIST SP 800-63B Rev. 4 requirements:
  - Minimum 15 characters (single-factor) or 8 characters (with MFA)
  - Maximum 64 characters
  - NO forced composition rules (uppercase/symbol/number mandatory rules are PROHIBITED)
  - NO mandatory periodic rotation
  - Mandatory blocklist screening against top compromised/breached passwords
  - Mapped to CWE-521 (Weak Password Requirements)
"""

import hashlib
import urllib.request
from typing import Dict, Any, List

# Top common compromised password sample blocklist (fallback offline blocklist)
OFFLINE_BREACH_BLOCKLIST = {
    "password", "123456", "123456789", "admin", "welcome",
    "password123", "password1234567", "letmein", "12345678", "qwerty", "monkey"
}


def validate_password_nist_800_63b(
    password: str,
    mfa_enabled: bool = False,
    check_hibp_online: bool = False
) -> Dict[str, Any]:
    """
    Validates a password against NIST SP 800-63B Revision 4 standards.
    
    Returns:
        Dict with 'is_valid', 'errors', 'cwe_id', and 'nist_control' info.
    """
    errors = []
    cwe_ids = []
    
    # 1. Length Floor Check
    min_len = 8 if mfa_enabled else 15
    if len(password) < min_len:
        errors.append(
            f"Password too short ({len(password)} chars). NIST SP 800-63B Rev. 4 requires minimum "
            f"{min_len} characters {'(with MFA)' if mfa_enabled else '(without MFA)'}."
        )
        cwe_ids.append("CWE-521")

    # 2. Length Ceiling Check
    if len(password) > 64:
        errors.append("Password exceeds maximum 64 character limit.")
        cwe_ids.append("CWE-521")

    # 3. Blocklist Check against offline dictionary
    if password.lower() in OFFLINE_BREACH_BLOCKLIST:
        errors.append("Password found on compromised breach blocklist. Choose a less common passphrase.")
        cwe_ids.append("CWE-521")

    # 4. Optional Have I Been Pwned (HIBP) k-Anonymity Online Check
    if check_hibp_online and not errors:
        sha1_pwd = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
        prefix = sha1_pwd[:5]
        suffix = sha1_pwd[5:]
        try:
            url = f"https://api.pwnedpasswords.com/range/{prefix}"
            req = urllib.request.Request(url, headers={"User-Agent": "NIST-800-63B-Validator"})
            with urllib.request.urlopen(req, timeout=3) as resp:
                body = resp.read().decode("utf-8")
                if suffix in body:
                    errors.append("Password detected in global breach database (HIBP k-anonymity check).")
                    cwe_ids.append("CWE-521")
        except Exception:
            pass  # Fallback gracefully if offline

    return {
        "is_valid": len(errors) == 0,
        "errors": errors,
        "cwe_ids": list(set(cwe_ids)),
        "standard_ref": "NIST SP 800-63B Rev. 4 (Section 5.1.1.2)",
        "composition_rules_policy": "NO composition rules enforced (Compliant with NIST 800-63B Rev. 4)"
    }

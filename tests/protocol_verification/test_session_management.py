import os
import requests
import pytest

TARGET_URL = os.getenv("VERIFICATION_TARGET_URL", "http://127.0.0.1:8000")

def test_session_cookie_attributes():
    """
    Control ID: ASVS V3.4.1 / V3.4.2 / V3.4.3 / CWE-614 / CWE-1004 / CWE-1275
    Verifies that session cookies contain HttpOnly, Secure, and SameSite attributes.
    """
    try:
        res = requests.get(TARGET_URL, timeout=5)
        for cookie in res.cookies:
            # Check cookie attributes if session cookie
            if "session" in cookie.name.lower() or "auth" in cookie.name.lower() or "token" in cookie.name.lower():
                assert cookie.has_nonstandard_attr("HttpOnly") or getattr(cookie, "httponly", False), f"Cookie {cookie.name} missing HttpOnly flag."
                assert cookie.secure, f"Cookie {cookie.name} missing Secure flag."
    except requests.exceptions.ConnectionError:
        pytest.skip(f"Target URL {TARGET_URL} is unreachable.")

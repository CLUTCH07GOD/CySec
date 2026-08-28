import os
import requests
import pytest

TARGET_URL = os.getenv("VERIFICATION_TARGET_URL", "http://127.0.0.1:8000")

def test_protected_routes_access_control():
    """
    Control ID: ASVS V4.1.1 / PR.AC-01
    Verifies that protected routes return 401/403 when accessed without authentication headers.
    """
    protected_endpoints = [
        f"{TARGET_URL.rstrip('/')}/api/v1/admin",
        f"{TARGET_URL.rstrip('/')}/api/v1/user/profile",
    ]
    
    for endpoint in protected_endpoints:
        try:
            res = requests.get(endpoint, timeout=5)
            assert res.status_code in [401, 403], f"Unauthenticated request to {endpoint} returned status {res.status_code} instead of 401/403."
        except requests.exceptions.ConnectionError:
            pytest.skip(f"Target URL {TARGET_URL} is unreachable.")

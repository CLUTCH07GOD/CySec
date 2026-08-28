import os
import requests
import pytest

TARGET_URL = os.getenv("VERIFICATION_TARGET_URL", "http://127.0.0.1:8000")

def test_password_policy_nist_800_63b():
    """
    Control ID: SP_800_63B_R4-REQ-021 / ASVS V2.1.1 / PR.AA-01
    Tests password policy enforcement (rejecting short passwords <8 chars, accepting passphrases >=15 chars).
    """
    candidate_endpoints = [
        f"{TARGET_URL.rstrip('/')}/api/v1/auth/password-check",
        f"{TARGET_URL.rstrip('/')}/v1/auth/login",
        f"{TARGET_URL.rstrip('/')}/api/v1/users",
        f"{TARGET_URL.rstrip('/')}/auth/register"
    ]
    
    active_endpoint = None
    for ep in candidate_endpoints:
        try:
            res = requests.options(ep, timeout=2)
            if res.status_code != 404:
                active_endpoint = ep
                break
        except Exception:
            continue
            
    if not active_endpoint:
        pytest.skip(f"No password policy endpoint active on {TARGET_URL}. Dynamic probe skipped (NO_DATA).")
        return

    try:
        res_short = requests.post(active_endpoint, json={"password": "short"}, timeout=5)
        res_valid = requests.post(active_endpoint, json={"password": "this_is_a_very_long_valid_passphrase_15"}, timeout=5)
        
        assert res_short.status_code in [400, 422], f"Short password (<8 chars) unexpectedly accepted at {active_endpoint}."
        assert res_valid.status_code in [200, 201, 204], f"Valid passphrase rejected at {active_endpoint}."
    except requests.exceptions.ConnectionError:
        pytest.skip(f"Target URL {TARGET_URL} is unreachable. Status: NO_DATA.")

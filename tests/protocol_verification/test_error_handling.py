import os
import requests
import pytest

TARGET_URL = os.getenv("VERIFICATION_TARGET_URL", "http://127.0.0.1:8000")

def test_malformed_input_error_handling():
    """
    Control ID: CWE-209 / DE.CM-1 / ASVS V14.3.1
    Verifies that malformed JSON input triggers generic errors without leaking sensitive stack traces or environment details.
    """
    endpoint = f"{TARGET_URL.rstrip('/')}/api/v1/data"
    try:
        headers = {"Content-Type": "application/json"}
        res = requests.post(endpoint, data="invalid_json_payload_{", headers=headers, timeout=5)
        
        body = res.text.lower()
        leaks = ["traceback (most recent call last)", "syntaxerror", "environment", "secret_key", "password"]
        for leak in leaks:
            assert leak not in body, f"Potential information leak detected in error response: '{leak}' found."
    except requests.exceptions.ConnectionError:
        pytest.skip(f"Target URL {TARGET_URL} is unreachable.")

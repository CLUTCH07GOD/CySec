"""
Tests for Framework-Driven Browser Testing Guide & Playwright Prober
---------------------------------------------------------------------
Validates that framework_browser_testing_guide.json schema parses correctly
and that agent_y_browser_prober.py produces mapped security findings.
"""

import os
import json
import pytest
import asyncio
from agent_y_browser_prober import load_testing_guide, probe_url_with_browser, DEFAULT_GUIDE_FILE


VALID_ACTIONS = {
    "navigate", "navigate_path", "inspect_headers", "inspect_cookies",
    "inspect_local_storage", "inspect_session_storage", "inspect_inputs",
    "inspect_password_fields", "inspect_forms", "inspect_meta_tags",
    "inspect_cors", "check_console_errors", "check_robots_txt",
    "check_security_txt", "probe_error_page"
}


def test_framework_testing_guide_schema():
    """Validates that framework_browser_testing_guide.json is present and properly structured."""
    assert os.path.exists(DEFAULT_GUIDE_FILE), f"Missing testing guide file: {DEFAULT_GUIDE_FILE}"
    
    guide = load_testing_guide(DEFAULT_GUIDE_FILE)
    assert "test_suites" in guide, "Guide missing 'test_suites' array"
    assert len(guide["test_suites"]) >= 5, "Guide must contain at least 5 test suites for production coverage"

    for suite in guide["test_suites"]:
        assert "suite_id" in suite, "Suite missing suite_id"
        assert "framework" in suite, "Suite missing framework label"
        assert "steps" in suite and len(suite["steps"]) > 0, f"Suite '{suite['suite_id']}' has no steps"

        for step in suite["steps"]:
            assert "action" in step, f"Step missing 'action' in suite '{suite['suite_id']}'"
            assert step["action"] in VALID_ACTIONS, f"Unknown action '{step['action']}' in suite '{suite['suite_id']}'"


def test_guide_control_id_coverage():
    """Validates that all steps have control_id mappings for regulatory traceability."""
    guide = load_testing_guide(DEFAULT_GUIDE_FILE)
    control_ids = set()
    for suite in guide["test_suites"]:
        if "control_id" in suite:
            control_ids.add(suite["control_id"])
        for step in suite.get("steps", []):
            if "control_id" in step:
                control_ids.add(step["control_id"])

    # Verify minimum control coverage across OWASP WSTG, ASVS, and NIST
    assert len(control_ids) >= 10, f"Insufficient control ID coverage: {len(control_ids)} (minimum 10 required)"
    
    # Verify presence of critical control families
    all_ids = " ".join(control_ids)
    assert "WSTG" in all_ids, "Missing OWASP WSTG control mappings"


def test_browser_prober_execution_with_guide():
    """Runs Playwright prober against test target using framework testing guide."""
    findings = asyncio.run(probe_url_with_browser(
        target_url="http://127.0.0.1:8000",
        guide_path=DEFAULT_GUIDE_FILE
    ))
    
    assert isinstance(findings, list)
    control_ids = {f.get("control_id") for f in findings if "control_id" in f}
    assert len(control_ids) > 0, "No control IDs mapped in findings"

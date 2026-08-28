"""
Unit & Integration Tests for Robustness & Governance Engine
"""

import os
import pytest
import robustness_governance as rg


def test_human_in_the_loop_review_gate():
    report_id = "REP_TEST_1001"
    client_id = "acme_corp"
    frameworks = ["eu/gdpr", "nist/csf"]

    submitted = rg.submit_report_for_human_review(
        report_id=report_id,
        client_id=client_id,
        frameworks=frameworks,
        report_markdown="# Test Report",
        auto_verdict="PASS"
    )
    assert submitted["human_review_status"] == "PENDING_EXPERT_SIGN_OFF"

    # Expert Auditor approves
    signed = rg.execute_human_sign_off(
        report_id=report_id,
        expert_auditor="Auditor_CISA_101",
        approved=True,
        expert_notes="All control evidence validated."
    )
    assert signed["human_review_status"] == "APPROVED_BY_EXPERT"
    assert signed["expert_auditor"] == "Auditor_CISA_101"


def test_hallucination_and_error_rate_eval():
    eval_res = rg.evaluate_hallucination_and_error_rate()
    assert "verdict_accuracy_pct" in eval_res
    assert "hallucination_error_rate_pct" in eval_res
    assert eval_res["verdict_accuracy_pct"] == 100.0


def test_mlops_adapter_lineage():
    entry = rg.log_adapter_run_lineage(
        report_id="REP_TEST_1001",
        client_id="acme_corp",
        framework="eu/gdpr",
        adapter_name="qwen3-gdpr-lora",
        adapter_version="v1.2.0"
    )
    assert entry["adapter_name"] == "qwen3-gdpr-lora"
    assert entry["adapter_version"] == "v1.2.0"


def test_standards_licensing_governance():
    pci_lic = rg.verify_standards_licensing("pci_dss")
    gdpr_lic = rg.verify_standards_licensing("eu/gdpr")

    assert pci_lic["status"] == "PUBLIC_SUMMARY_ONLY"
    assert gdpr_lic["status"] == "APPROVED_OPEN"

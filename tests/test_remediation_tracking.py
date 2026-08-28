"""
Unit & Integration Tests for Reporting, Remediation Tracking, and Evidence Confidence Indicators
"""

import os
import pytest
import remediation_tracker_engine as rte
import adapter_classification as ac


def test_remediation_tracking_lifecycle():
    client_id = "test_client_rem"
    framework = "eu/gdpr"

    # Clean up stale state from prior test runs
    rem_file = rte._get_remediation_file(client_id)
    if os.path.exists(rem_file):
        os.remove(rem_file)

    dummy_assessment = [
        {"control_id": "ART-5", "title": "Data Protection", "status": "Not Compliant", "evidence_similarity": 0.85},
        {"control_id": "ART-32", "title": "Security of Processing", "status": "Partially Compliant", "evidence_similarity": 0.55},
    ]

    synced = rte.sync_assessment_remediations(client_id, framework, dummy_assessment)
    assert len(synced) == 2
    assert synced[0]["evidence_strength"] == "🟢 HIGH CONFIDENCE"
    assert synced[1]["evidence_strength"] == "🔴 LOW CONFIDENCE"
    assert synced[0]["remediation_state"] == "open"

    # Update state to in_progress
    item_key = f"{framework}__ART-5"
    updated = rte.update_remediation_status(
        client_id=client_id,
        item_key=item_key,
        new_state="in_progress",
        owner="Security Lead",
        notes="Encryption patch in progress"
    )
    assert updated["remediation_state"] == "in_progress"
    assert updated["owner"] == "Security Lead"


def test_consolidated_report_pass_fail_matrix():
    dummy_assessments = {
        "eu/gdpr": [
            {"control_id": "ART-5", "title": "Data Protection Principles", "status": "Compliant", "evidence_similarity": 0.90},
            {"control_id": "ART-32", "title": "Security", "status": "Compliant", "evidence_similarity": 0.85},
        ],
        "india/dpdp": [
            {"control_id": "DPDP-8", "title": "Data Fiduciary Duties", "status": "Not Compliant", "evidence_similarity": 0.40},
        ]
    }
    report_md = ac.generate_consolidated_report_markdown("TestApp", dummy_assessments)
    assert "Per-Framework Pass/Fail Compliance Matrix" in report_md
    assert "🟢 PASS (>=80%)" in report_md
    assert "🔴 FAIL (<60%)" in report_md
    assert "Evidence Strength & Confidence" in report_md

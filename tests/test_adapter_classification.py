"""
Unit & Integration Tests for Adapter Classification & Selection
"""

import pytest
import adapter_classification
import compliance_jurisdictions
import agents.agent5_report_generation as agent5


def test_metadata_extension():
    catalog = adapter_classification.sync_and_extend_adapter_metadata()
    assert len(catalog) > 0
    assert "qwen3-gdpr-lora" in catalog
    assert "jurisdiction" in catalog["qwen3-gdpr-lora"]
    assert "control_domains" in catalog["qwen3-gdpr-lora"]


def test_recommendation_algorithm():
    res = adapter_classification.recommend_adapters(
        operating_countries=["eu", "germany"],
        industry_vertical="fintech",
        application_type="web_app",
        required_control_domains=["access_control", "data_protection_and_privacy"]
    )
    assert "recommended_adapters" in res
    frameworks = [r["framework"] for r in res["recommended_adapters"]]
    assert "eu/gdpr" in frameworks


def test_manual_override():
    res = adapter_classification.recommend_adapters(
        operating_countries=["us"],
        industry_vertical="general_saas",
        manual_overrides=["qwen3-dpdp-lora"]
    )
    overrides = [r for r in res["recommended_adapters"] if r["is_manual_override"]]
    assert len(overrides) > 0
    assert overrides[0]["adapter_name"] == "qwen3-dpdp-lora"


def test_consolidated_report_generation():
    dummy_assessments = {
        "eu/gdpr": [
            {"control_id": "ART-5", "title": "Data Protection Principles", "status": "Compliant", "explanation": "Pass", "evidence_source": "Vault"}
        ],
        "eu/nis2": [
            {"control_id": "NIS2-SEC-1", "title": "Incident Management", "status": "Not Compliant", "explanation": "Missing plan", "evidence_source": "Vault", "remediation": "Create plan"}
        ]
    }
    report_md = adapter_classification.generate_consolidated_report_markdown(
        client_name="TestFintechApp",
        assessments_by_framework=dummy_assessments
    )
    assert "# ComplianceMesh — Consolidated Multi-Framework Compliance Report" in report_md
    assert "TestFintechApp" in report_md
    assert "EU/GDPR" in report_md
    assert "EU/NIS2" in report_md

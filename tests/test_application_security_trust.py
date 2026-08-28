"""
Unit & Integration Tests for Security, Trust Posture & Multi-Tenancy Isolation
"""

import os
import shutil
import pytest
import application_security_trust as ast


def test_tenant_vault_isolation():
    tenant_a = "tenant_alpha"
    tenant_b = "tenant_beta"
    dir_a = ast.get_tenant_vault_dir(tenant_a)
    dir_b = ast.get_tenant_vault_dir(tenant_b)

    assert os.path.exists(dir_a)
    assert os.path.exists(dir_b)
    assert dir_a != dir_b

    # Verify cross-tenant access denial
    file_a = os.path.join(dir_a, "documents", "confidential.pdf")
    assert ast.verify_tenant_access(tenant_a, file_a) is True
    assert ast.verify_tenant_access(tenant_b, file_a) is False


def test_immutable_hash_chained_audit_logging():
    tenant = "tenant_audit_test"
    entry1 = ast.log_security_event(tenant, "FILE_UPLOAD", "auditor1", "vault/doc1.pdf")
    entry2 = ast.log_security_event(tenant, "RUN_ASSESSMENT", "auditor1", "nist/csf")

    assert entry1["previous_hash"] is not None
    assert entry2["previous_hash"] == entry1["record_hash"]
    assert len(entry1["record_hash"]) == 64  # SHA-256 hash length

    logs = ast.get_tenant_audit_trail(tenant)
    assert len(logs) >= 2


def test_legal_agreements_recording():
    tenant = "tenant_legal_test"
    saved = ast.save_tenant_legal_agreements(
        tenant_id=tenant,
        signed_by="Jane Doe",
        nda_signed=True,
        dpa_signed=True,
        mode_b_authorized=True,
    )
    assert saved["nda_signed"] is True
    assert saved["dpa_signed"] is True
    assert saved["mode_b_execution_authorized"] is True

    fetched = ast.get_tenant_legal_agreement_status(tenant)
    assert fetched["signed_by"] == "Jane Doe"


def test_gdpr_data_erasure():
    tenant = "tenant_erasure_test"
    v_dir = ast.get_tenant_vault_dir(tenant)
    dummy_file = os.path.join(v_dir, "documents", "test.txt")
    with open(dummy_file, "w") as f:
        f.write("test content")

    res = ast.execute_gdpr_data_deletion(tenant)
    assert res["status"] == "SUCCESS"
    assert not os.path.exists(dummy_file)

# Compliance Standards & Verification Guidelines Directory

This directory stores authoritative security standards, technical verification guides, and vulnerability taxonomies used by **Agent 0** and the **Compliance Engine**.

---

## 📁 Directory Structure & File Placement Guide

### 1. `compliance_standards_docs/nist_sp_800_63b/`
* **What to insert:** PDF or Markdown copies of **NIST SP 800-63B Revision 4 (2025)** (*Digital Identity Guidelines: Authentication and Lifecycle Management*).
* **Accepted Formats:** `NIST_SP_800_63B_r4.pdf`, `NIST_800_63B.md`, `NIST_800_63B.txt`
* **Purpose:** Provides password rules (15+ chars without MFA, 8+ with MFA, compromised password blocklist screening, prohibition of forced composition rules).

### 2. `compliance_standards_docs/owasp_asvs_v5/`
* **What to insert:** PDF or Markdown copies of **OWASP Application Security Verification Standard (ASVS) v5.0**.
* **Accepted Formats:** `OWASP_ASVS_v5.pdf`, `ASVS_v5.md`, `ASVS_v5.txt`
* **Purpose:** Provides testable technical requirements across 14 sections (V1 Architecture to V14 Config) mapped directly to CWE IDs.

### 3. `compliance_standards_docs/owasp_wstg/`
* **What to insert:** PDF or Markdown copies of **OWASP Web Security Testing Guide (WSTG)**.
* **Accepted Formats:** `OWASP_WSTG_v4.2.pdf`, `WSTG.md`, `WSTG.txt`
* **Purpose:** Defines step-by-step test procedures (e.g. `WSTG-AUTHN-01` for password policy testing) executed during dynamic sandboxed audits.

### 4. `compliance_standards_docs/cwe_taxonomy/`
* **What to insert:** MITRE Common Weakness Enumeration (CWE) reference lists or JSON dictionaries.
* **Accepted Formats:** `cwe_list.json`, `cwe_taxonomy.txt`
* **Purpose:** Provides standardized weakness IDs (`CWE-521`, `CWE-307`, `CWE-209`) for gap reporting in the compliance audit report.

---

## ⚡ How Agent 0 Auto-Ingests These Documents

Once you place your `.pdf` or `.md` files inside these folders:
1. Run **Agent 0** via UI or CLI:
   ```bash
   python agents/agent0_master_orchestrator.py --file compliance_standards_docs/nist_sp_800_63b/NIST_SP_800_63B_r4.pdf --jurisdiction nist --framework 800_63b
   ```
2. Agent 0 will automatically parse the text, generate vector embeddings in `chroma_db_controls/`, compute cross-framework mappings, and update the live compliance report engine!

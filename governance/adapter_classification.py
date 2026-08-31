"""
Adapter Classification & Selection Registry
-------------------------------------------
Provides a multi-axis classification taxonomy for LoRA adapters and frameworks,
extending adapter metadata, multi-attribute recommendation algorithms, manual override logic,
and multi-framework consolidated audit report generation for Agent 5.
"""

import os
import re
import glob
import json
from datetime import datetime
from typing import Dict, List, Any, Optional

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ADAPTERS_DIR = os.path.join(PROJECT_ROOT, "adapters")
STRUCTURED_CONTROLS_DIR = os.path.join(PROJECT_ROOT, "structured_controls")
REPORTS_DIR = os.path.join(PROJECT_ROOT, "reports")

# -----------------------------------------------------------------------------
# Multi-Axis Taxonomy Definitions
# -----------------------------------------------------------------------------
FRAMEWORK_AXIS = {
    "nist_csf": "NIST CSF 2.0",
    "nist_cloud": "NIST Cloud SP 800-145",
    "nist_zero_trust": "NIST Zero Trust SP 800-207",
    "nist_iot": "NIST IoT SP 800-213",
    "nist_ai_rmf": "NIST AI RMF 1.0",
    "nist_800_63b": "NIST SP 800-63B Authentication",
    "gdpr": "EU GDPR",
    "nis2": "EU NIS2 Directive",
    "dpdp": "India DPDP Act 2023",
    "cert_in": "India CERT-In Directives",
    "iso27001": "ISO/IEC 27001:2022",
    "hipaa": "US HIPAA Security & Privacy",
    "pci_dss": "PCI-DSS v4.0",
    "owasp_asvs": "OWASP ASVS v5",
    "owasp_wstg": "OWASP WSTG v4.2",
    "cwe": "CWE Top 25 Vulnerabilities",
}

INDUSTRY_VERTICALS = [
    "fintech",
    "healthcare",
    "e-commerce",
    "saas",
    "general_saas",
    "government",
    "critical_infrastructure",
    "iot_hardware",
    "ai_ml",
]

CONTROL_DOMAINS = [
    "access_control",
    "identity_and_authentication",
    "data_protection_and_privacy",
    "incident_response",
    "cloud_and_infrastructure_security",
    "cryptography_and_encryption",
    "application_security_and_devsecops",
    "governance_and_risk_management",
    "ai_safety_and_ethics",
]

JURISDICTION_MAP = {
    "india": ["India"],
    "in": ["India"],
    "eu": ["EU"],
    "germany": ["EU"],
    "france": ["EU"],
    "netherlands": ["EU"],
    "ireland": ["EU"],
    "spain": ["EU"],
    "italy": ["EU"],
    "uk": ["EU"],
    "us": ["US"],
    "usa": ["US"],
    "united states": ["US"],
    "international": ["International"],
    "global": ["India", "EU", "US", "International"],
}

# -----------------------------------------------------------------------------
# Core Adapter Metadata Classification Registry
# -----------------------------------------------------------------------------
DEFAULT_ADAPTER_CLASSIFICATION: Dict[str, Dict[str, Any]] = {
    "qwen3-csf-lora": {
        "adapter_name": "qwen3-csf-lora",
        "framework": "nist/csf",
        "short_code": "NIST CSF",
        "jurisdiction": ["US", "International"],
        "industry_verticals": ["general_saas", "fintech", "healthcare", "critical_infrastructure", "saas"],
        "control_domains": ["governance_and_risk_management", "access_control", "incident_response", "data_protection_and_privacy"],
        "application_types": ["web_app", "cloud_native", "api_service", "enterprise_software"],
        "description": "NIST Cybersecurity Framework 2.0 governance and cybersecurity controls."
    },
    "qwen3-gdpr-lora": {
        "adapter_name": "qwen3-gdpr-lora",
        "framework": "eu/gdpr",
        "short_code": "GDPR",
        "jurisdiction": ["EU", "International"],
        "industry_verticals": ["fintech", "healthcare", "e-commerce", "general_saas", "saas"],
        "control_domains": ["data_protection_and_privacy", "access_control", "incident_response"],
        "application_types": ["web_app", "mobile_app", "cloud_native", "api_service"],
        "description": "EU General Data Protection Regulation data privacy & protection controls."
    },
    "qwen3-dpdp-lora": {
        "adapter_name": "qwen3-dpdp-lora",
        "framework": "india/dpdp",
        "short_code": "DPDP",
        "jurisdiction": ["India"],
        "industry_verticals": ["fintech", "healthcare", "e-commerce", "general_saas", "saas"],
        "control_domains": ["data_protection_and_privacy", "access_control", "incident_response"],
        "application_types": ["web_app", "mobile_app", "cloud_native", "api_service"],
        "description": "India Digital Personal Data Protection Act 2023 requirements."
    },
    "qwen3-nis2-lora": {
        "adapter_name": "qwen3-nis2-lora",
        "framework": "eu/nis2",
        "short_code": "NIS2",
        "jurisdiction": ["EU"],
        "industry_verticals": ["fintech", "healthcare", "critical_infrastructure", "cloud_infrastructure", "saas"],
        "control_domains": ["incident_response", "cloud_and_infrastructure_security", "governance_and_risk_management", "access_control"],
        "application_types": ["cloud_native", "api_service", "critical_system"],
        "description": "EU Network & Information Security Directive 2 requirements."
    },
    "qwen3-iso27001-lora": {
        "adapter_name": "qwen3-iso27001-lora",
        "framework": "international/iso27001",
        "short_code": "ISO 27001",
        "jurisdiction": ["International", "US", "EU", "India"],
        "industry_verticals": ["fintech", "healthcare", "general_saas", "saas", "e-commerce", "critical_infrastructure"],
        "control_domains": ["governance_and_risk_management", "access_control", "cryptography_and_encryption", "incident_response"],
        "application_types": ["web_app", "cloud_native", "enterprise_software", "api_service"],
        "description": "ISO/IEC 27001:2022 Information Security Management System controls."
    },
    "qwen3-cloud-lora": {
        "adapter_name": "qwen3-cloud-lora",
        "framework": "nist/cloud",
        "short_code": "NIST Cloud",
        "jurisdiction": ["US", "International"],
        "industry_verticals": ["general_saas", "saas", "fintech", "healthcare"],
        "control_domains": ["cloud_and_infrastructure_security", "access_control", "data_protection_and_privacy"],
        "application_types": ["cloud_native", "api_service", "saas_platform"],
        "description": "NIST SP 800-145 Cloud Computing Security."
    },
    "qwen3-zerotrust-lora": {
        "adapter_name": "qwen3-zerotrust-lora",
        "framework": "nist/zero_trust",
        "short_code": "NIST Zero Trust",
        "jurisdiction": ["US", "International"],
        "industry_verticals": ["fintech", "healthcare", "government", "general_saas", "saas"],
        "control_domains": ["access_control", "identity_and_authentication", "cloud_and_infrastructure_security"],
        "application_types": ["web_app", "cloud_native", "api_service", "enterprise_software"],
        "description": "NIST SP 800-207 Zero Trust Architecture."
    },
    "qwen3-iot-lora": {
        "adapter_name": "qwen3-iot-lora",
        "framework": "nist/iot",
        "short_code": "NIST IoT",
        "jurisdiction": ["US", "International"],
        "industry_verticals": ["iot_hardware", "critical_infrastructure", "healthcare"],
        "control_domains": ["access_control", "cryptography_and_encryption", "cloud_and_infrastructure_security"],
        "application_types": ["embedded_iot", "firmware", "connected_device"],
        "description": "NIST SP 800-213 IoT Device Cybersecurity Guidance."
    },
    "qwen3-nistairmf-lora": {
        "adapter_name": "qwen3-nistairmf-lora",
        "framework": "us/nist_ai_rmf",
        "short_code": "NIST AI RMF",
        "jurisdiction": ["US", "International"],
        "industry_verticals": ["ai_ml", "fintech", "healthcare", "general_saas"],
        "control_domains": ["ai_safety_and_ethics", "governance_and_risk_management", "data_protection_and_privacy"],
        "application_types": ["ai_ml_system", "llm_app", "decision_engine"],
        "description": "NIST Artificial Intelligence Risk Management Framework 1.0."
    },
    "qwen3-80063br4-lora": {
        "adapter_name": "qwen3-80063br4-lora",
        "framework": "nist/sp_800_63b_r4",
        "short_code": "NIST 800-63B",
        "jurisdiction": ["US", "International"],
        "industry_verticals": ["fintech", "healthcare", "government", "general_saas", "saas"],
        "control_domains": ["identity_and_authentication", "access_control"],
        "application_types": ["web_app", "mobile_app", "api_service"],
        "description": "NIST SP 800-63B Digital Identity & Authentication Guidelines."
    },
    "qwen3-asvsv5-lora": {
        "adapter_name": "qwen3-asvsv5-lora",
        "framework": "owasp/asvs_v5",
        "short_code": "OWASP ASVS",
        "jurisdiction": ["International", "US", "EU", "India"],
        "industry_verticals": ["fintech", "healthcare", "general_saas", "saas", "e-commerce"],
        "control_domains": ["application_security_and_devsecops", "access_control", "cryptography_and_encryption"],
        "application_types": ["web_app", "api_service", "mobile_backend"],
        "description": "OWASP Application Security Verification Standard v5."
    },
    "qwen3-wstgv42-lora": {
        "adapter_name": "qwen3-wstgv42-lora",
        "framework": "owasp/wstg_v42",
        "short_code": "OWASP WSTG",
        "jurisdiction": ["International", "US", "EU", "India"],
        "industry_verticals": ["fintech", "healthcare", "general_saas", "saas"],
        "control_domains": ["application_security_and_devsecops", "access_control"],
        "application_types": ["web_app", "api_service"],
        "description": "OWASP Web Security Testing Guide v4.2."
    },
    "qwen3-cwev4-lora": {
        "adapter_name": "qwen3-cwev4-lora",
        "framework": "cwe/v4",
        "short_code": "CWE Top 25",
        "jurisdiction": ["International", "US", "EU"],
        "industry_verticals": ["fintech", "general_saas", "saas", "healthcare"],
        "control_domains": ["application_security_and_devsecops"],
        "application_types": ["web_app", "api_service", "embedded_iot"],
        "description": "Common Weakness Enumeration Top 25 Software Weaknesses."
    },
}


def llm_classify_adapter(adapter_name: str, sample_text: str = "") -> Dict[str, Any]:
    """
    Automated LLM Classifier:
    Uses LLM (Qwen) to dynamically infer jurisdiction, industry verticals,
    control domains, and application types for unknown/newly trained adapters.
    """
    try:
        import agents.config as cfg
        prompt = (
            f"You are a cybersecurity compliance taxonomy expert.\n"
            f"Analyze the following adapter/framework name and sample content and output ONLY a raw JSON dictionary classification with keys:\n"
            f"- 'jurisdiction': list of strings (e.g. ['US', 'EU', 'India', 'International'])\n"
            f"- 'industry_verticals': list of strings (choose from: fintech, healthcare, e-commerce, saas, general_saas, government, critical_infrastructure, iot_hardware, ai_ml)\n"
            f"- 'control_domains': list of strings (choose from: access_control, identity_and_authentication, data_protection_and_privacy, incident_response, cloud_and_infrastructure_security, cryptography_and_encryption, application_security_and_devsecops, governance_and_risk_management, ai_safety_and_ethics)\n"
            f"- 'application_types': list of strings (choose from: web_app, cloud_native, api_service, mobile_app, enterprise_software, ai_ml_system, embedded_iot)\n"
            f"- 'description': short 1-sentence summary\n\n"
            f"Adapter Name: {adapter_name}\n"
            f"Sample Content: {sample_text[:500]}\n"
            f"Return JSON ONLY:"
        )
        res_text = cfg.generate(prompt, max_new_tokens=250)
        json_match = re.search(r"\{.*\}", res_text, re.DOTALL)
        if json_match:
            parsed = json.loads(json_match.group(0))
            if isinstance(parsed, dict) and "jurisdiction" in parsed:
                return parsed
    except Exception as exc:
        pass

    # Heuristic fallback if LLM JSON parsing is unvailable
    fw_slug = adapter_name.replace("qwen3-", "").replace("-lora", "").lower()
    return {
        "jurisdiction": ["India"] if "dpdp" in fw_slug else (["EU"] if "gdpr" in fw_slug or "nis2" in fw_slug else ["US", "International"]),
        "industry_verticals": ["fintech", "general_saas"] if any(k in fw_slug for k in ["csf", "gdpr", "dpdp", "asvs", "iso"]) else ["general_saas"],
        "control_domains": ["access_control", "data_protection_and_privacy"],
        "application_types": ["web_app", "cloud_native", "api_service"],
        "description": f"Automated classification for {adapter_name}"
    }


def sync_and_extend_adapter_metadata(use_llm: bool = True) -> Dict[str, Dict[str, Any]]:
    """
    Scans adapters/ directory and writes or extends metadata.json inside each adapter folder.
    Uses predefined catalog or automated LLM classification for missing/new adapters.
    Returns the loaded classification catalog.
    """
    catalog = {}
    adapter_dirs = glob.glob(os.path.join(ADAPTERS_DIR, "*"))

    for ad_path in adapter_dirs:
        if not os.path.isdir(ad_path) or os.path.basename(ad_path).startswith("_"):
            continue

        folder_name = os.path.basename(ad_path)
        meta_file = os.path.join(ad_path, "metadata.json")

        existing_meta = {}
        if os.path.exists(meta_file):
            try:
                with open(meta_file, "r", encoding="utf-8") as f:
                    existing_meta = json.load(f)
            except Exception:
                existing_meta = {}

        # Default classification lookup or dynamic fallback / LLM automatic classification
        if folder_name in DEFAULT_ADAPTER_CLASSIFICATION:
            default_info = DEFAULT_ADAPTER_CLASSIFICATION[folder_name]
        elif existing_meta and "industry_verticals" in existing_meta and "control_domains" in existing_meta:
            default_info = existing_meta
        else:
            sample_txt = ""
            sample_file = os.path.join(ad_path, "adapter_config.json")
            if os.path.exists(sample_file):
                with open(sample_file, "r", encoding="utf-8", errors="ignore") as f:
                    sample_txt = f.read(500)
            llm_info = llm_classify_adapter(folder_name, sample_txt) if use_llm else {}
            default_info = {
                "adapter_name": folder_name,
                "framework": folder_name.replace("qwen3-", "").replace("-lora", ""),
                "short_code": folder_name.replace("qwen3-", "").replace("-lora", "").upper(),
                "jurisdiction": llm_info.get("jurisdiction", ["International"]),
                "industry_verticals": llm_info.get("industry_verticals", ["general_saas"]),
                "control_domains": llm_info.get("control_domains", ["access_control", "data_protection_and_privacy"]),
                "application_types": llm_info.get("application_types", ["web_app", "cloud_native"]),
                "description": llm_info.get("description", f"Automated adapter classification for {folder_name}")
            }

        merged_meta = {
            **default_info,
            **existing_meta,
            "adapter_name": folder_name,
            "last_updated": datetime.now().isoformat()
        }

        # Write/extend metadata.json in adapter folder
        with open(meta_file, "w", encoding="utf-8") as f:
            json.dump(merged_meta, f, indent=2)

        catalog[folder_name] = merged_meta

    return catalog


def recommend_adapters(
    operating_countries: List[str],
    industry_vertical: str,
    application_type: str = "web_app",
    required_control_domains: Optional[List[str]] = None,
    manual_overrides: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    Given a client's detected jurisdiction, industry vertical, application type, and control domains,
    recommends matching adapters & frameworks. Supports explicit manual override.
    """
    catalog = sync_and_extend_adapter_metadata()

    # Normalize input parameters
    detected_jurisdictions = set()
    for country in operating_countries:
        c_clean = country.strip().lower()
        if c_clean in JURISDICTION_MAP:
            detected_jurisdictions.update(JURISDICTION_MAP[c_clean])
        else:
            detected_jurisdictions.add("International")

    if not detected_jurisdictions:
        detected_jurisdictions.add("International")

    ind_clean = industry_vertical.strip().lower().replace(" ", "_")
    app_clean = application_type.strip().lower().replace(" ", "_")
    req_domains = [d.strip().lower().replace(" ", "_") for d in (required_control_domains or [])]

    recommendations = []

    for adapter_name, meta in catalog.items():
        score = 0.0
        reasons = []

        # 1. Strict Jurisdiction Match (weight: 0.40)
        adapter_jurs = set(meta.get("jurisdiction", []))
        jur_overlap = detected_jurisdictions.intersection(adapter_jurs)
        # Give full weight if exact region/country or explicit International overlap
        if jur_overlap:
            score += 0.40
            reasons.append(f"Jurisdiction match ({', '.join(sorted(list(jur_overlap)))})")

        # 2. Industry Vertical Match (weight: 0.25)
        adapter_industries = meta.get("industry_verticals", [])
        if ind_clean in adapter_industries:
            score += 0.25
            reasons.append(f"Industry vertical match ({industry_vertical})")

        # 3. Application Type Match (weight: 0.15)
        adapter_apps = meta.get("application_types", [])
        if app_clean in adapter_apps:
            score += 0.15
            reasons.append(f"Application type match ({application_type})")

        # 4. Control Domain Match (weight: 0.20)
        if req_domains:
            adapter_domains = meta.get("control_domains", [])
            domain_overlap = set(req_domains).intersection(set(adapter_domains))
            if domain_overlap:
                score += 0.20
                reasons.append(f"Control domain match ({', '.join(sorted(list(domain_overlap)))})")

        # Manual Override Check
        is_override = False
        if manual_overrides and (adapter_name in manual_overrides or meta.get("framework") in manual_overrides):
            score = 1.0
            is_override = True
            reasons = ["Manually selected override by client/auditor"]

        # Only include relevant recommendations with strong match (>= 0.65) or manual override
        if (score >= 0.65 and jur_overlap) or is_override:
            recommendations.append({
                "adapter_name": adapter_name,
                "framework": meta.get("framework"),
                "short_code": meta.get("short_code"),
                "description": meta.get("description"),
                "score": round(score, 2),
                "is_manual_override": is_override,
                "match_reasons": reasons,
            })

    recommendations.sort(key=lambda x: (x["is_manual_override"], x["score"]), reverse=True)

    selected_frameworks = [r["framework"] for r in recommendations]

    return {
        "operating_countries": operating_countries,
        "detected_jurisdictions": sorted(list(detected_jurisdictions)),
        "industry_vertical": industry_vertical,
        "application_type": application_type,
        "required_control_domains": req_domains,
        "recommended_adapters": recommendations,
        "auto_selected_frameworks": selected_frameworks,
        "timestamp": datetime.now().isoformat(),
    }


def consolidate_multi_framework_assessments(
    assessments_by_framework: Dict[str, List[Dict[str, Any]]]
) -> Dict[str, Any]:
    """
    Consolidates multi-framework compliance assessments (e.g. GDPR + NIS2 + PCI-DSS)
    into a single unified report data structure for Agent 5.
    """
    total_frameworks = len(assessments_by_framework)
    consolidated_controls = []
    global_counts = {
        "Compliant": 0,
        "Partially Compliant": 0,
        "Not Compliant": 0,
        "No Evidence Found": 0,
    }

    framework_summaries = {}

    for fw, items in assessments_by_framework.items():
        fw_counts = {"Compliant": 0, "Partially Compliant": 0, "Not Compliant": 0, "No Evidence Found": 0}
        for item in items:
            st = item.get("status", "Not Compliant")
            fw_counts[st] = fw_counts.get(st, 0) + 1
            global_counts[st] = global_counts.get(st, 0) + 1

            consolidated_controls.append({
                **item,
                "source_framework": fw,
            })

        framework_summaries[fw] = {
            "total": len(items),
            "counts": fw_counts,
            "compliance_pct": (fw_counts["Compliant"] / len(items) * 100) if items else 0.0,
        }

    total_controls = len(consolidated_controls)
    global_compliance_pct = (global_counts["Compliant"] / total_controls * 100) if total_controls else 0.0

    return {
        "total_frameworks": total_frameworks,
        "total_controls_assessed": total_controls,
        "global_counts": global_counts,
        "global_compliance_pct": round(global_compliance_pct, 1),
        "framework_summaries": framework_summaries,
        "consolidated_controls": consolidated_controls,
    }


def generate_consolidated_report_markdown(
    client_name: str,
    assessments_by_framework: Dict[str, List[Dict[str, Any]]],
    with_remediation: bool = True,
) -> str:
    """
    Generates a single consolidated Markdown audit report across multiple frameworks simultaneously.
    """
    data = consolidate_multi_framework_assessments(assessments_by_framework)
    total_ctrls = data["total_controls_assessed"]
    g_counts = data["global_counts"]
    g_pct = data["global_compliance_pct"]

    lines = []
    lines.append(f"# ComplianceMesh — Consolidated Multi-Framework Compliance Report")
    lines.append(f"## Client: **{client_name}**")
    lines.append(f"**Generated Date**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  ")
    lines.append(f"**Scope**: Consolidated Audit across **{data['total_frameworks']} Frameworks** ({', '.join(assessments_by_framework.keys())})  ")
    lines.append(f"**Total Controls Assessed**: {total_ctrls}  \n")

    # Executive Summary
    lines.append("---\n## Executive Summary")
    lines.append(
        f"This unified compliance audit evaluated **{total_ctrls} controls** across "
        f"**{data['total_frameworks']} applicable regulatory frameworks** simultaneously for **{client_name}**. "
        f"Overall consolidated compliance score is **{g_pct}%** ({g_counts['Compliant']}/{total_ctrls} controls fully satisfied). "
        f"Identified gaps requiring action: **{g_counts['Partially Compliant']} Partially Compliant** and "
        f"**{g_counts['Not Compliant']} Not Compliant** controls."
    )

    # Global Summary Table / Pass-Fail Matrix
    lines.append("\n---\n## 📊 Per-Framework Pass/Fail Compliance Matrix")
    lines.append("| Framework | Total Controls | ✅ Compliant | ⚠️ Gaps (Partial / Non-Compliant) | ❓ No Evidence | Compliance Rate | Pass/Fail Verdict |")
    lines.append("|---|---|---|---|---|---|---|")

    for fw, summary in data["framework_summaries"].items():
        c = summary["counts"]
        gaps_cnt = c["Partially Compliant"] + c["Not Compliant"]
        verdict = "🟢 PASS (>=80%)" if summary["compliance_pct"] >= 80.0 else ("🟡 CONDITIONAL" if summary["compliance_pct"] >= 60.0 else "🔴 FAIL (<60%)")
        lines.append(
            f"| **{fw.upper()}** | {summary['total']} | {c['Compliant']} | {gaps_cnt} ({c['Partially Compliant']} partial, {c['Not Compliant']} non-compliant) | "
            f"{c['No Evidence Found']} | **{summary['compliance_pct']:.1f}%** | {verdict} |"
        )

    lines.append(
        f"| **CONSOLIDATED TOTAL** | **{total_ctrls}** | **{g_counts['Compliant']}** | "
        f"**{g_counts['Partially Compliant'] + g_counts['Not Compliant']}** | "
        f"**{g_counts['No Evidence Found']}** | **{g_pct}%** | **{'🟢 PASS' if g_pct>=80 else '🔴 FAIL'}** |"
    )

    # Consolidated Gap Analysis with Evidence Strength & Remediation State
    lines.append("\n---\n## 🛠️ Confirmed Findings and Evidence Gaps")
    gaps = [c for c in data["consolidated_controls"] if c["status"] in ("Not Compliant", "Partially Compliant", "No Evidence Found")]

    if not gaps:
        lines.append("\nNo gaps identified — all controls across all target frameworks are Compliant.")
    else:
        lines.append(f"\n{len(gaps)} controls require either remediation or additional evidence across target frameworks:\n")
        for item in gaps:
            fw = item.get("source_framework", "").upper()
            cid = item.get("control_id") or "UNKNOWN"
            title = item.get("title") or ""
            sim_score = float(item.get("evidence_similarity", 0.0) or 0.0)
            
            # Surface Confidence & Evidence Strength Indicators
            if sim_score >= 0.80:
                confidence_indicator = f"🟢 HIGH CONFIDENCE (`similarity: {sim_score:.2f}`)"
            elif sim_score >= 0.60:
                confidence_indicator = f"🟡 MODERATE CONFIDENCE (`similarity: {sim_score:.2f}`)"
            elif sim_score > 0.0:
                confidence_indicator = f"🔴 LOW CONFIDENCE (`similarity: {sim_score:.2f}`)"
            else:
                confidence_indicator = "⚪ NO EVIDENCE FOUND"

            rem_state = item.get("remediation_state", "open").upper().replace("_", " ")
            is_evidence_gap = item.get("status") == "No Evidence Found"

            lines.append(f"### [{fw}] {cid} — {title}")
            lines.append(f"- **Verdict Status**: `{item['status']}` | **Remediation Tracking State**: `[{rem_state}]`")
            lines.append(f"- **Evidence Strength & Confidence**: {confidence_indicator}")
            lines.append(f"- **Auditor Rationale**: {item.get('explanation') or item.get('rationale')}")
            lines.append(f"- **Evidence Reviewed**: `{item.get('evidence_source', 'Vault')}`")
            if with_remediation:
                remediation = item.get("remediation") or "Develop and publish operational procedures to satisfy control requirement."
                label = "Evidence Collection Next Step" if is_evidence_gap else "Recommended Remediation"
                lines.append(f"- **{label}**: {remediation}\n")

    lines.append("\n---\n*Consolidated Multi-Framework Audit Report produced by ComplianceMesh Engine*")
    
    import robustness_governance as rg
    lines.append(rg.get_legal_disclaimer())

    return "\n".join(lines)

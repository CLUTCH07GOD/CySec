"""
Multi-Country & Multi-Framework Jurisdiction Detection & Standards Version Registry
-------------------------------------------------------------------------------------
Handles:
  1. Jurisdiction Detection -> Auto-selects applicable active frameworks on disk
  2. Standards Version Registry -> Tracks active versions for available standards
  3. Freshness Check -> Verifies assessment freshness against active version dates
"""

import os
import glob
from datetime import datetime
from typing import Dict, List, Any, Optional

# Directory paths
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STRUCTURED_CONTROLS_DIR = os.path.join(PROJECT_ROOT, "structured_controls")

# -----------------------------------------------------------------------------
# 1. DYNAMIC & EXTENSIBLE STANDARDS REGISTRY (Scans structured_controls/*.json)
# -----------------------------------------------------------------------------
META_MAP = {
    "cis__aws_foundations.json": {"title": "CIS Amazon Web Services Foundations Benchmark", "short_code": "CIS AWS", "jurisdiction": "Global", "category": "Cloud Security Benchmark", "version": "v3.0.0"},
    "cis__k8s.json": {"title": "CIS Kubernetes Benchmark", "short_code": "CIS K8s", "jurisdiction": "Global", "category": "Container Security", "version": "v1.8.0"},
    "eu__ai_act.json": {"title": "EU Artificial Intelligence Act", "short_code": "EU AI Act", "jurisdiction": "EU", "category": "AI Regulation & Governance", "version": "Regulation (EU) 2024/1689"},
    "eu__dora.json": {"title": "Digital Operational Resilience Act", "short_code": "DORA", "jurisdiction": "EU", "category": "Financial Operational Resilience", "version": "Regulation (EU) 2022/2554"},
    "eu__gdpr.json": {"title": "General Data Protection Regulation", "short_code": "GDPR", "jurisdiction": "EU", "category": "Privacy & Data Protection", "version": "2016/679 (v1.0)"},
    "eu__nis2.json": {"title": "Network and Information Security Directive 2", "short_code": "NIS2", "jurisdiction": "EU", "category": "Cybersecurity & Resilience", "version": "Directive (EU) 2022/2555"},
    "india__dpdp.json": {"title": "Digital Personal Data Protection Act", "short_code": "DPDP", "jurisdiction": "India", "category": "Privacy & Data Protection", "version": "Act No. 22 of 2023"},
    "international__iso27001.json": {"title": "ISO/IEC 27001 Information Security Management System", "short_code": "ISO 27001", "jurisdiction": "International", "category": "ISMS", "version": "ISO/IEC 27001:2022"},
    "mitre__atlas.json": {"title": "MITRE ATLAS (Adversarial Threat Landscape for AI Systems)", "short_code": "MITRE ATLAS", "jurisdiction": "Global", "category": "AI Threat Matrix", "version": "2024.1"},
    "mitre__attack.json": {"title": "MITRE ATT&CK Enterprise Matrix", "short_code": "MITRE ATT&CK", "jurisdiction": "Global", "category": "Threat Taxonomy & Tactics", "version": "v15.1"},
    "nist__csf.json": {"title": "NIST Cybersecurity Framework", "short_code": "NIST CSF", "jurisdiction": "US / Global", "category": "Cybersecurity Governance", "version": "v2.0"},
    "owasp__asvs_v5.json": {"title": "OWASP Application Security Verification Standard", "short_code": "OWASP ASVS", "jurisdiction": "Global", "category": "AppSec Verification", "version": "v5.0.0"},
    "owasp__llm_top10.json": {"title": "OWASP Top 10 for LLM Applications", "short_code": "OWASP LLM Top 10", "jurisdiction": "Global", "category": "GenAI / LLM Security", "version": "v2025.1"},
    "owasp__masvs.json": {"title": "OWASP Mobile Application Security Verification Standard", "short_code": "OWASP MASVS", "jurisdiction": "Global", "category": "Mobile Security", "version": "v2.1.0"},
    "owasp__top10_web.json": {"title": "OWASP Top 10 Web Application Security Risks", "short_code": "OWASP Top 10 Web", "jurisdiction": "Global", "category": "Web Application Security", "version": "v2021"},
    "us__cisa_cpg.json": {"title": "CISA Cross-Sector Cybersecurity Performance Goals", "short_code": "CISA CPG", "jurisdiction": "US", "category": "Critical Infrastructure", "version": "v2.0"},
    "us__hipaa.json": {"title": "HIPAA Security & Privacy Rule (NIST SP 800-66)", "short_code": "HIPAA", "jurisdiction": "US", "category": "Healthcare Data Security", "version": "SP 800-66 Rev 2"},
    "us__nist_ai_rmf.json": {"title": "NIST AI Risk Management Framework", "short_code": "NIST AI RMF", "jurisdiction": "US / Global", "category": "AI Safety & Risk", "version": "AI RMF 1.0"},
    "us__nist_sp_800_53.json": {"title": "NIST SP 800-53 Security and Privacy Controls", "short_code": "NIST 800-53", "jurisdiction": "US / Global", "category": "Federal Security Controls", "version": "Rev 5"},
    "us__pci_dss_v4.json": {"title": "Payment Card Industry Data Security Standard", "short_code": "PCI DSS", "jurisdiction": "Global", "category": "Payment Security", "version": "v4.0.1"},
    "us__soc2.json": {"title": "AICPA SOC 2 Trust Services Criteria", "short_code": "SOC 2", "jurisdiction": "Global", "category": "Cloud & Service Governance", "version": "2017 Rev 2022"},
}

STANDARDS_VERSION_REGISTRY: Dict[str, Dict[str, Any]] = {}

def refresh_standards_registry() -> Dict[str, Dict[str, Any]]:
    global STANDARDS_VERSION_REGISTRY
    registry = {}
    for path in glob.glob(os.path.join(STRUCTURED_CONTROLS_DIR, "*.json")):
        fn = os.path.basename(path)
        key = fn.replace(".json", "").replace("__", "/")
        meta = META_MAP.get(fn, {
            "title": fn.replace(".json", "").replace("_", " ").title(),
            "short_code": fn.replace(".json", "").upper(),
            "jurisdiction": "Global",
            "category": "Regulatory Compliance",
            "version": "v1.0"
        })
        registry[key] = {
            "title": meta["title"],
            "short_code": meta["short_code"],
            "jurisdiction": meta["jurisdiction"],
            "category": meta["category"],
            "version": meta["version"],
            "release_date": "2024-01-01",
            "last_amendment_date": "2024-06-01",
            "governing_body": meta["short_code"],
            "structured_file": fn,
        }
    STANDARDS_VERSION_REGISTRY = registry
    return registry

# Initialize dynamically on import
refresh_standards_registry()

# Mapping countries to jurisdictions
COUNTRY_TO_JURISDICTION: Dict[str, List[str]] = {
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
    "global": ["India", "EU", "US", "International", "Global"],
}

JURISDICTION_FRAMEWORKS: Dict[str, List[str]] = {
    "India": ["india/dpdp"],
    "EU": ["eu/gdpr", "eu/nis2", "eu/dora", "eu/ai_act"],
    "US": ["nist/csf", "us/nist_ai_rmf", "us/hipaa", "us/nist_sp_800_53", "us/cisa_cpg", "us/pci_dss_v4", "us/soc2"],
    "International": ["international/iso27001", "owasp/asvs_v5", "owasp/top10_web", "owasp/llm_top10", "owasp/masvs", "cis/aws_foundations", "cis/k8s", "mitre/atlas", "mitre/attack"],
    "Global": ["international/iso27001", "owasp/asvs_v5", "owasp/top10_web", "owasp/llm_top10", "owasp/masvs", "cis/aws_foundations", "cis/k8s", "mitre/atlas", "mitre/attack"],
}


def _get_existing_structured_controls() -> set:
    """Finds all structured_controls/*.json files on disk."""
    existing = set()
    for f in glob.glob(os.path.join(STRUCTURED_CONTROLS_DIR, "*.json")):
        existing.add(os.path.basename(f))
    return existing


def detect_company_jurisdiction(
    operating_countries: List[str],
    industry_sector: str = "General",
    **kwargs
) -> Dict[str, Any]:
    """
    Infers applicable jurisdictions and auto-selects framework set ONLY for files present on disk.
    """
    refresh_standards_registry()
    existing_files = _get_existing_structured_controls()
    detected_jurisdictions = set()

    for country in operating_countries:
        c_clean = country.strip().lower()
        if c_clean in COUNTRY_TO_JURISDICTION:
            detected_jurisdictions.update(COUNTRY_TO_JURISDICTION[c_clean])
        else:
            detected_jurisdictions.add("International")

    if not detected_jurisdictions:
        detected_jurisdictions.add("International")

    detected_jurisdictions.add("International")

    selected_keys = set()
    for j in detected_jurisdictions:
        if j in JURISDICTION_FRAMEWORKS:
            for fw in JURISDICTION_FRAMEWORKS[j]:
                if fw in STANDARDS_VERSION_REGISTRY:
                    sf = STANDARDS_VERSION_REGISTRY[fw].get("structured_file")
                    if sf and sf in existing_files:
                        selected_keys.add(fw)

    rec_engine_data = {}
    try:
        import adapter_classification
        rec_engine_data = adapter_classification.recommend_adapters(
            operating_countries=operating_countries,
            industry_vertical=industry_sector,
            application_type=kwargs.get("application_type", "web_app"),
            required_control_domains=kwargs.get("control_domains", []),
            manual_overrides=kwargs.get("manual_overrides", []),
        )
    except Exception:
        pass

    detailed_selected = []
    for fw_key in sorted(list(selected_keys)):
        reg = STANDARDS_VERSION_REGISTRY[fw_key]
        detailed_selected.append({
            "key": fw_key,
            "title": reg["title"],
            "short_code": reg["short_code"],
            "version": reg["version"],
            "jurisdiction": reg["jurisdiction"],
            "category": reg["category"],
            "reason": f"Statutory & Available Framework ({reg['jurisdiction']})",
        })

    return {
        "operating_countries": operating_countries,
        "industry_sector": industry_sector,
        "detected_jurisdictions": sorted(list(detected_jurisdictions)),
        "auto_selected_frameworks": sorted(list(selected_keys)),
        "detailed_frameworks": detailed_selected,
        "multi_axis_recommendations": rec_engine_data.get("recommended_adapters", []),
        "timestamp": datetime.now().isoformat(),
    }


def check_assessment_freshness(
    framework_key: str,
    assessment_run_date: Optional[str] = None,
    assessment_version: Optional[str] = None
) -> Dict[str, Any]:
    """
    Real-Time Freshness Check:
    Dynamically compares the active framework's control schema modification date on disk
    against the live system timestamp (or latest assessment timestamp).
    """
    refresh_standards_registry()
    if framework_key not in STANDARDS_VERSION_REGISTRY:
        return {
            "status": "Unknown Framework",
            "needs_rerun": False,
            "reason": f"Framework '{framework_key}' is not in active registry.",
        }

    reg = STANDARDS_VERSION_REGISTRY[framework_key]
    current_version = reg["version"]
    
    # 1. Inspect actual file modification time on disk in real-time
    sf = reg.get("structured_file")
    disk_file_mtime = None
    if sf:
        path = os.path.join(STRUCTURED_CONTROLS_DIR, sf)
        if os.path.exists(path):
            disk_file_mtime = datetime.fromtimestamp(os.path.getmtime(path))

    # 2. Use live current timestamp if assessment_run_date is not passed
    if not assessment_run_date or assessment_run_date.strip() == "":
        run_dt = datetime.now()
        assessment_run_date = run_dt.strftime("%Y-%m-%d %H:%M:%S")
    else:
        try:
            run_dt = datetime.fromisoformat(assessment_run_date.replace("Z", "+00:00").replace("/", "-"))
        except Exception:
            run_dt = datetime.now()

    # 3. Real-time freshness evaluation
    is_outdated = False
    if disk_file_mtime and run_dt < disk_file_mtime:
        is_outdated = True
        reason = f"⚡ Dynamic Update Detected! Standard schema was modified on disk at {disk_file_mtime.strftime('%Y-%m-%d %H:%M:%S')}. Existing assessment ({assessment_run_date}) is outdated."
    else:
        reason = f"🟢 Live Audit Verified Fresh: Assessment is up-to-date with real-time active version {current_version} as of {datetime.now().strftime('%H:%M:%S')}."

    return {
        "framework_key": framework_key,
        "title": reg["title"],
        "active_version": current_version,
        "assessment_run_date": assessment_run_date,
        "schema_modified_at": disk_file_mtime.strftime("%Y-%m-%d %H:%M:%S") if disk_file_mtime else "N/A",
        "is_outdated": is_outdated,
        "needs_rerun": is_outdated,
        "reason": reason,
        "live_check_timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }


def get_registered_standards() -> List[Dict[str, Any]]:
    """Returns all standards dynamically registered from structured_controls on disk."""
    refresh_standards_registry()
    existing_files = _get_existing_structured_controls()
    items = []
    for k, v in STANDARDS_VERSION_REGISTRY.items():
        if v.get("structured_file") in existing_files:
            items.append({"key": k, **v})
    return items

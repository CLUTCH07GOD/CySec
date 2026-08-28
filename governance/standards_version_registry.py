import os
import json
from datetime import datetime

REGISTRY_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "standards_registry.json")

DEFAULT_REGISTRY = {
    "eu/gdpr": {
        "framework_id": "eu/gdpr",
        "title": "General Data Protection Regulation",
        "jurisdiction": "eu",
        "version": "v2024.1 (EDPB Guidelines)",
        "effective_date": "2024-01-15",
        "last_updated": "2024-01-15T00:00:00Z",
        "changelog": "Incorporated 2024 EDPB international data transfer clarifications.",
        "status": "Active"
    },
    "eu/nis2": {
        "framework_id": "eu/nis2",
        "title": "Network & Information Security Directive 2",
        "jurisdiction": "eu",
        "version": "EU 2022/2555 (Oct 2024 Transposition)",
        "effective_date": "2024-10-17",
        "last_updated": "2024-10-17T00:00:00Z",
        "changelog": "Full mandatory transposition deadline by EU Member States.",
        "status": "Active"
    },
    "india/dpdp": {
        "framework_id": "india/dpdp",
        "title": "Digital Personal Data Protection Act",
        "jurisdiction": "india",
        "version": "2023 Act / 2024 Draft Rules",
        "effective_date": "2024-06-01",
        "last_updated": "2024-06-01T00:00:00Z",
        "changelog": "Added draft procedural rules for consent managers and breach notifications.",
        "status": "Active"
    },
    "international/iso27001": {
        "framework_id": "international/iso27001",
        "title": "ISO/IEC 27001:2022",
        "jurisdiction": "international",
        "version": "2022 + AMD 1:2024 (Climate Action)",
        "effective_date": "2024-02-23",
        "last_updated": "2024-02-23T00:00:00Z",
        "changelog": "Added mandatory ISO climate change consideration clauses (4.1 & 4.2).",
        "status": "Active"
    },
    "nist/csf": {
        "framework_id": "nist/csf",
        "title": "NIST Cybersecurity Framework",
        "jurisdiction": "nist",
        "version": "CSF 2.0 (Official Release)",
        "effective_date": "2024-02-26",
        "last_updated": "2024-02-26T00:00:00Z",
        "changelog": "Expanded scope to all organizations + added GOVERN (GV) core function.",
        "status": "Active"
    },
    "us/hipaa": {
        "framework_id": "us/hipaa",
        "title": "HIPAA Security & Privacy Rule",
        "jurisdiction": "us",
        "version": "2024 Privacy Rule Updates",
        "effective_date": "2024-06-25",
        "last_updated": "2024-06-25T00:00:00Z",
        "changelog": "Enhanced protection for reproductive healthcare records.",
        "status": "Active"
    },
    "owasp/wstg_v42": {
        "framework_id": "owasp/wstg_v42",
        "title": "OWASP Web Security Testing Guide",
        "jurisdiction": "international",
        "version": "v4.2 (Official Standard)",
        "effective_date": "2020-12-01",
        "last_updated": "2024-08-01T00:00:00Z",
        "changelog": "Declarative security probing taxonomy alignment.",
        "status": "Active"
    },
    "owasp/asvs_v5": {
        "framework_id": "owasp/asvs_v5",
        "title": "OWASP Application Security Verification Standard",
        "jurisdiction": "international",
        "version": "v5.0.0 Draft / Preview",
        "effective_date": "2024-05-01",
        "last_updated": "2024-08-01T00:00:00Z",
        "changelog": "Modern API, OAuth2, and microservice verification requirements.",
        "status": "Active"
    },
    "nist/zero_trust": {
        "framework_id": "nist/zero_trust",
        "title": "NIST Zero Trust Architecture (SP 800-207)",
        "jurisdiction": "nist",
        "version": "SP 800-207 Final",
        "effective_date": "2020-08-01",
        "last_updated": "2024-01-10T00:00:00Z",
        "changelog": "Identity & access micro-segmentation controls.",
        "status": "Active"
    },
    "us/nist_ai_rmf": {
        "framework_id": "us/nist_ai_rmf",
        "title": "NIST AI Risk Management Framework",
        "jurisdiction": "us",
        "version": "AI 100-1 (1.0)",
        "effective_date": "2023-01-26",
        "last_updated": "2024-03-15T00:00:00Z",
        "changelog": "Trustworthy AI governance, measure, and manage functions.",
        "status": "Active"
    }
}


def load_registry() -> dict:
    """Loads the standards version registry from disk or initializes defaults."""
    if not os.path.exists(REGISTRY_FILE):
        save_registry(DEFAULT_REGISTRY)
        return DEFAULT_REGISTRY
    try:
        with open(REGISTRY_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            # Ensure defaults are merged for any missing framework
            updated = False
            for k, v in DEFAULT_REGISTRY.items():
                if k not in data:
                    data[k] = v
                    updated = True
            if updated:
                save_registry(data)
            return data
    except Exception:
        return DEFAULT_REGISTRY


def save_registry(registry_data: dict) -> bool:
    """Persists the registry to JSON disk storage."""
    try:
        with open(REGISTRY_FILE, "w", encoding="utf-8") as f:
            json.dump(registry_data, f, indent=2)
        return True
    except Exception:
        return False


def get_framework_version_info(framework_id: str) -> dict:
    """Gets version info for a specific framework (e.g. 'eu/gdpr')."""
    registry = load_registry()
    if framework_id in registry:
        return registry[framework_id]
    
    # Fallback for dynamic frameworks
    parts = framework_id.split("/")
    title = framework_id.upper()
    if len(parts) == 2:
        title = f"{parts[0].upper()} {parts[1].replace('_', ' ').replace('-', ' ').upper()}"
    return {
        "framework_id": framework_id,
        "title": title,
        "jurisdiction": parts[0] if len(parts) == 2 else "global",
        "version": "v1.0 (Current)",
        "effective_date": datetime.now().strftime("%Y-%m-%d"),
        "last_updated": datetime.now().isoformat() + "Z",
        "changelog": "Initial version ingested into registry.",
        "status": "Active"
    }


def update_framework_version(framework_id: str, new_version: str, changelog: str) -> dict:
    """Updates standard version and logs timestamp for re-running assessments."""
    registry = load_registry()
    info = get_framework_version_info(framework_id)
    info["version"] = new_version
    info["changelog"] = changelog
    info["last_updated"] = datetime.now().isoformat() + "Z"
    registry[framework_id] = info
    save_registry(registry)
    return info


def is_assessment_outdated(framework_id: str, assessed_version: str) -> tuple[bool, str]:
    """
    Checks whether a past assessment was run on an outdated version of the standard.
    Returns (is_outdated, current_version).
    """
    current_info = get_framework_version_info(framework_id)
    curr_version = current_info.get("version", "v1.0")
    if not assessed_version:
        return True, curr_version
    return (assessed_version.strip() != curr_version.strip()), curr_version

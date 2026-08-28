"""
CISO Assistant YAML Converter & Cleanup Script
-----------------------------------------------
Parses CISO Assistant open-source regulatory libraries and cross-mappings (YAML),
converts them into normalized JSON format for the compliance engine, and cleans up
unvalidated/legacy PDF-derived control files.
"""

import os
import json
import yaml
import glob
from typing import Dict, List, Any

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CISO_LIB_DIR = os.path.join(PROJECT_ROOT, "tmp_sandboxes", "ciso_lib", "backend", "library", "libraries")
STRUCTURED_CONTROLS_DIR = os.path.join(PROJECT_ROOT, "structured_controls")
MAPPINGS_DIR = os.path.join(PROJECT_ROOT, "mappings")

os.makedirs(STRUCTURED_CONTROLS_DIR, exist_ok=True)
os.makedirs(MAPPINGS_DIR, exist_ok=True)

# Comprehensive list of official YAML frameworks to ingest
FRAMEWORK_FILE_MAP = {
    "india-dpdpa-2023.yaml": ("india", "dpdp", "structured_controls/india__dpdp.json"),
    "owasp-asvs-5.0.0.yaml": ("owasp", "asvs_v5", "structured_controls/owasp__asvs_v5.json"),
    "nist-csf-2.0.yaml": ("nist", "csf", "structured_controls/nist__csf.json"),
    "iso27001-2022.yaml": ("international", "iso27001", "structured_controls/international__iso27001.json"),
    "gdpr.yaml": ("eu", "gdpr", "structured_controls/eu__gdpr.json"),
    "nis2-directive.yaml": ("eu", "nis2", "structured_controls/eu__nis2.json"),
    "pcidss-4_0.yaml": ("us", "pci_dss_v4", "structured_controls/us__pci_dss_v4.json"),
    "nist-ai-rmf-1.0.yaml": ("us", "nist_ai_rmf", "structured_controls/us__nist_ai_rmf.json"),
    "dora.yaml": ("eu", "dora", "structured_controls/eu__dora.json"),
    "soc2_2017_with_rev_2022.yaml": ("us", "soc2", "structured_controls/us__soc2.json"),
    "nist-sp-800-53-rev5.yaml": ("us", "nist_sp_800_53", "structured_controls/us__nist_sp_800_53.json"),
    "nist-sp-800-66-rev2.yaml": ("us", "hipaa", "structured_controls/us__hipaa.json"),
    "owasp-top-10-web.yaml": ("owasp", "top10_web", "structured_controls/owasp__top10_web.json"),
    "owasp-llm-checklist.yaml": ("owasp", "llm_top10", "structured_controls/owasp__llm_top10.json"),
    "owasp-masvs-v2.1.0.yaml": ("owasp", "masvs", "structured_controls/owasp__masvs.json"),
    "mitre-attack.yaml": ("global", "mitre_attack", "structured_controls/mitre__attack.json"),
    "mitre-atlas.yaml": ("global", "mitre_atlas", "structured_controls/mitre__atlas.json"),
    "ai-act.yaml": ("eu", "ai_act", "structured_controls/eu__ai_act.json"),
    "cisa-cpg-2.0.yaml": ("us", "cisa_cpg", "structured_controls/us__cisa_cpg.json"),
    "cis-benchmark-aws-foundations.yaml": ("global", "cis_aws", "structured_controls/cis__aws_foundations.json"),
    "cis-benchmark-kubernetes-2.0.1.yaml": ("global", "cis_k8s", "structured_controls/cis__k8s.json"),
}

# Cross-framework mapping specifications
MAPPING_FILES = [
    ("mapping-nist-csf-2.0-to-iso27001-2022.yaml", "mappings/nist_csf_vs_iso27001.json"),
    ("mapping-annex-technical-and-methodological-requirements-nis2-and-iso27001-2022.yaml", "mappings/nis2_vs_iso27001.json"),
    ("mapping-annex-technical-and-methodological-requirements-nis2-and-nist-csf-2.0.yaml", "mappings/nis2_vs_nist_csf.json"),
    ("mapping-iso27001-2022-and-scf-2025.2.2.yaml", "mappings/iso27001_vs_scf.json"),
    ("mapping-nist-sp-800-53-rev5-to-iso27001-2022.yaml", "mappings/nist_sp_800_53_vs_iso27001.json"),
    ("mapping-nist-sp-800-66-rev2-to-nist-csf-2.0.yaml", "mappings/hipaa_vs_nist_csf.json"),
    ("mapping-cis-controls-v8-and-iso27001-2022.yaml", "mappings/cis_vs_iso27001.json"),
]

# Legacy low-quality PDF-derived files to purge
LEGACY_UNVALIDATED_FILES = [
    "cwe__cwe_v4.json",
    "nist__cloud.json",
    "nist__iot.json",
    "nist__sp_800_63b_r4.json",
    "nist__zero_trust.json",
    "owasp__wstg_v42.json",
    "india__cert_in.json",
]


def convert_ciso_yaml_to_controls(yaml_path: str, jurisdiction: str, framework: str) -> List[Dict[str, Any]]:
    """Converts a CISO Assistant framework YAML file to compliance control JSON schema."""
    with open(yaml_path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    obj = data.get("objects", {})
    nodes = (
        obj.get("framework", {}).get("requirement_nodes", [])
        or obj.get("reference_controls", [])
        or obj.get("tactics", [])
        or obj.get("threats", [])
        or obj.get("vulnerabilities", [])
        or obj.get("measures", [])
    )
    
    # Map node URN to node Name to resolve descriptive category names
    node_name_map = {}
    node_ref_map = {}
    for idx, node in enumerate(nodes):
        urn = node.get("urn", "")
        name = str(node.get("name", "") or "").strip()
        ref_id = str(node.get("ref_id", "") or "").strip()
        if urn:
            if name:
                node_name_map[urn] = name
            if ref_id:
                node_ref_map[urn] = ref_id

    controls = []

    for idx, node in enumerate(nodes):
        # Skip section headers and non-assessable structural nodes if assessable flag is explicitly False AND has children/name
        assessable = node.get("assessable")
        if assessable is False and node.get("name"):
            continue

        ref_id = str(node.get("ref_id", "") or "").strip()
        name = str(node.get("name", "") or "").strip()
        description = str(node.get("description", "") or "").strip()
        parent_urn = node.get("parent_urn", "")

        if not ref_id and parent_urn in node_ref_map:
            parent_ref = node_ref_map[parent_urn]
            ref_id = f"{parent_ref}.{idx + 1}"

        if not ref_id:
            ref_id = f"CTRL-{idx + 1}"

        if not name and not description:
            continue

        parent_name = node_name_map.get(parent_urn, "")
        if name:
            title = name
        elif parent_name:
            title = f"{parent_name} ({ref_id})"
        else:
            title = f"Control {ref_id}"

        full_desc = description if len(description) >= 15 else (f"{title}: {description}" if description else f"Security requirement for {title}")
        if len(full_desc) < 15:
            full_desc = f"{full_desc} - Mandatory security compliance control requirement."

        controls.append({
            "control_id": ref_id,
            "title": title,
            "description": full_desc,
            "jurisdiction": jurisdiction,
            "framework": framework,
            "source_file": os.path.basename(yaml_path)
        })

    return controls


def convert_ciso_mapping_yaml(yaml_path: str) -> List[Dict[str, Any]]:
    """Converts a CISO Assistant requirement_mapping_sets YAML to cross-framework JSON schema."""
    with open(yaml_path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    mapping_sets = data.get("objects", {}).get("requirement_mapping_sets", [])
    result = []

    for mset in mapping_sets:
        source_fw = mset.get("source_framework_urn", "").split(":")[-1]
        target_fw = mset.get("target_framework_urn", "").split(":")[-1]

        for req in mset.get("requirement_mappings", []):
            src_urn = req.get("source_requirement_urn", "")
            tgt_urn = req.get("target_requirement_urn", "")
            relationship = req.get("relationship", "intersect")

            src_cid = src_urn.split(":")[-1].upper()
            tgt_cid = tgt_urn.split(":")[-1].upper()

            result.append({
                "source_control": {
                    "id": src_cid,
                    "framework": source_fw,
                    "title": f"{source_fw} {src_cid}",
                    "jurisdiction": "global"
                },
                "target_control": {
                    "id": tgt_cid,
                    "framework": target_fw,
                    "title": f"{target_fw} {tgt_cid}",
                    "jurisdiction": "global"
                },
                "relationship": "Direct Equivalent" if relationship in ("equal", "equivalent") else "Partially Overlapping",
                "similarity": 0.95 if relationship in ("equal", "equivalent") else 0.85
            })

    return result


def ensure_ciso_lib_available():
    """Ensures CISO Assistant library directory is cloned via sparse checkout if missing."""
    if not os.path.exists(CISO_LIB_DIR) or not os.listdir(CISO_LIB_DIR):
        print("📥 CISO library missing. Fetching via sparse checkout...")
        target_dir = os.path.join(PROJECT_ROOT, "tmp_sandboxes", "ciso_lib")
        import shutil
        if os.path.exists(target_dir):
            shutil.rmtree(target_dir, ignore_errors=True)
        
        os.makedirs(os.path.dirname(target_dir), exist_ok=True)
        cmd = (
            f"git clone --filter=blob:none --sparse https://github.com/intuitem/ciso-assistant-community.git '{target_dir}' && "
            f"cd '{target_dir}' && "
            f"git sparse-checkout set backend/library/libraries"
        )
        os.system(cmd)


def main():
    ensure_ciso_lib_available()
    print("🚀 [CISO Assistant Converter] Processing official community libraries...")
    
    # 1. Framework Ingestion
    for filename, (jurisdiction, framework, target_rel_path) in FRAMEWORK_FILE_MAP.items():
        yaml_path = os.path.join(CISO_LIB_DIR, filename)
        if not os.path.exists(yaml_path):
            print(f"   ⚠️  YAML file missing: {filename}")
            continue

        controls = convert_ciso_yaml_to_controls(yaml_path, jurisdiction, framework)
        out_path = os.path.join(PROJECT_ROOT, target_rel_path)

        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(controls, f, indent=2)

        print(f"   ✅ Processed '{filename}' -> {len(controls)} controls written to '{target_rel_path}'")

    # 2. Auto-Discover & Ingest ALL Key Mappings (mapping-*.yaml)
    print("\n🌐 Ingesting ALL official cross-framework mapping YAMLs...")
    mapping_yaml_files = sorted(glob.glob(os.path.join(CISO_LIB_DIR, "mapping-*.yaml")))
    
    total_mapping_pairs = 0
    for yaml_path in mapping_yaml_files:
        base_name = os.path.basename(yaml_path)
        clean_name = base_name.replace("mapping-", "").replace(".yaml", "").replace("-and-", "_vs_").replace("-to-", "_vs_").replace("-", "_")
        target_rel_path = f"mappings/{clean_name}.json"
        
        mappings = convert_ciso_mapping_yaml(yaml_path)
        if not mappings:
            continue

        out_path = os.path.join(PROJECT_ROOT, target_rel_path)
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(mappings, f, indent=2)

        total_mapping_pairs += len(mappings)
        print(f"   🌐 Processed '{base_name}' -> {len(mappings)} control pairs written to '{target_rel_path}'")

    print(f"\n✨ Ingested a total of {total_mapping_pairs} cross-framework mapping pairs across {len(mapping_yaml_files)} mapping specifications!")


if __name__ == "__main__":
    main()

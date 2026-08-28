"""
Agent 6 — Training Data Synthesis
------------------------------------
Converts the outputs of Agents 1-5 (structured controls, compliance
assessments, control mappings) into JSONL instruction-response pairs
that match the exact format used by the existing Qwen3 LoRA adapters.

One train.jsonl is written per jurisdiction/framework, saved directly
into the adapter directory so Agent 7 can pick it up immediately.

PURPOSE & SCOPE:
    This agent is a DATA GENERATION tool — it creates synthetic Q&A pairs
    for LoRA fine-tuning (Agent 7). It is NOT intended for:
      - Real-time inference (use rag_utils.py or self_healing_rag.py)
      - Evaluation or benchmarking (use evaluate_router.py or evaluate_rag.py)
      - Direct user-facing output

    Input:  structured_controls/*.json, assessments/*.json, mappings/*.json
    Output: adapters/qwen3-<slug>-lora/train.jsonl (one per framework)

Run with:
    python agents/agent6_data_synthesis.py                   # all domains
    python agents/agent6_data_synthesis.py --domain india/dpdp
"""

import os
import re
import json
import glob
import random
import argparse

# Directory constants (mirrors agents/config.py — no model loading needed here)
STRUCTURED_CONTROLS_DIR = "structured_controls"
ASSESSMENTS_DIR          = "assessments"
MAPPINGS_DIR             = "mappings"


class _Cfg:
    STRUCTURED_CONTROLS_DIR = STRUCTURED_CONTROLS_DIR
    ASSESSMENTS_DIR          = ASSESSMENTS_DIR
    MAPPINGS_DIR             = MAPPINGS_DIR

config = _Cfg()

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
ADAPTERS_DIR = "adapters"

# Slug mapping: framework name → adapter directory suffix
# (mirrors how existing adapter dirs are named, e.g. zero_trust → zerotrust)
def _framework_slug(framework: str) -> str:
    return framework.replace("_", "").replace("-", "")

# Reverse-lookup: framework name → jurisdiction
# Full name & definition metadata for each framework
FRAMEWORK_FULL_NAMES = {
    "gdpr": {
        "full_name": "General Data Protection Regulation",
        "desc": "The General Data Protection Regulation (GDPR) (Regulation (EU) 2016/679) is a law on data protection and privacy in the European Union (EU) and the European Economic Area (EEA)."
    },
    "nis2": {
        "full_name": "Network and Information Security Directive 2 (Directive (EU) 2022/2555)",
        "desc": "NIS2 (Directive (EU) 2022/2555) is the EU-wide legislation on cybersecurity providing legal measures to boost the overall level of cybersecurity in the EU."
    },
    "dpdp": {
        "full_name": "Digital Personal Data Protection Act, 2023 (India)",
        "desc": "The Digital Personal Data Protection (DPDP) Act, 2023 is India's principal legislation governing the processing of digital personal data."
    },
    "csf": {
        "full_name": "NIST Cybersecurity Framework",
        "desc": "The NIST Cybersecurity Framework (CSF) provides a structured guidance based on existing standards, guidelines, and practices for organizations to manage cybersecurity risks."
    },
    "cloud": {
        "full_name": "NIST Special Publication 800-145 (Cloud Computing)",
        "desc": "NIST SP 800-145 defines the essential characteristics, service models (SaaS, PaaS, IaaS), and deployment models of cloud computing."
    },
    "iot": {
        "full_name": "NIST Special Publication 800-213 (IoT Cybersecurity Guidance)",
        "desc": "NIST SP 800-213 provides guidance for federal agencies to consider IoT device cybersecurity capabilities."
    },
    "zero_trust": {
        "full_name": "NIST Special Publication 800-207 (Zero Trust Architecture)",
        "desc": "NIST SP 800-207 describes Zero Trust Architecture (ZTA) concepts and provides general deployment models for enterprise cybersecurity."
    },
    "iso27001": {
        "full_name": "ISO/IEC 27001 Information Security Management System",
        "desc": "ISO/IEC 27001 is the international standard for managing information security risks through an Information Security Management System (ISMS)."
    },
}

FRAMEWORK_JURISDICTION = {
    "gdpr":       "eu",
    "nis2":       "eu",
    "dpdp":       "india",
    "csf":        "nist",
    "cloud":      "nist",
    "iot":        "nist",
    "zero_trust": "nist",
    "iso27001":   "international",
}

# Chat template matching Qwen3 (clean user→assistant, no think tags)
def _make_text(instruction: str, output: str) -> str:
    return (
        f"<|im_start|>user\n{instruction}<|im_end|>\n"
        f"<|im_start|>assistant\n{output}<|im_end|>\n"
    )


def _entry(instruction: str, output: str) -> dict:
    instruction = instruction.strip()
    output = output.strip()
    if not instruction or not output:
        return None
    return {
        "instruction": instruction,
        "input": "",
        "output": output,
        "text": _make_text(instruction, output),
    }


# ---------------------------------------------------------------------------
# Loaders
# ---------------------------------------------------------------------------
def load_structured_controls() -> dict:
    """Returns {(jurisdiction, framework): [control_dict, ...]}"""
    grouped: dict = {}
    for path in sorted(glob.glob(f"{config.STRUCTURED_CONTROLS_DIR}/*.json")):
        try:
            with open(path, encoding="utf-8") as f:
                raw_data = json.load(f)
            
            if isinstance(raw_data, dict):
                controls = raw_data.get("controls", [])
                default_jur = raw_data.get("jurisdiction", "")
                default_fw = raw_data.get("framework", "")
            elif isinstance(raw_data, list):
                controls = raw_data
                default_jur = ""
                default_fw = ""
            else:
                controls = []
                
            for c in controls:
                if isinstance(c, dict):
                    jur = c.get("jurisdiction") or default_jur
                    fw = c.get("framework") or default_fw
                    key = (jur, fw)
                    grouped.setdefault(key, []).append(c)
        except Exception as exc:
            print(f"Notice: Unable to load structured control file {path}: {exc}")
    return grouped


def load_assessments() -> dict:
    """Returns {(jurisdiction, framework): [assessment_item, ...]}"""
    grouped: dict = {}
    for path in sorted(glob.glob(f"{config.ASSESSMENTS_DIR}/*.json")):
        with open(path, encoding="utf-8") as f:
            items = json.load(f)
        if not items:
            continue
        # Infer (jurisdiction, framework) from filename: nist__csf_assessment.json
        basename = os.path.basename(path)
        parts = basename.replace("_assessment.json", "").split("__")
        if len(parts) == 2:
            key = (parts[0], parts[1])
            grouped.setdefault(key, []).extend(items)
    return grouped


def load_mappings() -> list:
    """Returns [(base_fw, compare_fw, [mapping_dict, ...])]"""
    results = []
    for path in sorted(glob.glob(f"{config.MAPPINGS_DIR}/*.json")):
        with open(path, encoding="utf-8") as f:
            mappings = json.load(f)
        if not mappings:
            continue
        basename = os.path.basename(path).replace(".json", "")
        parts = basename.split("_vs_")
        if len(parts) == 2:
            results.append((parts[0], parts[1], mappings))
    return results


# ---------------------------------------------------------------------------
# Synthesis: Structured Controls  →  Q&A pairs
# ---------------------------------------------------------------------------
CONTROL_TEMPLATES = [
    # (question_template, answer_uses_description)
    ("What is {title}?",
     "{description}"),
    ("Explain {title} as defined under {jurisdiction} {framework}.",
     "{description}"),
    ("What does {framework} require regarding {title}?",
     "{description}"),
    ("What are the requirements for {title} in {jurisdiction}/{framework}?",
     "{description}"),
    ("Under {jurisdiction} {framework}, what does {control_label} cover?",
     "{description}"),
    ("Describe {title} in the context of {framework} compliance.",
     "{description}"),
    ("What obligations does {title} impose under {framework}?",
     "{description}"),
    ("What is the significance of {title} in {framework}?",
     "{description}"),
]

CONTROL_ID_TEMPLATES = [
    ("What does {framework} section {control_id} cover?",
     "{description}"),
    ("Summarize {jurisdiction} {framework} requirement {control_id}.",
     "{description}"),
    ("What is {framework} {control_id}: {title}?",
     "{description}"),
]


def synthesize_from_controls(controls: list, jurisdiction: str, framework: str) -> list:
    entries = []
    fw_display = framework.upper()
    jur_display = jurisdiction.capitalize()

    BOILERPLATE_BLACKLIST = [
        "PROHIBITED", "Abstraction: Base", "Vulnerability Mapping",
        "Weakness Ordinality", "Applicable Platforms", "Content History"
    ]

    for c in controls:
        title = (c.get("title") or "").strip()
        description = (c.get("description") or "").strip()
        control_id = (c.get("control_id") or "").strip()

        if not title or not description or len(description) < 20 or len(title) < 5:
            continue

        # Reject boilerplate noise and non-alpha titles
        if any(bp.lower() in title.lower() or bp.lower() in description[:100].lower() for bp in BOILERPLATE_BLACKLIST):
            continue

        alpha_ratio = sum(ch.isalpha() for ch in title) / max(len(title), 1)
        if alpha_ratio < 0.5:
            continue

        ctrl_label = f"{control_id}: {title}" if control_id else title

        fmt = dict(
            title=title,
            description=description,
            control_id=control_id,
            control_label=ctrl_label,
            jurisdiction=jur_display,
            framework=fw_display,
        )

        # Nemotron 3 Ultra / 70B Generation
        try:
            from utils.nemotron_processor import generate_nemotron_qa_pairs_for_control
            nemotron_entries = generate_nemotron_qa_pairs_for_control(control_id, title, description, framework, jurisdiction)
            if nemotron_entries:
                entries.extend(nemotron_entries)
        except Exception:
            pass

        # Apply general templates
        for q_tmpl, a_tmpl in CONTROL_TEMPLATES:
            q = q_tmpl.format(**fmt)
            a = a_tmpl.format(**fmt)
            e = _entry(q, a)
            if e:
                entries.append(e)

        # Apply control-id-specific templates (only when id is present)
        if control_id:
            for q_tmpl, a_tmpl in CONTROL_ID_TEMPLATES:
                q = q_tmpl.format(**fmt)
                a = a_tmpl.format(**fmt)
                e = _entry(q, a)
                if e:
                    entries.append(e)

    return entries


# ---------------------------------------------------------------------------
# Synthesis: Assessment results  →  Q&A pairs
# ---------------------------------------------------------------------------
ASSESSMENT_TEMPLATES = [
    ("Is our organization compliant with {title}?",
     "Status: {status}. {rationale}"),
    ("What is the compliance status of {title} under {framework}?",
     "Status: {status}. {rationale}"),
    ("Assess compliance with {framework} requirement: {title}.",
     "Status: {status}. {rationale}"),
    ("Are we meeting {title} requirements in {framework}?",
     "Status: {status}. {rationale}"),
]

ASSESSMENT_ID_TEMPLATES = [
    ("What is our compliance status for {framework} {control_id}?",
     "Status: {status}. {rationale}"),
    ("Is {framework} {control_id} ({title}) compliant?",
     "Status: {status}. {rationale}"),
]


def synthesize_from_assessments(items: list, jurisdiction: str, framework: str) -> list:
    entries = []
    fw_display = framework.upper()

    for item in items:
        title = (item.get("title") or "").strip()
        status = (item.get("status") or "").strip()
        rationale = (item.get("rationale") or "").strip()
        control_id = (item.get("control_id") or "").strip()

        if not title or not status or not rationale:
            continue
        if status == "No Evidence Found":
            continue  # skip — not useful training signal

        fmt = dict(
            title=title,
            status=status,
            rationale=rationale,
            control_id=control_id,
            framework=fw_display,
            jurisdiction=jurisdiction.capitalize(),
        )

        for q_tmpl, a_tmpl in ASSESSMENT_TEMPLATES:
            q = q_tmpl.format(**fmt)
            a = a_tmpl.format(**fmt)
            e = _entry(q, a)
            if e:
                entries.append(e)

        if control_id:
            for q_tmpl, a_tmpl in ASSESSMENT_ID_TEMPLATES:
                q = q_tmpl.format(**fmt)
                a = a_tmpl.format(**fmt)
                e = _entry(q, a)
                if e:
                    entries.append(e)

    return entries


# ---------------------------------------------------------------------------
# Synthesis: Control Mappings  →  Q&A pairs for BOTH domains
# ---------------------------------------------------------------------------
MAPPING_TEMPLATES = [
    ("How does {src_fw} {src_label} relate to {tgt_fw} {tgt_label}?",
     "These controls have a '{relationship}' relationship (similarity: {similarity:.2f}). "
     "{src_fw} {src_label} and {tgt_fw} {tgt_label} address similar security requirements."),
    ("Map {src_fw} control '{src_title}' to {tgt_fw}.",
     "It maps to {tgt_fw} {tgt_label} with a '{relationship}' relationship (similarity: {similarity:.2f})."),
    ("What is the {tgt_fw} equivalent of {src_fw} {src_label}?",
     "The closest {tgt_fw} control is {tgt_label}: '{tgt_title}'. "
     "Relationship: {relationship} (similarity: {similarity:.2f})."),
    ("Is there an overlap between {src_fw} {src_label} and {tgt_fw}?",
     "Yes. {tgt_fw} {tgt_label} overlaps with a '{relationship}' relationship "
     "(similarity: {similarity:.2f})."),
]


def synthesize_from_mappings(base_fw: str, compare_fw: str, mappings: list) -> dict:
    """Returns {domain_key: [entries]} where domain_key is 'framework' string."""
    domain_entries: dict = {base_fw: [], compare_fw: []}

    for m in mappings:
        src = m.get("source_control", {})
        tgt = m.get("target_control", {})
        relationship = m.get("relationship", "")
        similarity = float(m.get("similarity", 0))

        src_id    = (src.get("id") or src.get("title") or "").strip()
        src_title = (src.get("title") or "").strip()
        src_fw    = (src.get("framework") or base_fw).upper()
        tgt_id    = (tgt.get("id") or tgt.get("title") or "").strip()
        tgt_title = (tgt.get("title") or "").strip()
        tgt_fw    = (tgt.get("framework") or compare_fw).upper()

        if not src_id or not tgt_id or not relationship:
            continue

        src_label = f"{src_id}: {src_title[:40]}" if src_title else src_id
        tgt_label = f"{tgt_id}: {tgt_title[:40]}" if tgt_title else tgt_id

        fmt = dict(
            src_fw=src_fw, src_label=src_label, src_title=src_title,
            tgt_fw=tgt_fw, tgt_label=tgt_label, tgt_title=tgt_title,
            relationship=relationship, similarity=similarity,
        )

        for q_tmpl, a_tmpl in MAPPING_TEMPLATES:
            q = q_tmpl.format(**fmt)
            a = a_tmpl.format(**fmt)
            e = _entry(q, a)
            if e:
                # Add to both source and target domains
                domain_entries[base_fw].append(e)
                domain_entries[compare_fw].append(e)

    return domain_entries


# ---------------------------------------------------------------------------
# Main synthesis runner
# ---------------------------------------------------------------------------
def synthesize_domain(
    jurisdiction: str,
    framework: str,
    all_controls: dict,
    all_assessments: dict,
    all_mapping_entries: dict,
    min_examples: int = 50,
) -> list:
    """Combine all data sources for one domain and return final entry list."""
    entries = []
    key = (jurisdiction, framework)

    # 1. Controls (primary source)
    controls = all_controls.get(key, [])
    entries.extend(synthesize_from_controls(controls, jurisdiction, framework))

    # 1b. Full name / definition pairs
    fw_info = FRAMEWORK_FULL_NAMES.get(framework.lower(), {})
    if fw_info:
        fn = fw_info["full_name"]
        fd = fw_info["desc"]
        fw_upper = framework.upper()
        full_form_qas = [
            (f"What is the full form of {framework}?", f"The full form of {fw_upper} is {fn}. {fd}"),
            (f"What is the full form of {fw_upper}?", f"The full form of {fw_upper} is {fn}. {fd}"),
            (f"What does {framework} stand for?", f"{fw_upper} stands for {fn}. {fd}"),
            (f"What does {fw_upper} stand for?", f"{fw_upper} stands for {fn}. {fd}"),
            (f"What is the full name of {framework}?", f"The full name of {fw_upper} is {fn}."),
            (f"What is {fw_upper}?", f"{fn} ({fw_upper}): {fd}"),
            (f"What is {framework}?", f"{fn} ({fw_upper}): {fd}"),
            (f"Define {fw_upper}.", f"{fn} ({fw_upper}): {fd}"),
            (f"Explain {fw_upper}.", f"{fn} ({fw_upper}): {fd}"),
        ]
        for q, a in full_form_qas:
            e = _entry(q, a)
            if e:
                # Add multiple copies to emphasize full name during training
                for _ in range(5):
                    entries.append(e)

    # 2. Assessment results
    items = all_assessments.get(key, [])
    entries.extend(synthesize_from_assessments(items, jurisdiction, framework))

    # 3. Mapping contributions (from both sides of any mapping involving this fw)
    entries.extend(all_mapping_entries.get(framework, []))

    # Deduplicate by instruction text
    seen = set()
    unique = []
    for e in entries:
        k = e["instruction"].lower().strip()
        if k not in seen:
            seen.add(k)
            unique.append(e)

    # Shuffle for training diversity
    random.shuffle(unique)

    print(f"  [{jurisdiction}/{framework}] synthesized {len(unique)} unique examples "
          f"(controls={len(controls)}, assessments={len(items)})")
    return unique


def run(target_domains: list = None) -> dict:
    """
    Synthesize training data for all (or specified) domains.
    Returns {(jurisdiction, framework): num_examples_written}
    """
    print("Loading data sources...")
    all_controls    = load_structured_controls()
    all_assessments = load_assessments()
    raw_mappings    = load_mappings()

    # Pre-process mappings into per-framework contribution dicts
    all_mapping_entries: dict = {}
    for base_fw, compare_fw, mappings in raw_mappings:
        domain_entries = synthesize_from_mappings(base_fw, compare_fw, mappings)
        for fw, entries in domain_entries.items():
            all_mapping_entries.setdefault(fw, []).extend(entries)

    # Determine which domains to process
    all_domains = list(all_controls.keys())
    if target_domains:
        # target_domains is list of "jurisdiction/framework" strings
        td_set = {(d.split("/")[0], d.split("/")[1]) for d in target_domains}
        domains = [d for d in all_domains if d in td_set]
    else:
        domains = all_domains

    results = {}
    for (jur, fw) in domains:
        print(f"\nSynthesizing: {jur}/{fw}")
        entries = synthesize_domain(jur, fw, all_controls, all_assessments, all_mapping_entries)

        if not entries:
            print(f"  WARNING: No examples generated for {jur}/{fw}, skipping.")
            continue

        slug = _framework_slug(fw)
        adapter_dir = os.path.join(ADAPTERS_DIR, f"qwen3-{slug}-lora")
        os.makedirs(adapter_dir, exist_ok=True)

        raw_out_path = os.path.join(adapter_dir, "train_raw.jsonl")
        out_path = os.path.join(adapter_dir, "train.jsonl")
        with open(raw_out_path, "w", encoding="utf-8") as f:
            for e in entries:
                f.write(json.dumps(e, ensure_ascii=False) + "\n")

        # Pass through Nemotron quality filtering engine
        try:
            from utils.nemotron_processor import filter_dataset_file
            stats = filter_dataset_file(raw_out_path, out_path)
            print(f"  [Nemotron 2-Stage Gate] Modified & Retained {stats['modified_and_retained']}/{stats['total_raw']} entries -> {out_path}")
            if os.path.exists(raw_out_path):
                os.remove(raw_out_path)
        except Exception as exc:
            # Fallback to direct write if filtering module has exception
            with open(out_path, "w", encoding="utf-8") as f:
                for e in entries:
                    f.write(json.dumps(e, ensure_ascii=False) + "\n")
            print(f"  Written {len(entries)} examples -> {out_path}")

        results[(jur, fw)] = len(entries)

    print(f"\nDone. Synthesized data for {len(results)} domain(s).")
    return results


def main():
    parser = argparse.ArgumentParser(description="Agent 6: Training Data Synthesis")
    parser.add_argument(
        "--domain",
        nargs="*",
        help="Specific domain(s) to process, e.g. india/dpdp eu/gdpr. Default: all.",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="List available domains and exit.",
    )
    args = parser.parse_args()

    if args.list:
        controls = load_structured_controls()
        print("Available domains:")
        for jur, fw in sorted(controls.keys()):
            n = len(controls[(jur, fw)])
            print(f"  {jur}/{fw}  ({n} controls)")
        return

    run(target_domains=args.domain)


if __name__ == "__main__":
    main()

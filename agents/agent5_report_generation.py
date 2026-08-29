"""
Agent 5 — Report Generation Agent
-------------------------------------
Takes the output of Agent 4 (compliance assessment) and optionally Agent 3
(control mappings), and produces a readable Markdown compliance report:
summary statistics, a gap analysis (Not Compliant / Partially Compliant
controls), and remediation recommendations.

Run with:
    python agents/agent5_report_generation.py --framework nist/csf
"""

import os
import json
import glob
import argparse
from datetime import datetime
from typing import Optional, List, Dict, Any

import config

REMEDIATION_PROMPT = """A cybersecurity control was assessed as "{status}".

Control: {title} — {rationale}

In 1-2 sentences, recommend a concrete remediation action to close this gap."""


def load_assessment(jurisdiction: str, framework: str) -> list[dict]:
    path = os.path.join(config.ASSESSMENTS_DIR, f"{jurisdiction}__{framework}_assessment.json")
    if not os.path.exists(path):
        raise FileNotFoundError(f"No assessment found at {path}. Run Agent 4 first.")
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def load_all_mappings() -> list[dict]:
    """Load all mapping files produced by Agent 3."""
    all_mappings = []
    for path in sorted(glob.glob(os.path.join(config.MAPPINGS_DIR, "*.json"))):
        with open(path, encoding="utf-8") as f:
            mappings = json.load(f)
        for m in mappings:
            m["_file"] = os.path.basename(path)
        all_mappings.extend(mappings)
    return all_mappings


def generate_remediation(item: dict) -> str:
    prompt = REMEDIATION_PROMPT.format(
        status=item["status"],
        title=item["title"],
        rationale=item["rationale"]
    )
    return config.generate(prompt, max_new_tokens=80)


def build_report(
    jurisdiction: str,
    framework: str,
    assessment: list[dict],
    with_remediation: bool = True,
) -> str:
    total = len(assessment)
    counts = {"Compliant": 0, "Partially Compliant": 0, "Not Compliant": 0, "No Evidence Found": 0}
    for item in assessment:
        counts[item["status"]] = counts.get(item["status"], 0) + 1

    lines = []

    # ------------------------------------------------------------------ header
    lines.append(f"# ComplianceMesh — Compliance Report")
    lines.append(f"## Framework: {jurisdiction.upper()} / {framework.upper()}")
    lines.append(f"\n**Generated**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  ")
    lines.append(f"**Total controls assessed**: {total}  ")
    lines.append(f"**Tool**: ComplianceMesh — Multi-Agent Cybersecurity Compliance Framework  ")

    # --------------------------------------------------------- executive summary
    compliance_pct = (counts["Compliant"] / total * 100) if total else 0
    gap_pct = ((counts["Partially Compliant"] + counts["Not Compliant"]) / total * 100) if total else 0
    lines.append("\n---\n")
    lines.append("## Executive Summary")
    lines.append(
        f"This automated compliance assessment evaluated **{total} controls** from the "
        f"{framework.upper()} framework against the organization's submitted evidence. "
        f"**{counts['Compliant']} controls ({compliance_pct:.1f}%)** are fully compliant. "
        f"**{counts['Partially Compliant'] + counts['Not Compliant']} controls ({gap_pct:.1f}%)** "
        f"have identified gaps requiring remediation. "
        f"**{counts['No Evidence Found']} controls** could not be assessed due to missing evidence."
    )

    # --------------------------------------------------------------- summary table
    lines.append("\n---\n")
    lines.append("## Summary")
    lines.append("| Status | Count | Percentage |")
    lines.append("|---|---|---|")
    for status, count in counts.items():
        pct = (count / total * 100) if total else 0
        emoji = {"Compliant": "✅", "Partially Compliant": "⚠️", "Not Compliant": "❌", "No Evidence Found": "❓"}.get(status, "")
        lines.append(f"| {emoji} {status} | {count} | {pct:.1f}% |")

    # --------------------------------------------------------- cross-framework mappings
    mappings = load_all_mappings()
    if mappings:
        lines.append("\n---\n")
        lines.append("## Cross-Framework Control Mappings")
        lines.append(
            f"Agent 3 identified **{len(mappings)} cross-framework control equivalences** "
            f"across all ingested standards:"
        )
        lines.append("")
        lines.append("| Source Framework | Source Control | Relationship | Target Framework | Target Control | Similarity |")
        lines.append("|---|---|---|---|---|---|")
        for m in mappings:
            src = m.get("source_control", {})
            tgt = m.get("target_control", {})
            src_label = f"{src.get('id', 'UNKNOWN')}"
            tgt_label = f"{tgt.get('id', 'UNKNOWN')}"
            src_title = (src.get("title") or "")[:50]
            tgt_title = (tgt.get("title") or "")[:50]
            rel = m.get("relationship", "")
            sim = m.get("similarity", 0)
            lines.append(
                f"| {src.get('framework','').upper()} | {src_label}: {src_title} "
                f"| {rel} | {tgt.get('framework','').upper()} "
                f"| {tgt_label}: {tgt_title} | {sim} |"
            )

    # ---------------------------------------------------------------- gap analysis
    lines.append("\n---\n")
    lines.append("## Gap Analysis")
    gaps = [
        item for item in assessment
        if item["status"] in ("Not Compliant", "Partially Compliant", "No Evidence Found")
    ]

    if not gaps:
        lines.append("\nNo gaps identified — all assessed controls are Compliant.")
    else:
        lines.append(f"\n{len(gaps)} controls require attention:\n")
        for item in gaps:
            control_id = item.get("control_id") or "UNKNOWN"
            title = item.get("title") or ""
            lines.append(f"\n### {control_id} — {title}")
            lines.append(f"- **Status**: {item['status']}")
            lines.append(f"- **Rationale**: {item['rationale']}")
            if item.get("evidence_source"):
                sim_score = item.get('evidence_similarity', item.get('similarity_score', 'N/A'))
                lines.append(
                    f"- **Evidence reviewed**: `{item['evidence_source']}` "
                    f"(similarity score: {sim_score})"
                )
            else:
                lines.append("- **Evidence reviewed**: None found")
            if with_remediation:
                remediation = generate_remediation(item)
                lines.append(f"- **Recommended remediation**: {remediation}")

    # --------------------------------------------------------- compliant controls
    lines.append("\n---\n")
    lines.append("## Fully Compliant Controls")
    compliant = [item for item in assessment if item["status"] == "Compliant"]
    if compliant:
        lines.append(f"\n{len(compliant)} controls are fully compliant:\n")
        lines.append("| Control ID | Title |")
        lines.append("|---|---|")
        for item in compliant:
            lines.append(f"| **{item.get('control_id','UNKNOWN')}** | {item.get('title','')} |")
    else:
        lines.append("\nNone.")

    lines.append("\n---\n")
    lines.append("*Report generated by ComplianceMesh — Multi-Agent AI Framework for Cybersecurity Compliance*")

    raw_report = "\n".join(lines)
    healed_report, _ = verify_and_heal_report(raw_report, f"Compliance audit report for {jurisdiction}/{framework}")
    return healed_report


def verify_and_heal_report(
    report_md: str,
    query_context: str = "Compliance Assessment Report Verification",
    framework: str = "general",
    assessment: Optional[list] = None,
    live_evidence: Optional[list] = None
) -> tuple[str, bool]:
    """
    Bypassed Verification Gate: Directly returns the generated compliance report 
    without post-processing through external LLM APIs.
    """
    return report_md, False


def generate_consolidated_multi_framework_report(
    client_name: str,
    framework_list: list[str],
    with_remediation: bool = True,
) -> tuple[str, str]:
    """
    Agent 5 Multi-Adapter Consolidated Report Generator:
    Executes assessments across all applicable frameworks (e.g. GDPR + NIS2 + PCI-DSS)
    and produces ONE consolidated Markdown audit report.
    Returns (report_markdown, report_file_path).
    """
    import adapter_classification
    import agents.agent4_compliance_assessment as agent4
    import remediation_tracker_engine as rte

    assessments = {}
    for fw in framework_list:
        fw_clean = fw.strip()
        if "/" in fw_clean:
            j, f = fw_clean.split("/", 1)
            raw_items = agent4.assess_compliance(j, f)
            synced_items = rte.sync_assessment_remediations(client_name, fw_clean, raw_items)
            assessments[fw_clean] = synced_items
        elif "__" in fw_clean:
            j, f = fw_clean.split("__", 1)
            raw_items = agent4.assess_compliance(j, f)
            synced_items = rte.sync_assessment_remediations(client_name, f"{j}/{f}", raw_items)
            assessments[f"{j}/{f}"] = synced_items

    import robustness_governance as rg

    raw_report_md = adapter_classification.generate_consolidated_report_markdown(
        client_name=client_name,
        assessments_by_framework=assessments,
        with_remediation=with_remediation,
    )
    
    report_md, was_healed = verify_and_heal_report(raw_report_md, f"Consolidated compliance audit report for {client_name}")

    os.makedirs(config.REPORTS_DIR, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_id = f"REP_{client_name.upper()}_{timestamp}"

    # 1. Submit for Human-in-the-Loop Expert Review Gate
    rg.submit_report_for_human_review(
        report_id=report_id,
        client_id=client_name,
        frameworks=framework_list,
        report_markdown=report_md
    )

    # 2. Trace MLOps Lineage for Adapter Fleet
    for fw in framework_list:
        rg.log_adapter_run_lineage(
            report_id=report_id,
            client_id=client_name,
            framework=fw,
            adapter_name=f"qwen3-{fw.replace('/', '_').replace('-', '')}-lora",
            adapter_version="v1.2.0"
        )

    out_path = os.path.join(
        config.REPORTS_DIR,
        f"consolidated_{client_name.lower().replace(' ', '_')}_report_{timestamp}.md"
    )
    with open(out_path, "w", encoding="utf-8-sig") as f:
        f.write(report_md)

    return report_md, out_path


def main():
    parser = argparse.ArgumentParser(description="Agent 5: Report Generation")
    parser.add_argument("--framework", required=True, help="e.g. nist/csf")
    parser.add_argument(
        "--no-remediation", action="store_true",
        help="Skip LLM remediation suggestions (faster, useful for quick drafts)"
    )
    args = parser.parse_args()

    jurisdiction, framework = args.framework.split("/")
    assessment = load_assessment(jurisdiction, framework)

    report = build_report(
        jurisdiction, framework, assessment,
        with_remediation=not args.no_remediation
    )

    os.makedirs(config.REPORTS_DIR, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_path = os.path.join(
        config.REPORTS_DIR,
        f"{jurisdiction}__{framework}_report_{timestamp}.md"
    )
    # UTF-8 with BOM ensures Windows apps (Notepad, Word) render special chars correctly
    with open(out_path, "w", encoding="utf-8-sig") as f:
        f.write(report)

    print(f"Report generated -> {out_path}")


if __name__ == "__main__":
    main()
"""
Agent 10 — Automated Active Learning & Continuous Alignment Orchestrator
-------------------------------------------------------------------------
Monitors auditor evaluations (+1 / -1 ratings & remediations), evaluates domain
error thresholds, and automatically triggers alignment retraining:
  - If preference pairs >= min_dpo_pairs (default: 5) -> runs DPO (Agent 8)
  - If negative feedback >= sft_threshold (default: 10) -> runs Enhanced SFT (Agent 7)
  - Hot-reloads updated LoRA adapters seamlessly without restarting the server.

Usage:
  ./venv/bin/python3 agents/agent10_active_learning.py --status
  ./venv/bin/python3 agents/agent10_active_learning.py --run --threshold 5
  ./venv/bin/python3 agents/agent10_active_learning.py --framework dpdp --force
"""

import os
import sys
import json
import time
import argparse
from typing import Dict, Any, List, Optional

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

AGENTS_DIR = os.path.join(PROJECT_ROOT, "agents")
if AGENTS_DIR not in sys.path:
    sys.path.insert(0, AGENTS_DIR)

import core.feedback_collector as fb_col

try:
    import pipeline_logger as plog
    _HAS_PLOG = True
except ImportError:
    _HAS_PLOG = False


def get_alignment_status() -> Dict[str, Any]:
    """
    Summarizes feedback volume and alignment readiness across all compliance frameworks.
    """
    stats = fb_col.get_feedback_count_by_framework()
    overall = fb_col.get_feedback_statistics()

    framework_readiness = {}
    for fw, data in stats.items():
        if fw in ("Auto-Detect", "General"):
            continue
        remediations = data.get("with_remediation", 0)
        negatives = data.get("negative", 0)
        total = data.get("total", 0)

        # Decide alignment recommendation
        if remediations >= 5:
            rec = "DPO Alignment Ready"
            action = "dpo"
        elif negatives >= 5 or total >= 10:
            rec = "Enhanced SFT Ready"
            action = "sft"
        else:
            rec = "Collecting Feedback"
            action = "none"

        framework_readiness[fw] = {
            **data,
            "recommendation": rec,
            "action": action
        }

    return {
        "overall": overall,
        "frameworks": framework_readiness,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
    }


def run_continuous_alignment(
    framework: Optional[str] = None,
    sft_threshold: int = 10,
    min_dpo_pairs: int = 5,
    epochs: int = 2,
    force: bool = False
) -> Dict[str, Any]:
    """
    Executes the continuous alignment pipeline for candidate frameworks.
    """
    status = get_alignment_status()
    fw_dict = status["frameworks"]
    results = {"dpo_trained": [], "sft_trained": [], "skipped": []}

    targets = [framework] if framework else list(fw_dict.keys())

    for fw in targets:
        if fw not in fw_dict and not force:
            continue

        info = fw_dict.get(fw, {"with_remediation": 0, "negative": 0, "total": 0})
        remediations = info.get("with_remediation", 0)
        negatives = info.get("negative", 0)

        # Step 1: Check if DPO is viable
        if remediations >= min_dpo_pairs or (force and remediations > 0):
            print(f"\n[Agent 10] Triggering DPO Alignment for '{fw}' ({remediations} preference pairs)...")
            if _HAS_PLOG:
                plog.log_stage("agent10_alignment", f"Starting DPO training for {fw}", extra={"remediations": remediations})
            try:
                import agent8_dpo_trainer
                out_path = agent8_dpo_trainer.train_dpo_adapter(
                    jurisdiction="compliance",
                    framework=fw,
                    num_epochs=epochs,
                    min_pairs=1 if force else min_dpo_pairs
                )
                if out_path:
                    results["dpo_trained"].append(fw)
            except Exception as e:
                print(f"[Agent 10] DPO training failed for {fw}: {e}")

        # Step 2: Check if Enhanced SFT is needed
        elif negatives >= sft_threshold or force:
            print(f"\n[Agent 10] Triggering Enhanced SFT for '{fw}' ({negatives} negative samples)...")
            if _HAS_PLOG:
                plog.log_stage("agent10_alignment", f"Starting Enhanced SFT for {fw}", extra={"negatives": negatives})
            try:
                import agent7_lora_trainer
                out_path = agent7_lora_trainer.train_adapter(
                    jurisdiction="compliance",
                    framework=fw,
                    num_epochs=epochs,
                    include_feedback=True
                )
                if out_path:
                    results["sft_trained"].append(fw)
            except Exception as e:
                print(f"[Agent 10] SFT training failed for {fw}: {e}")
        else:
            results["skipped"].append({
                "framework": fw,
                "reason": f"Under threshold (Remediations: {remediations}/{min_dpo_pairs}, Negatives: {negatives}/{sft_threshold})"
            })

    return results


def main():
    parser = argparse.ArgumentParser(description="Agent 10: Active Learning & Alignment Orchestrator")
    parser.add_argument("--status", action="store_true", help="Print current alignment readiness statistics")
    parser.add_argument("--run", action="store_true", help="Run alignment loop for eligible frameworks")
    parser.add_argument("--framework", type=str, help="Specific framework to align (e.g. dpdp, gdpr)")
    parser.add_argument("--threshold", type=int, default=10, help="Negative feedback threshold for SFT (default: 10)")
    parser.add_argument("--min-dpo", type=int, default=5, help="Minimum preference pairs for DPO (default: 5)")
    parser.add_argument("--epochs", type=int, default=2, help="Training epochs (default: 2)")
    parser.add_argument("--force", action="store_true", help="Force retraining regardless of threshold")
    args = parser.parse_args()

    if args.status:
        st = get_alignment_status()
        print("\n" + "=" * 65)
        print(f"Compliance Active Learning Status [{st['timestamp']}]")
        print("=" * 65)
        print(f"Total Reviews   : {st['overall']['total_reviews']}")
        print(f"Approval Rate   : {st['overall']['approval_rate_pct']}%")
        print("-" * 65)
        for fw, f_info in st["frameworks"].items():
            print(f"• {fw.upper():<12}: Total={f_info['total']:<3} (+{f_info['positive']}/-{f_info['negative']}) | Remediations={f_info['with_remediation']:<2} -> [{f_info['recommendation']}]")
        print("=" * 65 + "\n")

    elif args.run or args.framework:
        res = run_continuous_alignment(
            framework=args.framework,
            sft_threshold=args.threshold,
            min_dpo_pairs=args.min_dpo,
            epochs=args.epochs,
            force=args.force
        )
        print("\nExecution Summary:")
        print(json.dumps(res, indent=2))
    else:
        parser.print_help()


if __name__ == "__main__":
    main()

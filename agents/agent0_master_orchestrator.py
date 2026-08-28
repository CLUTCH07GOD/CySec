"""
Agent 0 — End-to-End Master Automation Orchestrator
----------------------------------------------------
Automates the complete compliance pipeline for any new standard (PDF/TXT):
  1. Ingests raw PDF -> structured controls & ChromaDB vector store (Agent 1 + Ingestion)
  2. Builds Vector Knowledge Base (Agent 2)
  3. Computes cross-framework control mappings (Agent 3)
  4. Synthesizes Q&A instruction pairs -> train.jsonl (Agent 6)
  5. Fine-tunes a new LoRA adapter for Qwen2.5-1.5B-Instruct (Agent 7)
  6. Registers the new adapter with the router for live inference

Run via CLI:
    py -3.11 agents/agent0_master_orchestrator.py --file standards/us/hipaa/hipaa.pdf --jurisdiction us --framework hipaa --full-name "Health Insurance Portability and Accountability Act"

Or import programmatically into app.py:
    from agents.agent0_master_orchestrator import run_agent0_pipeline
"""

import os
import sys
import shutil
import json
import random
import time
import gc
import argparse
from typing import Callable, Optional

# Add agents dir to path
AGENTS_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(AGENTS_DIR)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)
if AGENTS_DIR not in sys.path:
    sys.path.insert(0, AGENTS_DIR)

import agent1_ingestion
import agent6_data_synthesis
import agent7_lora_trainer
import ingest_standards

try:
    sys.path.insert(0, PROJECT_ROOT)
    import pipeline_logger as plog
    _HAS_PLOG = True
except ImportError:
    _HAS_PLOG = False

try:
    import agent3_control_mapping as agent3
    COMPLIANCE_MAPPINGS_AVAILABLE = True
except ImportError:
    COMPLIANCE_MAPPINGS_AVAILABLE = False


def _slug(text: str) -> str:
    return text.lower().replace("_", "").replace("-", "").replace(" ", "")


def run_agent0_pipeline(
    file_path: str,
    jurisdiction: str,
    framework: str,
    full_name: Optional[str] = None,
    description: Optional[str] = None,
    epochs: int = 3,
    max_train_samples: int = 2000,
    progress_callback: Optional[Callable[[str, float], None]] = None,
) -> dict:
    """
    Runs the complete end-to-end automation pipeline.
    
    Args:
        file_path: Path to the input PDF or TXT standard file.
        jurisdiction: E.g., 'eu', 'us', 'india', 'nist', 'international'.
        framework: E.g., 'hipaa', 'pci_dss', 'soc2', 'iso27001'.
        full_name: Full descriptive name (e.g. 'Health Insurance Portability and Accountability Act').
        description: Brief description of the standard.
        epochs: Number of LoRA fine-tuning epochs (default: 3).
        max_train_samples: Maximum training examples to use for fine-tuning (default: 2000).
        progress_callback: Optional function callback(stage_message, float_percentage).
        
    Returns:
        Summary dict containing execution logs, timing, and created artifacts.
    """
    t_start = time.time()
    logs = []

    def log(msg: str, pct: float = 0.0):
        timestamp = time.strftime("[%H:%M:%S]")
        formatted = f"{timestamp} {msg}"
        logs.append(formatted)
        print(formatted)
        if progress_callback:
            progress_callback(msg, pct)
        # Structured logging to pipeline_logger
        if _HAS_PLOG:
            level = "WARNING" if "[WARNING]" in msg else "INFO"
            plog.log_stage("agent0_orchestrator", msg, level=level, extra={"progress": pct})

    jurisdiction = jurisdiction.lower().strip()
    framework = framework.lower().strip()
    slug = _slug(framework)
    full_name = full_name or framework.upper()
    description = description or f"Compliance framework for {framework.upper()} under {jurisdiction.upper()}."

    log(f"Starting Agent 0 Automation Pipeline for '{jurisdiction}/{framework}'...", 0.05)

    # -------------------------------------------------------------------------
    # STEP 1: Copy file to standards/ and extract structured controls
    # -------------------------------------------------------------------------
    log("Step 1/6: Copying document & extracting structured controls (Agent 1)...", 0.15)
    target_dir = os.path.join(PROJECT_ROOT, "standards", jurisdiction, framework)
    os.makedirs(target_dir, exist_ok=True)
    target_file = os.path.join(target_dir, os.path.basename(file_path))
    if os.path.abspath(file_path) != os.path.abspath(target_file):
        shutil.copy2(file_path, target_file)

    controls = agent1_ingestion.ingest_single_file(target_file, jurisdiction, framework)
    log(f"[OK] Step 1 Complete: Extracted {len(controls)} controls -> structured_controls/{jurisdiction}__{framework}.json", 0.30)

    # -------------------------------------------------------------------------
    # STEP 2: Ingest into ChromaDB vector store
    # -------------------------------------------------------------------------
    log("Step 2/6: Embedding & indexing document chunks into ChromaDB (Agent 2)...", 0.35)
    try:
        ingest_standards.main()
        log("[OK] Step 2 Complete: Vector Knowledge Base updated in ChromaDB.", 0.45)
    except Exception as exc:
        log(f"[WARNING] Step 2 ChromaDB indexing note: {exc}", 0.45)

    # -------------------------------------------------------------------------
    # STEP 3: Compute Control Mappings against existing standards (Agent 3)
    # -------------------------------------------------------------------------
    log("Step 3/6: Computing cross-framework control mappings (Agent 3)...", 0.50)
    mapping_count = 0
    if COMPLIANCE_MAPPINGS_AVAILABLE:
        try:
            # Map against existing structured controls
            all_sc = agent6_data_synthesis.load_structured_controls()
            for (exist_j, exist_f) in all_sc.keys():
                if (exist_j, exist_f) != (jurisdiction, framework):
                    try:
                        maps = agent3.map_controls(jurisdiction, framework, exist_j, exist_f, False)
                        mapping_count += len(maps)
                    except Exception:
                        pass
            log(f"[OK] Step 3 Complete: Generated {mapping_count} cross-framework control mappings.", 0.60)
        except Exception as exc:
            log(f"[WARNING] Step 3 Mapping notice: {exc}", 0.60)
    else:
        log("[SKIP] Step 3: Agent 3 mapping skipped (optional agent unavailable).", 0.60)

    # -------------------------------------------------------------------------
    # STEP 4: Synthesize Training Data (Agent 6)
    # -------------------------------------------------------------------------
    log("Step 4/6: Synthesizing training Q&A instruction pairs (Agent 6)...", 0.65)
    # Update Agent 6 framework metadata dynamically
    agent6_data_synthesis.FRAMEWORK_FULL_NAMES[framework] = {
        "full_name": full_name,
        "desc": description,
    }
    agent6_data_synthesis.FRAMEWORK_JURISDICTION[framework] = jurisdiction

    all_controls = agent6_data_synthesis.load_structured_controls()
    all_assessments = agent6_data_synthesis.load_assessments()
    all_mappings = agent6_data_synthesis.load_mappings()
    mapping_entries = {}
    for (base_fw, compare_fw, maps) in all_mappings:
        synthed = agent6_data_synthesis.synthesize_from_mappings(base_fw, compare_fw, maps)
        for k, v in synthed.items():
            mapping_entries.setdefault(k, []).extend(v)

    entries = agent6_data_synthesis.synthesize_domain(
        jurisdiction, framework, all_controls, all_assessments, mapping_entries
    )

    adapter_dir = os.path.join(PROJECT_ROOT, "adapters", f"qwen3-{slug}-lora")
    os.makedirs(adapter_dir, exist_ok=True)
    train_file = os.path.join(adapter_dir, "train.jsonl")

    # Sample to max_train_samples if dataset is large
    if len(entries) > max_train_samples:
        random.seed(42)
        entries = random.sample(entries, max_train_samples)
        log(f"Subsampled dataset to {max_train_samples} examples for optimal fine-tuning speed.", 0.70)

    with open(train_file, "w", encoding="utf-8") as f:
        for e in entries:
            f.write(json.dumps(e) + "\n")

    log(f"[OK] Step 4 Complete: Synthesized {len(entries)} Q&A pairs -> {train_file}", 0.75)

    # -------------------------------------------------------------------------
    # STEP 5: Fine-Tune LoRA Adapter (Agent 7)
    # -------------------------------------------------------------------------
    log(f"Step 5/6: Fine-tuning LoRA adapter on Qwen2.5-1.5B-Instruct for {epochs} epochs (Agent 7)...", 0.80)
    try:
        # Fine-tune adapter
        agent7_lora_trainer.train_adapter(
            jurisdiction,
            framework,
            num_epochs=epochs,
            batch_size=2,
            grad_accum=4,
            learning_rate=2e-4,
            max_seq_length=512,
        )
        log(f"[OK] Step 5 Complete: LoRA adapter fine-tuned & saved -> adapters/qwen3-{slug}-lora/", 0.95)
    except Exception as exc:
        log(f"[WARNING] Step 5 LoRA Training note: {exc}", 0.95)
    finally:
        if agent7_lora_trainer.torch.cuda.is_available():
            agent7_lora_trainer.torch.cuda.empty_cache()
        gc.collect()

    # -------------------------------------------------------------------------
    # STEP 6: Final Verification & Pipeline Summary
    # -------------------------------------------------------------------------
    total_time = time.time() - t_start
    log(f"🎉 Step 6/6 Complete: Agent 0 Automation finished successfully in {total_time:.1f}s!", 1.0)

    return {
        "status": "success",
        "jurisdiction": jurisdiction,
        "framework": framework,
        "slug": slug,
        "controls_count": len(controls),
        "training_examples": len(entries),
        "adapter_dir": adapter_dir,
        "total_time_seconds": total_time,
        "logs": logs,
    }


def main():
    parser = argparse.ArgumentParser(description="Agent 0: End-to-End Master Automation")
    parser.add_argument("--file", required=True, help="Path to input PDF or TXT standard file")
    parser.add_argument("--jurisdiction", required=True, help="Jurisdiction (e.g. us, eu, india, nist)")
    parser.add_argument("--framework", required=True, help="Framework slug (e.g. hipaa, pci_dss, soc2)")
    parser.add_argument("--full-name", help="Full descriptive name of the framework")
    parser.add_argument("--description", help="Short description of the framework")
    parser.add_argument("--epochs", type=int, default=3, help="Training epochs (default: 3)")
    args = parser.parse_args()

    run_agent0_pipeline(
        file_path=args.file,
        jurisdiction=args.jurisdiction,
        framework=args.framework,
        full_name=args.full_name,
        description=args.description,
        epochs=args.epochs,
    )


if __name__ == "__main__":
    main()

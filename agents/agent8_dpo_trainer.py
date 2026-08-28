"""
Agent 8 — Direct Preference Optimization (DPO) Trainer
-------------------------------------------------------
Optimizes domain-specific LoRA adapters directly from auditor preference pairs
(chosen vs. rejected responses) without needing a separate reward model or
costly PPO reinforcement learning loops.

Data sources:
  1. High-quality remediation pairs: (Prompt, Auditor Remediation [Chosen], Model Error [Rejected])
  2. Contrast pairs: Same query with +1 positive answer vs -1 negative answer.
  3. Pre-synthesized preference pairs from Agent 6/domains.

Saved output:
  adapters/qwen3-<slug>-dpo-lora/

Usage:
  ./venv/bin/python3 agents/agent8_dpo_trainer.py --domain india/dpdp
  ./venv/bin/python3 agents/agent8_dpo_trainer.py --domain eu/gdpr --epochs 3 --beta 0.1
  ./venv/bin/python3 agents/agent8_dpo_trainer.py --all --min-pairs 10
  ./venv/bin/python3 agents/agent8_dpo_trainer.py --domain india/dpdp --dry-run
"""

import os
import sys
import glob
import json
import argparse
from typing import Optional

# Ensure project root in sys.path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

_MISSING = []
try:
    import torch
except ImportError:
    _MISSING.append("torch")
try:
    import transformers
    from transformers import AutoModelForCausalLM, AutoTokenizer, TrainingArguments
except ImportError:
    _MISSING.append("transformers")
try:
    import peft
    from peft import LoraConfig, get_peft_model, TaskType, PeftModel
except ImportError:
    _MISSING.append("peft")
try:
    import trl
    from trl import DPOTrainer, DPOConfig
except ImportError:
    _MISSING.append("trl")
try:
    import datasets
    from datasets import Dataset, load_dataset
except ImportError:
    _MISSING.append("datasets")

if _MISSING:
    print(f"[WARNING] Missing packages for DPO training: {', '.join(_MISSING)}")

import core.feedback_collector as fb_col

BASE_MODEL_NAME = "Qwen/Qwen2.5-1.5B-Instruct"
ADAPTERS_DIR    = os.path.join(PROJECT_ROOT, "adapters")
DOMAINS_DIR     = os.path.join(PROJECT_ROOT, "domains")

LORA_CONFIG = LoraConfig(
    r=16,
    lora_alpha=32,
    lora_dropout=0.05,
    bias="none",
    task_type=TaskType.CAUSAL_LM,
    target_modules=[
        "q_proj", "k_proj", "v_proj", "o_proj",
        "gate_proj", "up_proj", "down_proj",
    ],
)


def _framework_slug(framework: str) -> str:
    return framework.replace("_", "").replace("-", "").lower()


def get_device() -> str:
    if torch.backends.mps.is_available():
        return "mps"
    if torch.cuda.is_available():
        return "cuda"
    return "cpu"


def collect_dpo_dataset(framework: str, target_dir: str) -> tuple[str, int]:
    """
    Exports and merges active preference pairs for the given framework.
    Returns (dataset_path, pair_count).
    """
    os.makedirs(target_dir, exist_ok=True)
    dpo_file = os.path.join(target_dir, "dpo_pairs.jsonl")

    # 1. Export from live SQLite feedback DB
    count, _ = fb_col.export_dpo_pairs(framework=framework, output_path=dpo_file)
    
    # 2. If framework specific domain pairs exist in domains/ or adapter dir, merge them
    domain_pref_file = os.path.join(DOMAINS_DIR, f"{_framework_slug(framework)}_dpo_pairs.jsonl")
    if os.path.exists(domain_pref_file):
        existing_items = []
        if os.path.exists(dpo_file):
            with open(dpo_file, "r", encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        existing_items.append(json.loads(line))
        with open(domain_pref_file, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    existing_items.append(json.loads(line))
        with open(dpo_file, "w", encoding="utf-8") as f:
            for item in existing_items:
                f.write(json.dumps(item) + "\n")
        count = len(existing_items)

    return dpo_file, count


def train_dpo_adapter(
    jurisdiction: str,
    framework: str,
    num_epochs: int = 3,
    batch_size: int = 1,
    grad_accum: int = 4,
    learning_rate: float = 5e-5,
    beta: float = 0.1,
    max_seq_length: int = 512,
    max_prompt_length: int = 256,
    min_pairs: int = 5,
    dry_run: bool = False,
) -> Optional[str]:
    """
    Trains a DPO preference-aligned adapter for the given jurisdiction/framework.
    """
    slug = _framework_slug(framework)
    dpo_adapter_dir = os.path.join(ADAPTERS_DIR, f"qwen3-{slug}-dpo-lora")
    sft_adapter_dir = os.path.join(ADAPTERS_DIR, f"qwen3-{slug}-lora")

    print(f"\n{'='*65}")
    print(f"DPO Preference Optimization: {jurisdiction}/{framework}")
    print(f"  Target Adapter Dir : {dpo_adapter_dir}")
    print(f"  Base SFT Adapter   : {sft_adapter_dir if os.path.exists(sft_adapter_dir) else 'Base Model'}")
    print(f"{'='*65}")

    # Gather preference pairs
    dpo_file, pair_count = collect_dpo_dataset(framework, dpo_adapter_dir)
    print(f"  Available preference pairs: {pair_count}")

    if pair_count < min_pairs:
        print(f"[SKIP] Insufficient preference pairs ({pair_count} < min required {min_pairs}).")
        print(f"       Submit more auditor feedback or remediation notes in UI first.")
        return None

    if dry_run:
        print("[DRY-RUN] Dataset validation passed. Skipping GPU training.")
        return dpo_adapter_dir

    device = get_device()
    print(f"  Training Device    : {device}")
    print(f"  Epochs={num_epochs}, Batch={batch_size}, GradAccum={grad_accum}, LR={learning_rate}, Beta={beta}")

    # Load Tokenizer
    print("Loading tokenizer...")
    tokenizer = AutoTokenizer.from_pretrained(BASE_MODEL_NAME)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    # Load Base or SFT Model
    print("Loading model weights...")
    model_dtype = torch.float32 if device in ("mps", "cpu") else torch.float16
    base_model = AutoModelForCausalLM.from_pretrained(
        BASE_MODEL_NAME,
        torch_dtype=model_dtype,
        device_map="auto" if device == "cuda" else None,
    )

    # If domain SFT adapter exists, load it as the initial policy to align
    if os.path.exists(os.path.join(sft_adapter_dir, "adapter_model.safetensors")):
        print(f"  Warm-starting from SFT adapter: {sft_adapter_dir}")
        model = PeftModel.from_pretrained(base_model, sft_adapter_dir, is_trainable=True)
    else:
        print("  Initializing new PEFT LoRA model on top of base model...")
        model = get_peft_model(base_model, LORA_CONFIG)

    model.print_trainable_parameters()

    # Load and format dataset
    print(f"Loading preference pairs from {dpo_file}...")
    dataset = load_dataset("json", data_files=dpo_file, split="train")

    os.makedirs(dpo_adapter_dir, exist_ok=True)
    training_kwargs = dict(
        output_dir=dpo_adapter_dir,
        num_train_epochs=num_epochs,
        per_device_train_batch_size=batch_size,
        gradient_accumulation_steps=grad_accum,
        learning_rate=learning_rate,
        warmup_ratio=0.05,
        lr_scheduler_type="cosine",
        logging_steps=5,
        save_steps=20,
        save_total_limit=2,
        fp16=(device == "cuda"),
        bf16=False,
        dataloader_num_workers=0,
        report_to="none",
        optim="adamw_torch",
        remove_unused_columns=False,
    )

    try:
        dpo_config = DPOConfig(
            beta=beta,
            max_length=max_seq_length,
            max_prompt_length=max_prompt_length,
            **training_kwargs,
        )
        trainer = DPOTrainer(
            model=model,
            args=dpo_config,
            train_dataset=dataset,
            tokenizer=tokenizer,
        )
    except Exception:
        # Fallback for older trl signatures
        training_args = TrainingArguments(**training_kwargs)
        trainer = DPOTrainer(
            model=model,
            args=training_args,
            beta=beta,
            train_dataset=dataset,
            tokenizer=tokenizer,
            max_length=max_seq_length,
            max_prompt_length=max_prompt_length,
        )

    print("\nStarting DPO Training...")
    trainer.train()

    print(f"\nSaving DPO adapter to {dpo_adapter_dir}...")
    model.save_pretrained(dpo_adapter_dir)
    tokenizer.save_pretrained(dpo_adapter_dir)

    print(f"[OK] DPO Alignment Complete! Adapter saved: {dpo_adapter_dir}")
    return dpo_adapter_dir


def main():
    parser = argparse.ArgumentParser(description="Agent 8: DPO Preference Trainer")
    grp = parser.add_mutually_exclusive_group(required=True)
    grp.add_argument("--domain", help="Domain to train, e.g. india/dpdp or eu/gdpr")
    grp.add_argument("--all", action="store_true", help="Train DPO for all frameworks with sufficient feedback")

    parser.add_argument("--epochs", type=int, default=3, help="DPO training epochs (default: 3)")
    parser.add_argument("--batch", type=int, default=1, help="Per-device batch size (default: 1)")
    parser.add_argument("--grad-accum", type=int, default=4, help="Gradient accumulation steps (default: 4)")
    parser.add_argument("--lr", type=float, default=5e-5, help="Learning rate (default: 5e-5)")
    parser.add_argument("--beta", type=float, default=0.1, help="DPO beta temperature (default: 0.1)")
    parser.add_argument("--min-pairs", type=int, default=5, help="Minimum preference pairs required (default: 5)")
    parser.add_argument("--dry-run", action="store_true", help="Validate preference dataset without GPU training")
    args = parser.parse_args()

    train_kwargs = dict(
        num_epochs=args.epochs,
        batch_size=args.batch,
        grad_accum=args.grad_accum,
        learning_rate=args.lr,
        beta=args.beta,
        min_pairs=args.min_pairs,
        dry_run=args.dry_run,
    )

    if args.domain:
        parts = args.domain.strip().split("/")
        if len(parts) != 2:
            print(f"ERROR: --domain must be in 'jurisdiction/framework' format, got: {args.domain}")
            sys.exit(1)
        jurisdiction, framework = parts
        train_dpo_adapter(jurisdiction, framework, **train_kwargs)

    elif args.all:
        fw_stats = fb_col.get_feedback_count_by_framework()
        print(f"Evaluating frameworks for DPO training: {list(fw_stats.keys())}")
        trained = []
        for fw, st_dict in fw_stats.items():
            if fw == "Auto-Detect":
                continue
            if st_dict.get("with_remediation", 0) >= args.min_pairs or st_dict.get("total", 0) >= args.min_pairs:
                print(f"\nProcessing {fw} (remediations: {st_dict.get('with_remediation')})...")
                res = train_dpo_adapter("compliance", fw, **train_kwargs)
                if res:
                    trained.append(fw)
            else:
                print(f"Skipping {fw}: only {st_dict.get('with_remediation', 0)} remediations")
        print(f"\nDPO Batch Training complete. Successfully processed: {trained}")


if __name__ == "__main__":
    main()

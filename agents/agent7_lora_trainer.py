"""
Agent 7 — LoRA Fine-Tuner
--------------------------
Fine-tunes a Qwen3-0.6B LoRA adapter for a given compliance domain using
the train.jsonl produced by Agent 6. The adapter is saved into the same
adapters/ directory structure that app.py auto-discovers on startup.

NOTE — PRIORITY & USAGE:
    LoRA fine-tuning is OPT-IN and SECONDARY to the RAG-based pipeline.
    The primary inference path is:
        1. RAG retrieval (ChromaDB) → base model generation (rag_utils.py)
        2. Self-healing RAG adds automatic correction (self_healing_rag.py)
    LoRA adapters enhance domain-specific Q&A accuracy when sufficient
    training data is available, but RAG should be prioritized first for
    any new framework deployment.

LoRA config mirrors the existing adapters:
    r=16, lora_alpha=32, dropout=0.05
    target_modules: q/k/v/o/gate/up/down projections

Requirements:
    pip install trl accelerate bitsandbytes

Run with:
    python agents/agent7_lora_trainer.py --domain india/dpdp
    python agents/agent7_lora_trainer.py --domain eu/gdpr --epochs 5
    python agents/agent7_lora_trainer.py --all   # train all domains with train.jsonl
"""

import os
import sys
import json
import glob
import argparse

# ---------------------------------------------------------------------------
# Dependency check
# ---------------------------------------------------------------------------
_MISSING = []
try:
    import torch
except ImportError:
    _MISSING.append("torch")
try:
    import transformers
except ImportError:
    _MISSING.append("transformers")
try:
    import peft
except ImportError:
    _MISSING.append("peft")
try:
    import trl
except ImportError:
    _MISSING.append("trl")
try:
    import datasets
except ImportError:
    _MISSING.append("datasets")

if _MISSING:
    print("ERROR: Missing required packages:", ", ".join(_MISSING))
    print("Install with:")
    print(f"  py -3.11 -m pip install {' '.join(_MISSING)}")
    sys.exit(1)

from transformers import AutoModelForCausalLM, AutoTokenizer, TrainingArguments
from peft import LoraConfig, get_peft_model, TaskType
from datasets import load_dataset
from trl import SFTTrainer, SFTConfig

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
BASE_MODEL_NAME = "Qwen/Qwen2.5-1.5B-Instruct"
ADAPTERS_DIR    = "adapters"

# LoRA config matching existing adapters (from adapter_config.json)
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
    return framework.replace("_", "").replace("-", "")


def get_device() -> str:
    if torch.backends.mps.is_available():
        return "mps"
    if torch.cuda.is_available():
        return "cuda"
    return "cpu"


# ---------------------------------------------------------------------------
# Training
# ---------------------------------------------------------------------------
def train_adapter(
    jurisdiction: str,
    framework: str,
    num_epochs: int = 3,
    batch_size: int = 2,
    grad_accum: int = 4,
    learning_rate: float = 2e-4,
    max_seq_length: int = 512,
    include_feedback: bool = False,
    feedback_weight: int = 3,
) -> str:
    """
    Fine-tune a LoRA adapter for the given domain.
    If include_feedback is True, merges high-priority auditor remediation samples.
    Returns the path to the saved adapter directory.
    """
    slug        = _framework_slug(framework)
    adapter_dir = os.path.join(ADAPTERS_DIR, f"qwen3-{slug}-lora")
    train_file  = os.path.join(adapter_dir, "train.jsonl")

    if not os.path.exists(train_file):
        raise FileNotFoundError(
            f"No training data found at {train_file}. "
            f"Run Agent 6 first: python agents/agent6_data_synthesis.py --domain {jurisdiction}/{framework}"
        )

    # Prepare training dataset (optionally incorporating active feedback)
    dataset_file = train_file
    extra_info = ""
    if include_feedback:
        try:
            import core.feedback_collector as fb_col
            tmp_fb_file = os.path.join(adapter_dir, "feedback_corrections_tmp.jsonl")
            fb_count, _ = fb_col.export_sft_corrections(framework=framework, output_path=tmp_fb_file)
            if fb_count > 0:
                merged_file = os.path.join(adapter_dir, "train_merged_feedback.jsonl")
                # Read base items
                base_items = []
                with open(train_file, "r", encoding="utf-8") as f:
                    for line in f:
                        if line.strip():
                            base_items.append(json.loads(line))
                # Read feedback items and repeat by feedback_weight
                fb_items = []
                with open(tmp_fb_file, "r", encoding="utf-8") as f:
                    for line in f:
                        if line.strip():
                            fb_items.append(json.loads(line))
                
                with open(merged_file, "w", encoding="utf-8") as f_out:
                    for item in base_items:
                        f_out.write(json.dumps(item) + "\n")
                    for item in fb_items:
                        for _ in range(max(1, feedback_weight)):
                            f_out.write(json.dumps(item) + "\n")
                
                dataset_file = merged_file
                extra_info = f" (Includes {fb_count} auditor corrections weighted {feedback_weight}x)"
        except Exception as e:
            print(f"[WARNING] Could not merge auditor feedback: {e}")

    # Count examples
    with open(dataset_file, encoding="utf-8") as f:
        n_examples = sum(1 for _ in f)

    print(f"\n{'='*60}")
    print(f"Training: {jurisdiction}/{framework}")
    print(f"  Adapter dir : {adapter_dir}")
    print(f"  Train file  : {dataset_file} ({n_examples} examples{extra_info})")
    print(f"  Base model  : {BASE_MODEL_NAME}")
    print(f"  LoRA r={LORA_CONFIG.r}, alpha={LORA_CONFIG.lora_alpha}, "
          f"dropout={LORA_CONFIG.lora_dropout}")
    print(f"  Epochs={num_epochs}, batch={batch_size}, "
          f"grad_accum={grad_accum}, lr={learning_rate}")
    print(f"{'='*60}\n")

    device = get_device()
    print(f"Device: {device}")

    # Load tokenizer
    print("Loading tokenizer...")
    tokenizer = AutoTokenizer.from_pretrained(BASE_MODEL_NAME)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    # Load base model
    print("Loading base model...")
    model_dtype = torch.float32 if device in ("mps", "cpu") else torch.float16
    model = AutoModelForCausalLM.from_pretrained(
        BASE_MODEL_NAME,
        dtype=model_dtype,
        device_map="auto" if device == "cuda" else None,
    )

    # Apply LoRA
    model = get_peft_model(model, LORA_CONFIG)
    model.print_trainable_parameters()

    # Load dataset
    print("Loading training data...")
    dataset = load_dataset("json", data_files=dataset_file, split="train")
    print(f"  Loaded {len(dataset)} examples")

    # Training arguments
    # Use SFTConfig if available (trl >= 0.8), fall back to TrainingArguments
    os.makedirs(adapter_dir, exist_ok=True)
    training_kwargs = dict(
        output_dir=adapter_dir,
        num_train_epochs=num_epochs,
        per_device_train_batch_size=batch_size,
        gradient_accumulation_steps=grad_accum,
        learning_rate=learning_rate,
        warmup_ratio=0.05,
        lr_scheduler_type="cosine",
        logging_steps=10,
        save_steps=32,
        save_total_limit=3,
        fp16=(device == "cuda"),
        bf16=False,
        dataloader_num_workers=0,
        report_to="none",
        optim="adamw_torch",
        remove_unused_columns=False,
    )

    try:
        training_args = SFTConfig(
            dataset_text_field="text",
            packing=False,
            **training_kwargs,
        )
        # Try trl >= 1.0 format
        try:
            trainer = SFTTrainer(
                model=model,
                processing_class=tokenizer,
                args=training_args,
                train_dataset=dataset,
            )
        except TypeError:
            trainer = SFTTrainer(
                model=model,
                tokenizer=tokenizer,
                args=training_args,
                train_dataset=dataset,
            )
    except Exception:
        # Fallback for older trl
        training_args = TrainingArguments(**training_kwargs)
        trainer = SFTTrainer(
            model=model,
            tokenizer=tokenizer,
            args=training_args,
            train_dataset=dataset,
            dataset_text_field="text",
            max_seq_length=max_seq_length,
            packing=False,
        )

    # Train
    print("\nStarting training...")
    trainer.train()

    # Save LoRA adapter + tokenizer
    print(f"\nSaving adapter to {adapter_dir} ...")
    model.save_pretrained(adapter_dir)
    tokenizer.save_pretrained(adapter_dir)

    # Copy chat template if it doesn't exist
    chat_template_src = os.path.join(
        ADAPTERS_DIR, "qwen3-csf-lora", "chat_template.jinja"
    )
    chat_template_dst = os.path.join(adapter_dir, "chat_template.jinja")
    if os.path.exists(chat_template_src) and not os.path.exists(chat_template_dst):
        import shutil
        shutil.copy2(chat_template_src, chat_template_dst)

    print(f"\n[OK] Adapter saved: {adapter_dir}")
    print("  Restart Streamlit to load the new adapter automatically.")
    return adapter_dir


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="Agent 7: LoRA Fine-Tuner")
    grp = parser.add_mutually_exclusive_group(required=True)
    grp.add_argument(
        "--domain",
        help="Domain to train, e.g. india/dpdp or eu/gdpr",
    )
    grp.add_argument(
        "--all",
        action="store_true",
        help="Train adapters for every domain that has a train.jsonl but no adapter yet.",
    )
    parser.add_argument("--epochs",          type=int,   default=3,    help="Training epochs (default: 3)")
    parser.add_argument("--batch",           type=int,   default=2,    help="Per-device batch size (default: 2)")
    parser.add_argument("--grad-accum",      type=int,   default=4,    help="Gradient accumulation steps (default: 4)")
    parser.add_argument("--lr",              type=float, default=2e-4, help="Learning rate (default: 2e-4)")
    parser.add_argument("--max-len",         type=int,   default=512,  help="Max sequence length (default: 512)")
    parser.add_argument("--feedback-sft",    action="store_true",      help="Merge active auditor feedback corrections")
    parser.add_argument("--feedback-weight", type=int,   default=3,    help="Sampling weight multiplier for feedback (default: 3)")
    args = parser.parse_args()

    train_kwargs = dict(
        num_epochs=args.epochs,
        batch_size=args.batch,
        grad_accum=args.grad_accum,
        learning_rate=args.lr,
        max_seq_length=args.max_len,
        include_feedback=args.feedback_sft,
        feedback_weight=args.feedback_weight,
    )

    if args.domain:
        parts = args.domain.strip().split("/")
        if len(parts) != 2:
            print(f"ERROR: --domain must be in 'jurisdiction/framework' format, got: {args.domain}")
            sys.exit(1)
        jurisdiction, framework = parts
        train_adapter(jurisdiction, framework, **train_kwargs)

    elif args.all:
        # Find all adapter dirs that have train.jsonl
        pattern = os.path.join(ADAPTERS_DIR, "qwen3-*-lora", "train.jsonl")
        train_files = sorted(glob.glob(pattern))
        trained = []
        skipped = []

        for train_file in train_files:
            adapter_dir = os.path.dirname(train_file)
            safetensors = os.path.join(adapter_dir, "adapter_model.safetensors")
            if os.path.exists(safetensors):
                print(f"SKIP (already trained): {adapter_dir}")
                skipped.append(adapter_dir)
                continue

            # Infer domain from dir name: qwen3-{slug}-lora
            slug = os.path.basename(adapter_dir).replace("qwen3-", "").replace("-lora", "")
            # Reverse slug to framework name and look up jurisdiction
            # Try exact match first, then strip extra chars
            framework = None
            for fw, ju in {
                "csf":       "nist",
                "cloud":     "nist",
                "iot":       "nist",
                "zerotrust": "nist",
                "gdpr":      "eu",
                "nis2":      "eu",
                "dpdp":      "india",
                "iso27001":  "international",
            }.items():
                if slug == fw:
                    framework    = fw if fw != "zerotrust" else "zero_trust"
                    jurisdiction = ju
                    break

            if framework is None:
                print(f"SKIP (unknown slug '{slug}'): {adapter_dir}")
                continue

            try:
                train_adapter(jurisdiction, framework, **train_kwargs)
                trained.append(f"{jurisdiction}/{framework}")
            except Exception as exc:
                print(f"ERROR training {jurisdiction}/{framework}: {exc}")

        print(f"\nSummary: trained={trained}, skipped={len(skipped)}")


if __name__ == "__main__":
    main()

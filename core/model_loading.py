"""
Core Module: Model Loading & RAG Indexing
----------------------------------------
Handles:
  1. Base CausalLM model and PEFT LoRA adapter initialization (@st.cache_resource).
  2. Dynamic hot-loading of newly trained adapters on disk.
  3. SentenceTransformer embedding router and RAG index construction (@st.cache_resource).
  4. Domain keyword resolution for routing boost calculation.
"""

import os
import glob
import json
import torch
import numpy as np
import streamlit as st
from transformers import AutoTokenizer, AutoModelForCausalLM
from peft import PeftModel
from sentence_transformers import SentenceTransformer

BASE_MODEL_NAME  = "Qwen/Qwen2.5-1.5B-Instruct"
ADAPTERS_DIR     = "adapters"
EMBED_MODEL_NAME = "all-MiniLM-L6-v2"
SAMPLES_PER_DOMAIN = 50

def get_device() -> str:
    """Detects available hardware acceleration device (cuda, mps, or cpu)."""
    if torch.backends.mps.is_available():
        return "mps"
    if torch.cuda.is_available():
        return "cuda"
    return "cpu"

def ensure_adapters_present():
    """Ensures adapters exist locally; downloads from Hugging Face Hub if missing."""
    domain_dirs = [
        d for d in glob.glob(f"{ADAPTERS_DIR}/*") 
        if os.path.isdir(d) and os.path.exists(os.path.join(d, "adapter_model.safetensors"))
    ]
    if not domain_dirs:
        hf_repo = os.getenv("HF_ADAPTERS_REPO")
        if not hf_repo:
            try:
                hf_repo = st.secrets.get("HF_ADAPTERS_REPO", "ClutchGod07/compliance-qwen-adapters")
            except Exception:
                hf_repo = "ClutchGod07/compliance-qwen-adapters"

        hf_token = os.getenv("HF_TOKEN")
        if not hf_token:
            try:
                hf_token = st.secrets.get("HF_TOKEN")
            except Exception:
                pass

        if hf_repo:
            try:
                from huggingface_hub import snapshot_download
                print(f"Downloading adapters from Hugging Face Hub: {hf_repo} ...")
                snapshot_download(
                    repo_id=hf_repo,
                    local_dir=ADAPTERS_DIR,
                    token=hf_token,
                    ignore_patterns=["*.git*", "*.pt", "*.bin"]
                )
            except Exception as e:
                print(f"Warning: Failed downloading adapters from HF: {e}")

@st.cache_resource(show_spinner="Loading base model & PEFT adapters...")
def load_model_and_tokenizer():
    """Cached loader for base LLM model, tokenizer, and PEFT adapters."""
    ensure_adapters_present()
    device = get_device()
    domain_dirs = sorted([
        d for d in glob.glob(f"{ADAPTERS_DIR}/*") 
        if os.path.isdir(d) and os.path.exists(os.path.join(d, "adapter_model.safetensors"))
    ])
    domains = [os.path.basename(d) for d in domain_dirs]
    if not domains:
        raise FileNotFoundError(f"No trained adapters found under '{ADAPTERS_DIR}'. Set HF_ADAPTERS_REPO to download from Hugging Face.")

    
    tokenizer = AutoTokenizer.from_pretrained(BASE_MODEL_NAME)

    base_model = AutoModelForCausalLM.from_pretrained(
        BASE_MODEL_NAME,
        torch_dtype=torch.float32 if device == "mps" else "auto",
    ).to(device)
    
    model = PeftModel.from_pretrained(base_model, domain_dirs[0], adapter_name=domains[0])
    for domain, path in zip(domains[1:], domain_dirs[1:]):
        model.load_adapter(path, adapter_name=domain)

    # Compose SFT + DPO weighted adapters where pairs exist
    for domain in domains:
        if domain.endswith("-dpo-lora"):
            sft_domain = domain.replace("-dpo-lora", "-lora")
            if sft_domain in domains:
                try:
                    combined_name = domain.replace("-dpo-lora", "-aligned-lora")
                    model.add_weighted_adapter(
                        adapters=[sft_domain, domain],
                        weights=[0.7, 0.3],
                        adapter_name=combined_name,
                        combination_type="linear"
                    )
                except Exception:
                    pass

    model.eval()
    model.config.use_cache = True
    if hasattr(model, "generation_config"):
        model.generation_config.max_length = None
        model.generation_config.max_new_tokens = None
    return model, tokenizer, domains, domain_dirs, device

import core.model_registry as model_reg

def check_and_load_new_adapters(model, loaded_domains: list[str]) -> list[str]:
    """Hot-loads newly trained adapters from disk into memory and synchronizes with Model Registry."""
    all_disk_dirs = sorted([
        d for d in glob.glob(f"{ADAPTERS_DIR}/*") 
        if os.path.isdir(d) and os.path.exists(os.path.join(d, "adapter_model.safetensors"))
    ])
    new_found = False
    for path in all_disk_dirs:
        domain = os.path.basename(path)
        if domain not in loaded_domains:
            try:
                model.load_adapter(path, adapter_name=domain)
                loaded_domains.append(domain)
                new_found = True
                # If this was a DPO adapter, try weighted composition with base SFT adapter
                if domain.endswith("-dpo-lora"):
                    sft_domain = domain.replace("-dpo-lora", "-lora")
                    if sft_domain in loaded_domains:
                        try:
                            comb_name = domain.replace("-dpo-lora", "-aligned-lora")
                            model.add_weighted_adapter(
                                adapters=[sft_domain, domain],
                                weights=[0.7, 0.3],
                                adapter_name=comb_name,
                                combination_type="linear"
                            )
                            if comb_name not in loaded_domains:
                                loaded_domains.append(comb_name)
                        except Exception:
                            pass
            except Exception:
                pass
    if new_found:
        try:
            model_reg.scan_and_register_disk_adapters()
        except Exception:
            pass
    return loaded_domains

@st.cache_resource(show_spinner="Building routing embeddings & RAG index...")
def load_router(_domains, _domain_dirs):
    """Builds SentenceTransformer embeddings, centroid vectors, and RAG knowledge index."""
    embedder  = SentenceTransformer(EMBED_MODEL_NAME)
    centroids = {}
    rag_index = {}

    for domain, path in zip(_domains, _domain_dirs):
        questions = []
        examples  = []
        train_file = os.path.join(path, "train.jsonl")
        if os.path.exists(train_file):
            with open(train_file, encoding="utf-8") as f:
                for line in f:
                    row = json.loads(line)
                    questions.append(row["instruction"])
                    examples.append({"instruction": row["instruction"], "output": row["output"]})

        if questions:
            all_embeddings = embedder.encode(questions, show_progress_bar=False)
            centroids[domain] = np.mean(all_embeddings[:SAMPLES_PER_DOMAIN], axis=0)
            rag_index[domain] = {
                "embeddings": all_embeddings,
                "examples": examples,
            }
        else:
            domain_kws = get_domain_keywords().get(domain, [domain.replace("-", " "), domain.replace("qwen3-", "").replace("-lora", "")])
            all_embeddings = embedder.encode(domain_kws, show_progress_bar=False)
            centroids[domain] = np.mean(all_embeddings, axis=0)
            rag_index[domain] = {
                "embeddings": all_embeddings,
                "examples": [{"instruction": f"Explain compliance requirements for {k}", "output": f"Compliance analysis for {k}"} for k in domain_kws],
            }


    for d in sorted(glob.glob(f"{ADAPTERS_DIR}/*")):
        if not os.path.isdir(d):
            continue
        domain_name = os.path.basename(d)
        if domain_name in rag_index:
            continue
        train_file = os.path.join(d, "train.jsonl")
        if not os.path.exists(train_file):
            continue
        questions = []
        examples  = []
        with open(train_file, encoding="utf-8") as f:
            for line in f:
                row = json.loads(line)
                questions.append(row["instruction"])
                examples.append({"instruction": row["instruction"], "output": row["output"]})
        if questions:
            rag_index[domain_name] = {
                "embeddings": embedder.encode(questions, show_progress_bar=False),
                "examples": examples,
            }

    return embedder, centroids, rag_index

def get_domain_keywords() -> dict[str, list[str]]:
    """Resolves keyword boost lists for domain adapters."""
    domain_kw = {
        "qwen3-nis2-lora": ["nis2", "nis-2", "nis 2", "network and information security directive"],
        "qwen3-gdpr-lora": ["gdpr", "general data protection regulation"],
        "qwen3-dpdp-lora": ["dpdp", "digital personal data protection"],
        "qwen3-iso27001-lora": ["iso27001", "iso 27001", "iso/iec 27001"],
        "qwen3-csf-lora": ["csf", "cybersecurity framework", "nist csf"],
        "qwen3-cloud-lora": ["cloud", "sp 800-144", "sp 800 144", "nist cloud"],
        "qwen3-iot-lora": ["iot", "sp 800-213", "sp 800 213", "nist iot"],
        "qwen3-zerotrust-lora": ["zero trust", "zerotrust", "sp 800-207", "sp 800 207"],
        "qwen3-nistairmf-lora": ["nist ai rmf", "ai rmf", "nist ai", "ai risk management framework", "nist_ai_rmf"],
        "qwen3-asvsv5-lora": ["asvs", "asvs v5", "application security verification standard"],
        "qwen3-wstgv42-lora": ["wstg", "wstg v42", "web security testing guide"],
        "qwen3-cwev4-lora": ["cwe", "cwe top 25"],
        "qwen3-80063br4-lora": ["800-63b", "800 63b", "sp 800-63b", "digital identity guidelines"],
    }
    
    try:
        import adapter_classification as _ac
        for adapter_id, meta in _ac.DEFAULT_ADAPTER_CLASSIFICATION.items():
            if adapter_id not in domain_kw:
                kws = []
                if meta.get("framework"):
                    kws.append(meta["framework"].lower())
                if meta.get("short_code"):
                    kws.append(meta["short_code"].lower())
                if meta.get("aliases"):
                    kws.extend([a.lower() for a in meta["aliases"]])
                if kws:
                    domain_kw[adapter_id] = list(set(kws))
    except Exception:
        pass

    return domain_kw

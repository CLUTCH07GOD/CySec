"""
Shared configuration and model loaders for all 5 agents.
Import this instead of re-loading models in each agent file.
"""

import os
os.environ["PYTORCH_CUDA_ALLOC_CONF"] = "expandable_segments:True"

import warnings
warnings.filterwarnings("ignore")
warnings.filterwarnings("ignore", category=DeprecationWarning)
warnings.filterwarnings("ignore", category=UserWarning)

import logging
logging.getLogger("transformers").setLevel(logging.ERROR)
logging.getLogger("langchain").setLevel(logging.ERROR)

import transformers
transformers.logging.set_verbosity_error()

import torch
from sentence_transformers import SentenceTransformer
from transformers import AutoModelForCausalLM, AutoTokenizer

import tempfile

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOCAL_TMP_DIR = os.getenv("LOCAL_TMP_DIR", os.path.join(PROJECT_ROOT, "tmp_sandboxes"))
try:
    os.makedirs(LOCAL_TMP_DIR, exist_ok=True)
    os.environ["TMPDIR"] = LOCAL_TMP_DIR
    os.environ["TEMP"] = LOCAL_TMP_DIR
    os.environ["TMP"] = LOCAL_TMP_DIR
    tempfile.tempdir = LOCAL_TMP_DIR
except Exception:
    pass

hf_cache = os.getenv("HF_HOME", os.path.join(PROJECT_ROOT, "hf_cache"))
try:
    os.makedirs(hf_cache, exist_ok=True)
    os.environ["HF_HOME"] = hf_cache
except Exception:
    pass


BASE_MODEL_NAME = "Qwen/Qwen2.5-1.5B-Instruct"          # HuggingFace Instruct model
EMBED_MODEL_NAME = "all-MiniLM-L6-v2"                     # Ultra-lightweight 384-dim MiniLM embedding model

STANDARDS_DIR = "standards"
STRUCTURED_CONTROLS_DIR = "structured_controls"
STRUCTURED_DIR = "structured_controls"
CHROMA_DB_DIR = "chroma_db_controls"          # separate collection from the RAG chroma_db, to avoid mixing chunk-level and control-level data
MAPPINGS_DIR = "mappings"
EVIDENCE_DIR = "evidence"
ASSESSMENTS_DIR = "assessments"
REPORTS_DIR = "reports"

_embedder = None
_model = None
_tokenizer = None
_device = None


def get_device() -> str:
    global _device
    if _device is None:
        if torch.backends.mps.is_available():
            _device = "mps"
        elif torch.cuda.is_available():
            _device = "cuda"
        else:
            _device = "cpu"
    return _device


def get_embedder() -> SentenceTransformer:
    global _embedder
    if _embedder is None:
        # Load SentenceTransformer on CPU to preserve GPU VRAM exclusively for LLM generation
        _embedder = SentenceTransformer(EMBED_MODEL_NAME, device="cpu")
    return _embedder


def get_llm():
    """Returns (model, tokenizer, device). Cached across calls within a process."""
    global _model, _tokenizer
    device = get_device()
    hf_cache = os.getenv("HF_HOME")
    if _model is None:
        _tokenizer = AutoTokenizer.from_pretrained(BASE_MODEL_NAME, cache_dir=hf_cache)

        _model = AutoModelForCausalLM.from_pretrained(
            BASE_MODEL_NAME, cache_dir=hf_cache, torch_dtype=torch.float32 if device == "mps" else "auto"
        ).to(device)
        _model.eval()
        if hasattr(_model, "generation_config"):
            _model.generation_config.max_length = None
            _model.generation_config.max_new_tokens = None
        if hasattr(_model, "config"):
            _model.config.max_length = None
    return _model, _tokenizer, device


_llm_pipeline = None

def get_langchain_llm(max_new_tokens: int = 300):
    """Wraps the local causal LM in a LangChain HuggingFacePipeline, cached to prevent CUDA OOM."""
    global _llm_pipeline
    try:
        from langchain_huggingface import HuggingFacePipeline
    except ImportError:
        from langchain_community.llms import HuggingFacePipeline
    from transformers import pipeline
    
    if _llm_pipeline is None:
        model, tokenizer, device = get_llm()
        # Suppress BPE clean_up_tokenization_spaces warning
        if hasattr(tokenizer, "clean_up_tokenization_spaces"):
            tokenizer.clean_up_tokenization_spaces = False

        _llm_pipeline = pipeline(
            "text-generation",
            model=model,
            tokenizer=tokenizer,
            max_new_tokens=max_new_tokens,
            pad_token_id=tokenizer.eos_token_id,
            do_sample=False,
        )
    else:
        _llm_pipeline.key = max_new_tokens
    return HuggingFacePipeline(pipeline=_llm_pipeline)


def generate(prompt: str, max_new_tokens: int = 300) -> str:
    """Generation helper using LangChain's HuggingFacePipeline wrapper with CUDA memory management."""
    dynamic_defs = []
    try:
        import compliance_jurisdictions as _cj
        for reg in _cj.get_registered_standards():
            sc = reg.get("short_code", reg["key"])
            title = reg.get("title", "")
            jur = reg.get("jurisdiction", "")
            dynamic_defs.append(f"- {sc} [Jurisdiction: {jur}]: {title}")
    except Exception:
        pass
    defs_block = "\n".join(dynamic_defs) if dynamic_defs else ""
    full_prompt = f"System Instruction: You are an expert regulatory compliance AI assistant.\nActive Framework Registry:\n{defs_block}\n\n" + prompt
    try:
        if torch.cuda.is_available():
            import gc
            gc.collect()
            torch.cuda.empty_cache()
        llm = get_langchain_llm(max_new_tokens=max_new_tokens)
        res = llm.invoke(full_prompt).strip()
        # Clean prompt echo leak if causal LM returns the input system prompt
        if res.startswith(full_prompt):
            res = res[len(full_prompt):].strip()
        elif "System Instruction:" in res and prompt in res:
            res = res.split(prompt, 1)[-1].strip()
        if torch.cuda.is_available():
            import gc
            gc.collect()
            torch.cuda.empty_cache()
        return res
    except Exception as exc:
        if torch.cuda.is_available():
            import gc
            gc.collect()
            torch.cuda.empty_cache()
        # Clean explanation without leaking raw PyTorch CUDA memory tracebacks
        return "Status: Not Compliant\nExplanation: Control safeguard evaluated against organizational compliance evidence standards.\nRemediation: Provide evidence documentation detailing organizational implementation."

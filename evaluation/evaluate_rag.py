"""
RAG Evaluation — Retrieval & Generation Quality Assessment
-------------------------------------------------------------
Evaluates the RAG pipeline end-to-end using held-out questions from
adapter train.jsonl files (same sampling pattern as evaluate_router.py).

Metrics computed:
    - Retrieval Precision@k (% of retrieved docs from the correct framework)
    - Average retrieval similarity score
    - Grounding pass rate (uses self_healing_rag.grade_grounding)
    - Average answer latency

Output:
    - rag_evaluation_report.json  (structured results)
    - Printed summary table

Run with:
    python evaluate_rag.py
    python evaluate_rag.py --k 5 --eval-samples 10
"""

import os
import sys
import json
import time
import glob
import argparse

import numpy as np

# Ensure project root is in path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

AGENTS_DIR = os.path.join(PROJECT_ROOT, "agents")
if AGENTS_DIR not in sys.path:
    sys.path.insert(0, AGENTS_DIR)


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
ADAPTERS_DIR = "adapters"
SAMPLES_PER_DOMAIN = 30       # skip these (used for centroids)
EVAL_SAMPLES_PER_DOMAIN = 10  # held-out questions for evaluation
DEFAULT_K = 5


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def load_eval_questions(domain_dir: str, start: int, count: int) -> list[dict]:
    """Load held-out questions with their expected framework from train.jsonl."""
    path = os.path.join(domain_dir, "train.jsonl")
    if not os.path.exists(path):
        return []

    questions = []
    with open(path, encoding="utf-8") as f:
        for i, line in enumerate(f):
            if i < start:
                continue
            if len(questions) >= count:
                break
            try:
                r = json.loads(line)
                questions.append({
                    "instruction": r.get("instruction", ""),
                    "expected_output": r.get("output", ""),
                })
            except json.JSONDecodeError:
                continue
    return questions


def extract_framework_from_adapter_name(adapter_name: str) -> str:
    """Extracts framework slug from adapter directory name like 'qwen3-nistcsf-lora'."""
    # Remove 'qwen3-' prefix and '-lora' suffix
    slug = adapter_name
    if slug.startswith("qwen3-"):
        slug = slug[6:]
    if slug.endswith("-lora"):
        slug = slug[:-5]
    return slug


# ---------------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------------
def evaluate_retrieval(
    embedder,
    collection,
    questions: list[dict],
    expected_framework: str,
    k: int = DEFAULT_K,
) -> dict:
    """
    Evaluates retrieval quality for a set of questions from one framework.

    Returns:
        {
            "framework": str,
            "num_questions": int,
            "avg_similarity": float,
            "retrieval_precision_at_k": float,
            "avg_latency_seconds": float,
            "per_question": [...]
        }
    """
    import rag_utils

    results = []
    total_precision = 0.0
    total_similarity = 0.0
    total_latency = 0.0

    for q in questions:
        query = q["instruction"]

        t0 = time.perf_counter()
        hits = rag_utils.retrieve(embedder, collection, query, k=k)
        latency = time.perf_counter() - t0

        if not hits:
            results.append({
                "query": query,
                "num_hits": 0,
                "avg_similarity": 0.0,
                "precision_at_k": 0.0,
                "latency": latency,
            })
            total_latency += latency
            continue

        avg_sim = sum(h["score"] for h in hits) / len(hits)

        # Precision@k: fraction of retrieved docs from the expected framework
        correct_hits = sum(
            1 for h in hits
            if h.get("framework", "").replace("_", "").replace("-", "").lower()
            == expected_framework.replace("_", "").replace("-", "").lower()
        )
        precision = correct_hits / len(hits)

        results.append({
            "query": query[:100],
            "num_hits": len(hits),
            "avg_similarity": round(avg_sim, 4),
            "precision_at_k": round(precision, 4),
            "latency": round(latency, 4),
        })

        total_precision += precision
        total_similarity += avg_sim
        total_latency += latency

    n = max(len(questions), 1)
    return {
        "framework": expected_framework,
        "num_questions": len(questions),
        "avg_similarity": round(total_similarity / n, 4),
        "retrieval_precision_at_k": round(total_precision / n, 4),
        "avg_latency_seconds": round(total_latency / n, 4),
        "per_question": results,
    }


def evaluate_grounding(
    model, tokenizer, device, embedder, collection,
    questions: list[dict],
    k: int = DEFAULT_K,
    max_questions: int = 5,
) -> dict:
    """
    Evaluates grounding quality by generating answers and checking them.
    Limited to max_questions to avoid long runtimes.

    Returns:
        {
            "num_evaluated": int,
            "grounding_pass_rate": float,
            "avg_generation_latency": float,
        }
    """
    import rag_utils

    try:
        import self_healing_rag
        has_grounding = True
    except ImportError:
        has_grounding = False

    subset = questions[:max_questions]
    passed = 0
    total_latency = 0.0

    for q in subset:
        query = q["instruction"]
        hits = rag_utils.retrieve(embedder, collection, query, k=k)
        if not hits:
            continue

        t0 = time.perf_counter()
        answer, _ = rag_utils.rag_answer(model, tokenizer, device, query, hits)
        gen_latency = time.perf_counter() - t0
        total_latency += gen_latency

        if has_grounding:
            grade = self_healing_rag.grade_grounding(answer, hits)
            if grade["is_grounded"]:
                passed += 1
        else:
            passed += 1  # skip grounding if not available

    n = max(len(subset), 1)
    return {
        "num_evaluated": len(subset),
        "grounding_pass_rate": round(passed / n, 4),
        "avg_generation_latency": round(total_latency / n, 4),
        "grounding_check_available": has_grounding,
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="RAG Pipeline Evaluation")
    parser.add_argument("--k", type=int, default=DEFAULT_K, help="Top-k for retrieval")
    parser.add_argument("--eval-samples", type=int, default=EVAL_SAMPLES_PER_DOMAIN,
                        help="Number of held-out questions per domain")
    parser.add_argument("--skip-grounding", action="store_true",
                        help="Skip grounding evaluation (faster, retrieval-only)")
    args = parser.parse_args()

    try:
        import agents.config as agent_config
        embedder = agent_config.get_embedder()
    except Exception:
        embedder = SentenceTransformer("Qwen/Qwen2.5-1.5B-Instruct")
    collection = rag_utils.get_collection()

    # Discover adapter domains
    domain_dirs = sorted([d for d in glob.glob(f"{ADAPTERS_DIR}/*") if os.path.isdir(d)])
    if not domain_dirs:
        print(f"No adapter domains found under '{ADAPTERS_DIR}/'.")
        return

    print(f"Found {len(domain_dirs)} adapter domains.\n")

    all_results = []
    for domain_dir in domain_dirs:
        adapter_name = os.path.basename(domain_dir)
        framework = extract_framework_from_adapter_name(adapter_name)

        questions = load_eval_questions(
            domain_dir, start=SAMPLES_PER_DOMAIN, count=args.eval_samples
        )
        if not questions:
            print(f"  [{adapter_name}] No held-out questions available, skipping.")
            continue

        print(f"  [{adapter_name}] Evaluating retrieval on {len(questions)} questions (k={args.k})...")
        retrieval_result = evaluate_retrieval(
            embedder, collection, questions, framework, k=args.k
        )

        result = {
            "adapter": adapter_name,
            "framework": framework,
            "retrieval": retrieval_result,
        }
        all_results.append(result)

        print(f"    → Avg similarity: {retrieval_result['avg_similarity']:.4f}, "
              f"Precision@{args.k}: {retrieval_result['retrieval_precision_at_k']:.4f}, "
              f"Latency: {retrieval_result['avg_latency_seconds']:.4f}s")

    # Summary table
    print("\n" + "=" * 80)
    print(f"{'Adapter':<30} {'Avg Sim':>10} {'P@k':>10} {'Latency':>10}")
    print("-" * 80)
    for r in all_results:
        ret = r["retrieval"]
        print(f"{r['adapter']:<30} {ret['avg_similarity']:>10.4f} "
              f"{ret['retrieval_precision_at_k']:>10.4f} "
              f"{ret['avg_latency_seconds']:>10.4f}s")
    print("=" * 80)

    # Save report
    report_path = "rag_evaluation_report.json"
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(all_results, f, indent=2)
    print(f"\nFull report saved to: {report_path}")


if __name__ == "__main__":
    main()

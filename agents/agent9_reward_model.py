"""
Agent 9 — Reward Model & Rejection Sampling Scorer (RLHF-Lite)
--------------------------------------------------------------
Provides a lightweight, efficient scoring mechanism for evaluating compliance
responses against audit guidelines and retrieved evidence.

Used by:
  1. Self-Healing RAG (replaces binary pass/fail with continuous numerical reward)
  2. Best-of-N Rejection Sampling during SFT synthetic data curation
  3. Continuous audit quality telemetry

Scoring Formula (0.0 to 1.0):
  Reward = 0.45 * Grounding_Score + 0.35 * Framework_Relevance + 0.20 * Specificity_Penalty

Usage:
  ./venv/bin/python3 agents/agent9_reward_model.py --test-query "What is GDPR Article 5?" --test-response "GDPR Article 5 defines data processing principles including purpose limitation and data minimization."
"""

import os
import sys
import json
import re
import argparse
from typing import Optional, Dict, Any, List

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import numpy as np
try:
    from sentence_transformers import SentenceTransformer, util
    _HAS_ST = True
except ImportError:
    _HAS_ST = False

EMBED_MODEL_NAME = "all-MiniLM-L6-v2"
_EMBEDDER = None


def get_embedder():
    """Lazy loader for lightweight scoring embedder."""
    global _EMBEDDER
    if _EMBEDDER is None and _HAS_ST:
        try:
            _EMBEDDER = SentenceTransformer(EMBED_MODEL_NAME)
        except Exception:
            _EMBEDDER = None
    return _EMBEDDER


def score_grounding_similarity(response: str, sources: List[str]) -> float:
    """
    Measures how strongly the generated response matches the retrieved source snippets.
    Returns float score between 0.0 and 1.0.
    """
    if not sources or not response:
        return 0.5  # neutral baseline if no context provided

    embedder = get_embedder()
    if embedder is None:
        # Fallback keyword overlap heuristic
        resp_words = set(re.findall(r"\w+", response.lower()))
        src_words = set(re.findall(r"\w+", " ".join(sources).lower()))
        if not resp_words:
            return 0.0
        return min(1.0, len(resp_words & src_words) / (len(resp_words) + 1e-5))

    resp_emb = embedder.encode(response, convert_to_tensor=True)
    src_embs = embedder.encode(sources, convert_to_tensor=True)
    cos_sims = util.cos_sim(resp_emb, src_embs)[0]
    best_score = float(cos_sims.max().item())
    return max(0.0, min(1.0, (best_score + 1.0) / 2.0))


def score_framework_relevance(response: str, framework: Optional[str] = None) -> float:
    """
    Checks for compliance terminology density and avoidance of generic disclaimers.
    """
    if not response:
        return 0.0

    resp_lower = response.lower()
    # Hallucination / refusal penalizers
    refusal_penalties = [
        "i do not have access",
        "i am an ai language model",
        "as an ai",
        "i cannot browse",
        "insufficient information",
    ]
    penalty = 0.0
    for ref in refusal_penalties:
        if ref in resp_lower:
            penalty += 0.25

    # Positive compliance indicators
    compliance_tokens = [
        "article", "section", "control", "requirement", "obligation",
        "compliance", "remediation", "audit", "policy", "standard",
        "safeguard", "assessment", "governance", "penalty", "data subject"
    ]
    hit_count = sum(1 for tok in compliance_tokens if tok in resp_lower)
    token_score = min(1.0, 0.4 + (hit_count * 0.12))

    if framework and framework.lower() in resp_lower:
        token_score = min(1.0, token_score + 0.15)

    return max(0.0, min(1.0, token_score - penalty))


def score_response(
    query: str,
    response: str,
    framework: Optional[str] = None,
    sources: Optional[List[str]] = None
) -> Dict[str, Any]:
    """
    Evaluates response quality using reward model components.
    
    Returns:
      {
        "reward_score": float (0.0 to 1.0),
        "verdict": "ACCEPT" | "MARGINAL" | "REJECT",
        "breakdown": {
           "grounding": float,
           "relevance": float,
           "length_penalty": float
        }
      }
    """
    if not response or not response.strip():
        return {
            "reward_score": 0.0,
            "verdict": "REJECT",
            "breakdown": {"grounding": 0.0, "relevance": 0.0, "length_penalty": 1.0}
        }

    # 1. Grounding score
    grounding = score_grounding_similarity(response, sources or [])

    # 2. Framework relevance score
    relevance = score_framework_relevance(response, framework)

    # 3. Length / verbosity sanity
    char_len = len(response.strip())
    length_mult = 1.0
    if char_len < 40:
        length_mult = 0.5
    elif char_len > 4000:
        length_mult = 0.85

    # Composite Reward Calculation
    raw_reward = (0.50 * grounding + 0.50 * relevance) * length_mult
    final_reward = round(float(np.clip(raw_reward, 0.0, 1.0)), 3)

    if final_reward >= 0.65:
        verdict = "ACCEPT"
    elif final_reward >= 0.45:
        verdict = "MARGINAL"
    else:
        verdict = "REJECT"

    return {
        "reward_score": final_reward,
        "verdict": verdict,
        "breakdown": {
            "grounding": round(grounding, 3),
            "relevance": round(relevance, 3),
            "length_multiplier": round(length_mult, 2)
        }
    }


def rank_candidate_responses(
    query: str,
    candidates: List[str],
    framework: Optional[str] = None,
    sources: Optional[List[str]] = None
) -> List[Dict[str, Any]]:
    """
    Best-of-N rejection sampling ranker.
    Ranks candidate responses by descending reward score.
    """
    results = []
    for idx, cand in enumerate(candidates):
        eval_res = score_response(query, cand, framework=framework, sources=sources)
        results.append({
            "candidate_index": idx,
            "response": cand,
            **eval_res
        })
    results.sort(key=lambda x: x["reward_score"], reverse=True)
    return results


def main():
    parser = argparse.ArgumentParser(description="Agent 9: RLHF Reward Model & Scorer")
    parser.add_argument("--test-query", type=str, default="What is GDPR Article 5?", help="Test user query")
    parser.add_argument("--test-response", type=str, required=True, help="Test response string to score")
    parser.add_argument("--framework", type=str, default="gdpr", help="Framework code")
    args = parser.parse_args()

    print(f"\nScoring Response for Query: '{args.test_query}' (Framework: {args.framework})")
    print(f"Response: {args.test_response}\n")

    res = score_response(args.test_query, args.test_response, framework=args.framework)
    print(json.dumps(res, indent=2))


if __name__ == "__main__":
    main()

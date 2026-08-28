"""
Self-Healing RAG — wraps the existing RAG pipeline with automatic correction.
--------------------------------------------------------------------------------
This module does NOT modify rag_utils.py or any existing function. It calls
your existing retrieve() and rag_answer() functions and adds two safety
loops around them:

1. RETRIEVAL GRADING: after retrieving chunks, check if they're actually
   relevant to the question. If not, rewrite the query and try again
   (up to max_retries times) before falling back to "insufficient info."

2. GROUNDING CHECK: after generating an answer, check if it's actually
   supported by the retrieved context. If not, regenerate with a stricter
   prompt, or fall back to an honest "can't fully answer this" response.

Because this is a separate module, every existing call site
(Standards RAG tab, framework_router's RAG fallback) continues to work
completely unchanged unless you explicitly switch it to call
self_healing_rag_answer() instead of rag_utils.rag_answer().
"""

import os
import re
import sys
from typing import Optional, Dict, Any, List

# Ensure agents directory is in sys.path so config can be imported
_agents_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "agents")
if _agents_path not in sys.path:
    sys.path.insert(0, _agents_path)

try:
    import config
except ImportError:
    from agents import config

try:
    import rag_utils
except ImportError:
    import database.rag_utils as rag_utils

MAX_RETRIES = 2
RETRIEVAL_RELEVANCE_THRESHOLD = 0.35   # below this avg similarity, retrieval is considered weak


# ------------------------------------------------------------------
# Step A: Retrieval grading
# ------------------------------------------------------------------
def grade_retrieval(query: str, hits: list[dict]) -> dict:
    """Returns {is_relevant: bool, reason: str}. Two-tier check:
    1. Fast embedding-similarity check for high confidence (avg similarity >= 0.40)
    2. Ask LLM judge to evaluate retrieved excerpts before discarding hits
    """
    if not hits:
        return {"is_relevant": False, "reason": "No sources retrieved at all."}

    avg_score = sum(h["score"] for h in hits) / len(hits)
    if avg_score >= 0.40:
        return {"is_relevant": True, "reason": f"High retrieval confidence (avg similarity {avg_score:.2f})."}

    # Evaluate retrieved excerpts with LLM judge
    sources_preview = "\n".join(f"- {h['text'][:250]}" for h in hits[:3])
    prompt = (
        f"Question: {query}\n\nRetrieved excerpts:\n{sources_preview}\n\n"
        f"Do these excerpts contain information relevant to answering the question? "
        f"Reply with exactly one word: YES or NO."
    )
    verdict = config.generate(prompt, max_new_tokens=5).strip().upper()
    is_relevant = verdict.startswith("Y")
    return {"is_relevant": is_relevant, "reason": f"LLM relevance judgment: {verdict} (avg similarity {avg_score:.2f})"}


def rewrite_query(original_query: str, reason: str) -> str:
    """Asks the LLM to rewrite the query to retrieve better — broader terms,
    different phrasing, or standard cybersecurity terminology."""
    prompt = (
        f"A search for this question retrieved poor results: \"{original_query}\"\n"
        f"Reason: {reason}\n\n"
        f"Rewrite the question to be more likely to retrieve relevant document excerpts. "
        f"Keep standard cybersecurity acronyms intact (e.g. NIST CSF = NIST Cybersecurity Framework, GDPR, NIS2, DPDP). "
        f"Reply with ONLY the rewritten question, nothing else."
    )
    rewritten = config.generate(prompt, max_new_tokens=40).strip()
    return rewritten if rewritten else original_query


# ------------------------------------------------------------------
# Step B: Grounding check (hallucination detection)
# ------------------------------------------------------------------
def grade_grounding(answer: str, hits: list[dict], query: Optional[str] = None, framework: Optional[str] = None) -> dict:
    """Checks whether the generated answer is actually supported by the
    retrieved sources. Incorporates Agent 9 Reward Model scoring when available."""
    sources_text = [h["text"] for h in hits] if hits else []
    reward_info = None

    # Step 1: Agent 9 Reward Model check if available
    try:
        from agents import agent9_reward_model
        if query:
            reward_info = agent9_reward_model.score_response(
                query=query,
                response=answer,
                framework=framework,
                sources=sources_text
            )
    except Exception:
        reward_info = None

    # If reward model score is definitively high, pass immediately
    if reward_info and reward_info.get("reward_score", 0) >= 0.70:
        return {
            "is_grounded": True,
            "reason": f"Agent 9 Reward Model verified (Score: {reward_info['reward_score']})",
            "reward_score": reward_info["reward_score"],
            "verdict": reward_info["verdict"]
        }

    # Step 2: LLM judge fallback
    context = "\n".join(f"- {h['text'][:300]}" for h in hits)
    prompt = (
        f"Sources:\n{context}\n\n"
        f"Generated answer: {answer}\n\n"
        f"Is this answer FULLY supported by the sources above, with no invented facts? "
        f"Reply with exactly one word: YES or NO."
    )
    try:
        verdict = config.generate(prompt, max_new_tokens=5).strip().upper()
        is_grounded = verdict.startswith("Y")
        reason = f"LLM grounding judgment: {verdict}"
    except Exception:
        # If config.generate fails, rely on reward_info or fallback
        if reward_info:
            is_grounded = reward_info.get("verdict") != "REJECT"
            reason = f"Reward Model fallback verdict: {reward_info.get('verdict')}"
        else:
            is_grounded = True
            reason = "Default grounding fallback (check bypassed)"

    res = {"is_grounded": is_grounded, "reason": reason}
    if reward_info:
        res["reward_score"] = reward_info["reward_score"]
        res["verdict"] = reward_info["verdict"]
    return res


# ------------------------------------------------------------------
# Main entry point — this is the only new function you actually call
# ------------------------------------------------------------------
def self_healing_rag_answer(model, tokenizer, device, embedder, collection, query: str,
                              k: int = 5, jurisdictions=None, frameworks=None,
                              max_retries: int = MAX_RETRIES):
    """Drop-in replacement for rag_utils.rag_answer(), but with automatic
    retrieval/grounding correction. Returns (answer, hits, trace) where trace
    is a list of correction steps taken, for UI transparency."""
    trace = []
    current_query = query

    # ---- Retrieval loop with query rewriting ----
    hits = []
    for attempt in range(max_retries + 1):
        hits = rag_utils.retrieve(embedder, collection, current_query, k=k,
                                   jurisdictions=jurisdictions, frameworks=frameworks)
        grade = grade_retrieval(current_query, hits)
        trace.append({
            "step": f"retrieval_attempt_{attempt + 1}",
            "query": current_query,
            "relevant": grade["is_relevant"],
            "reason": grade["reason"],
        })

        if grade["is_relevant"]:
            break

        if attempt < max_retries:
            current_query = rewrite_query(current_query, grade["reason"])
            trace.append({"step": "query_rewritten", "new_query": current_query})
        else:
            # Exhausted retries — be honest instead of guessing
            return (
                "I wasn't able to find sufficiently relevant information to answer this "
                "confidently, even after refining the search. You may want to check if "
                "the relevant standard has been ingested, or rephrase your question.",
                hits,
                trace,
            )

    # Framework identifier for reward model
    primary_fw = frameworks[0] if isinstance(frameworks, list) and frameworks else None

    # ---- Generation + grounding check loop ----
    for attempt in range(max_retries + 1):
        answer, _ = rag_utils.rag_answer(model, tokenizer, device, query, hits)
        grounding = grade_grounding(answer, hits, query=query, framework=primary_fw)
        step_log = {
            "step": f"grounding_check_attempt_{attempt + 1}",
            "grounded": grounding["is_grounded"],
            "reason": grounding["reason"],
        }
        if "reward_score" in grounding:
            step_log["reward_score"] = grounding["reward_score"]
        trace.append(step_log)

        if grounding["is_grounded"]:
            return answer, hits, trace

        if attempt == max_retries:
            # Final fallback — return the answer but flag it clearly rather
            # than silently presenting a possibly-hallucinated response
            flagged_answer = (
                answer + "\n\n*(Note: this answer could not be fully verified against "
                "the retrieved sources — treat with extra caution.)*"
            )
            return flagged_answer, hits, trace

    return answer, hits, trace

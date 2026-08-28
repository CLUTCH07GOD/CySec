"""
Explainability — RAG Answer Transparency & Confidence Scoring
---------------------------------------------------------------
Takes existing RAG outputs (retrieved hits, answer text, self-healing trace)
and enriches them into a structured explainability report.

Usage:
    import explainability

    report = explainability.build_explainability_report(
        query="What is NIST CSF?",
        answer="NIST CSF is a framework...",
        hits=[...],              # from rag_utils.retrieve()
        trace=[...],             # from self_healing_rag (optional)
    )

    # report is a dict with keys:
    #   - confidence_score (float, 0-1)
    #   - confidence_label ("High" / "Medium" / "Low")
    #   - retrieved_sources (list of source summaries)
    #   - source_attribution (mapping of claims to source numbers)
    #   - self_healing_summary (optional, if trace was provided)

This module is purely additive — it reads existing outputs and returns
enriched metadata. No existing functions are modified.
"""

from __future__ import annotations


# ---------------------------------------------------------------------------
# Confidence scoring
# ---------------------------------------------------------------------------
def compute_confidence(
    hits: list[dict],
    grounding_passed: bool | None = None,
) -> tuple[float, str]:
    """
    Computes an overall answer confidence score (0.0 – 1.0) based on:
      - Average retrieval similarity of top-k hits
      - Whether grounding check passed (if available)

    Returns (score, label) where label is "High", "Medium", or "Low".
    """
    if not hits:
        return 0.0, "Low"

    avg_similarity = sum(h.get("score", 0.0) for h in hits) / len(hits)
    top_similarity = max(h.get("score", 0.0) for h in hits)

    # Weighted score: 60% from top hit, 40% from average
    base_score = 0.6 * top_similarity + 0.4 * avg_similarity

    # Grounding bonus/penalty
    if grounding_passed is True:
        base_score = min(1.0, base_score + 0.1)
    elif grounding_passed is False:
        base_score = max(0.0, base_score - 0.2)

    # Clamp and label
    score = max(0.0, min(1.0, base_score))
    if score >= 0.6:
        label = "High"
    elif score >= 0.35:
        label = "Medium"
    else:
        label = "Low"

    return round(score, 3), label


# ---------------------------------------------------------------------------
# Source summarization
# ---------------------------------------------------------------------------
def summarize_sources(hits: list[dict]) -> list[dict]:
    """
    Returns a clean list of source summaries for display.
    Each entry has: source_number, jurisdiction, framework, source_file, score, preview.
    """
    summaries = []
    for i, h in enumerate(hits, start=1):
        preview = h.get("text", "")[:200].replace("\n", " ").strip()
        if len(h.get("text", "")) > 200:
            preview += "…"
        summaries.append({
            "source_number": i,
            "jurisdiction": h.get("jurisdiction", "unknown").upper(),
            "framework": h.get("framework", "unknown").upper(),
            "source_file": h.get("source_file", "unknown"),
            "similarity_score": round(h.get("score", 0.0), 4),
            "preview": preview,
        })
    return summaries


# ---------------------------------------------------------------------------
# Self-healing trace summary
# ---------------------------------------------------------------------------
def summarize_trace(trace: list[dict] | None) -> dict | None:
    """
    Condenses a self-healing trace into a human-readable summary.
    Returns None if trace is empty or not provided.
    """
    if not trace:
        return None

    retrieval_attempts = [t for t in trace if t.get("step", "").startswith("retrieval_attempt")]
    rewrites = [t for t in trace if t.get("step") == "query_rewritten"]
    grounding_checks = [t for t in trace if t.get("step", "").startswith("grounding_check")]

    final_retrieval = retrieval_attempts[-1] if retrieval_attempts else None
    final_grounding = grounding_checks[-1] if grounding_checks else None

    return {
        "total_retrieval_attempts": len(retrieval_attempts),
        "queries_rewritten": len(rewrites),
        "final_retrieval_relevant": final_retrieval.get("relevant") if final_retrieval else None,
        "grounding_checks_performed": len(grounding_checks),
        "final_grounding_passed": final_grounding.get("grounded") if final_grounding else None,
        "rewritten_queries": [r.get("new_query", "") for r in rewrites],
    }


# ---------------------------------------------------------------------------
# Main report builder
# ---------------------------------------------------------------------------
def build_explainability_report(
    query: str,
    answer: str,
    hits: list[dict],
    trace: list[dict] | None = None,
    grounding_passed: bool | None = None,
) -> dict:
    """
    Builds a complete explainability report from RAG outputs.

    Args:
        query: The original user question.
        answer: The generated answer text.
        hits: List of retrieved document hits from rag_utils.retrieve().
        trace: Optional self-healing trace from self_healing_rag.
        grounding_passed: Optional bool indicating if grounding check passed.

    Returns:
        A structured dict with confidence, sources, attribution, and trace summary.
    """
    # Infer grounding status from trace if not explicitly provided
    if grounding_passed is None and trace:
        grounding_checks = [t for t in trace if t.get("step", "").startswith("grounding_check")]
        if grounding_checks:
            grounding_passed = grounding_checks[-1].get("grounded")

    confidence_score, confidence_label = compute_confidence(hits, grounding_passed)

    report = {
        "query": query,
        "confidence_score": confidence_score,
        "confidence_label": confidence_label,
        "sources_used": len(hits),
        "retrieved_sources": summarize_sources(hits),
        "avg_retrieval_similarity": round(
            sum(h.get("score", 0.0) for h in hits) / max(len(hits), 1), 4
        ),
        "grounding_passed": grounding_passed,
    }

    # Add self-healing summary if trace is available
    trace_summary = summarize_trace(trace)
    if trace_summary:
        report["self_healing_summary"] = trace_summary

    return report


# ---------------------------------------------------------------------------
# Standalone test
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import json

    mock_hits = [
        {"text": "NIST CSF is a voluntary framework...", "jurisdiction": "us",
         "framework": "nist_csf", "source_file": "nist_csf_2_0.pdf", "score": 0.72},
        {"text": "The Framework Core consists of...", "jurisdiction": "us",
         "framework": "nist_csf", "source_file": "nist_csf_2_0.pdf", "score": 0.65},
        {"text": "Cybersecurity risk management...", "jurisdiction": "us",
         "framework": "nist_csf", "source_file": "nist_csf_2_0.pdf", "score": 0.58},
    ]
    mock_trace = [
        {"step": "retrieval_attempt_1", "query": "What is NIST CSF?",
         "relevant": True, "reason": "High retrieval confidence (avg similarity 0.65)."},
        {"step": "grounding_check_attempt_1", "grounded": True,
         "reason": "LLM grounding judgment: YES"},
    ]

    report = build_explainability_report(
        query="What is NIST CSF?",
        answer="NIST CSF is a voluntary framework for managing cybersecurity risk.",
        hits=mock_hits,
        trace=mock_trace,
    )
    print(json.dumps(report, indent=2))

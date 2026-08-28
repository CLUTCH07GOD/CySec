import os
import re
import sys
from typing import Dict, Any, Optional

KNOWN_FRAMEWORKS = [
    "nist/csf", "eu/gdpr", "india/dpdp", "international/iso27001",
    "eu/nis2", "nist/zero_trust", "nist/cloud", "nist/iot",
    "us/hipaa", "us/nist_ai_rmf", "owasp/asvs_v5", "owasp/wstg",
    "cwe", "cert_in", "nist/800_63b_r4"
]

FRAMEWORK_KEYWORDS = {
    # Privacy & Protection
    "gdpr": "eu/gdpr",
    "general data protection": "eu/gdpr",
    "dpdp": "india/dpdp",
    "digital personal data": "india/dpdp",
    "data protection officer": "india/dpdp",
    
    # ISO & International
    "iso 27001": "international/iso27001",
    "iso27001": "international/iso27001",
    "annex a": "international/iso27001",
    
    # NIST Suites
    "csf": "nist/csf",
    "nist csf": "nist/csf",
    "cybersecurity framework": "nist/csf",
    "pr.ac": "nist/csf",
    "pr.aa": "nist/csf",
    "zero trust": "nist/zero_trust",
    "sp 800-207": "nist/zero_trust",
    "800-207": "nist/zero_trust",
    "sp 800-144": "nist/cloud",
    "800-144": "nist/cloud",
    "sp 800-213": "nist/iot",
    "800-213": "nist/iot",
    "sp 800-63b": "nist/800_63b_r4",
    "800-63b": "nist/800_63b_r4",
    "authenticator assurance": "nist/800_63b_r4",
    "ai rmf": "us/nist_ai_rmf",
    "ai 100-1": "us/nist_ai_rmf",
    "nist ai": "us/nist_ai_rmf",
    
    # Web & Application Security
    "wstg": "owasp/wstg",
    "web security testing": "owasp/wstg",
    "asvs": "owasp/asvs_v5",
    "asvs v5": "owasp/asvs_v5",
    "cwe": "cwe",
    "cwe-89": "cwe",
    "cwe-79": "cwe",
    
    # Regulatory & Critical Infrastructure
    "cert-in": "cert_in",
    "cert in": "cert_in",
    "cert_in": "cert_in",
    "nis2": "eu/nis2",
    "hipaa": "us/hipaa",
}

def route_query(query: str) -> Dict[str, Any]:
    """Detects target compliance framework and intent from query string."""
    q_lower = query.lower()
    
    # 1. Direct path matching (e.g. nist/csf)
    matched_fw = None
    for fw in KNOWN_FRAMEWORKS:
        if fw in q_lower:
            matched_fw = fw
            break
            
    if not matched_fw:
        for kw, fw in FRAMEWORK_KEYWORDS.items():
            if re.search(r'\b' + re.escape(kw) + r'\b', q_lower):
                matched_fw = fw
                break

    # 2. Intent detection using strict word boundaries and contextual syntax
    if re.search(r'\b(probe|scan|check url|live probe)\b', q_lower):
        intent = "live_web_probe"
    elif re.search(r'\b(map\s+[\w/]+\s+to\b|cross[- ]map|mapping\s+table|compare\s+[\w/]+\s+(with|to|vs)|versus|\bvs\b)', q_lower):
        intent = "map_frameworks"
    elif re.search(r'\b(assess|audit|gap analysis|compliance check)\b', q_lower):
        intent = "assess_framework"
    elif re.search(r'\b(generate report|export report|download report)\b', q_lower):
        intent = "generate_report"
    elif re.search(r'\b(list frameworks|show frameworks|available standards)\b', q_lower):
        intent = "list_frameworks"
    else:
        intent = "rag_query"

    return {
        "framework": matched_fw or "nist/csf",
        "intent": intent,
        "raw_query": query
    }

def answer_single(query, model, tokenizer, device, embedder, adapter_centroids,
                   rag_collection=None, rag_utils_module=None, length_max_tokens=300,
                   use_self_healing=False):   # NEW parameter, defaults to OFF
    """
    Answer a query by routing to appropriate adapter or RAG fallback.
    If use_self_healing=True, wraps RAG retrieval and generation with
    self-correcting loops (retrieval grading + grounding check).
    """
    routing = {"use_self_healing": use_self_healing}

    if rag_collection is not None and rag_utils_module is not None:
        hits = rag_utils_module.retrieve(embedder, rag_collection, query, k=5)
        if hits:
            if use_self_healing:
                import self_healing_rag
                answer, hits, trace = self_healing_rag.self_healing_rag_answer(
                    model, tokenizer, device, embedder, rag_collection, query
                )
                routing["self_healing_trace"] = trace
            else:
                answer, _ = rag_utils_module.rag_answer(model, tokenizer, device, query, hits)
        else:
            if use_self_healing:
                import self_healing_rag
                answer, hits, trace = self_healing_rag.self_healing_rag_answer(
                    model, tokenizer, device, embedder, rag_collection, query
                )
                routing["self_healing_trace"] = trace
            else:
                answer = "No relevant documents found in RAG collection."
    else:
        answer = "RAG components not configured."

    return answer, routing


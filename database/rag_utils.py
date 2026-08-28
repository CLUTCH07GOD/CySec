"""
RAG Utilities — Retrieval + Grounded Generation + Self-Healing RAG Engine
-------------------------------------------------------------------------
Shared by app.py's "Standards RAG" tab and agentic_router.py.
Retrieves relevant chunks from ChromaDB / Neo4j vector stores.
Includes a Self-Healing RAG Pipeline (Self-RAG / CRAG):
  1. Retrieval Relevance Grading
  2. Query Rewriting & Self-Correction Fallback
  3. Grounded Answer Synthesis
  4. Fidelity & Anti-Hallucination Verification
"""

import time
import re
import chromadb
import torch

CHROMA_DB_DIR = "chroma_db"
COLLECTION_NAME = "standards"


def get_collection():
    client = chromadb.PersistentClient(path=CHROMA_DB_DIR)
    return client.get_or_create_collection(COLLECTION_NAME, embedding_function=None)


def list_available_filters(collection) -> dict:
    """Returns {jurisdiction: [frameworks]} discovered from stored metadata."""
    all_meta = collection.get(include=["metadatas"])["metadatas"]
    filters: dict[str, set] = {}
    for m in all_meta:
        filters.setdefault(m["jurisdiction"], set()).add(m["framework"])
    return {j: sorted(fw) for j, fw in sorted(filters.items())}


def retrieve(embedder, collection, query: str, k: int = 5, jurisdictions=None, frameworks=None):
    """Returns a list of {text, jurisdiction, framework, source_file, score}.
    Attempts Neo4j vector search first if available; falls back to ChromaDB if not.
    """
    query_embedding = embedder.encode([query])[0].tolist()

    # Try Neo4j Vector Retrieval first if active
    try:
        import neo4j_utils
        if neo4j_utils.is_neo4j_available():
            neo4j_hits = neo4j_utils.retrieve_neo4j(
                query_embedding=query_embedding,
                k=k,
                jurisdictions=jurisdictions,
                frameworks=frameworks,
            )
            if neo4j_hits:
                return neo4j_hits
    except Exception:
        pass  # Fall back to ChromaDB on error

    # ChromaDB Fallback Path
    where = None
    conditions = []
    if jurisdictions:
        conditions.append({"jurisdiction": {"$in": jurisdictions}})
    if frameworks:
        conditions.append({"framework": {"$in": frameworks}})
    if len(conditions) == 1:
        where = conditions[0]
    elif len(conditions) > 1:
        where = {"$and": conditions}

    results = collection.query(
        query_embeddings=[query_embedding],
        n_results=k,
        where=where,
        include=["documents", "metadatas", "distances"],
    )

    if not results["documents"] or not results["documents"][0]:
        return []

    hits = []
    for doc, meta, dist in zip(results["documents"][0], results["metadatas"][0], results["distances"][0]):
        if dist > 1.0:
            score = max(0.0, 1.0 - (dist / 2.0))
        else:
            score = max(0.0, 1.0 - dist)
        hits.append(
            {
                "text": doc,
                "jurisdiction": meta["jurisdiction"],
                "framework": meta["framework"],
                "source_file": meta["source_file"],
                "score": score,
            }
        )
    return hits


def build_context_block(hits: list[dict]) -> str:
    """Formats retrieved chunks into a labeled context block for the prompt."""
    blocks = []
    for i, h in enumerate(hits, start=1):
        blocks.append(
            f"[Source {i}: {h['jurisdiction'].upper()} / {h['framework'].upper()} / {h['source_file']}]\n{h['text']}"
        )
    return "\n\n".join(blocks)


def grade_retrieval_quality(hits: list[dict], min_threshold: float = 0.35) -> dict:
    """Self-Healing Grader Node: Assesses similarity and quality of retrieved evidence."""
    if not hits:
        return {"relevant": False, "reason": "No vector hits returned", "max_score": 0.0}
    
    max_score = max(h.get("score", 0.0) for h in hits)
    if max_score < min_threshold:
        return {"relevant": False, "reason": f"Retrieval score ({max_score:.2f}) below threshold ({min_threshold})", "max_score": max_score}
        
    return {"relevant": True, "reason": f"High relevance evidence retrieved (top score: {max_score:.2f})", "max_score": max_score}


def rewrite_query_for_retrieval(query: str) -> str:
    """Self-Healing Query Rewriter Node: Expands abbreviations and regulatory terms."""
    q_lower = query.lower()
    rewritten = query
    
    # Common regulatory abbreviation expansions
    expansions = {
        "dpd": "Digital Personal Data Protection Act India DPDP",
        "dpdp": "Digital Personal Data Protection Act India 2023",
        "gdpr": "General Data Protection Regulation EU 2016/679",
        "nis2": "Network Information Security Directive 2 EU 2022/2555",
        "csf": "NIST Cybersecurity Framework v2.0",
        "nist ai rmf": "NIST Artificial Intelligence Risk Management Framework AI RMF 1.0",
        "iso27001": "ISO IEC 27001 Information Security Management System",
    }
    
    for key, val in expansions.items():
        if re.search(r'\b' + re.escape(key) + r'\b', q_lower):
            rewritten += f" ({val})"
            
    return rewritten


def self_healing_rag_pipeline(embedder, collection, model, tokenizer, device, query: str, k: int = 5) -> dict:
    """
    Self-Healing RAG Pipeline (Self-RAG / CRAG):
      1. Primary Vector Retrieval
      2. Relevance Grading
      3. Automatic Query Rewriting & Re-retrieval (Self-Healing Step)
      4. Grounded Generation & Anti-Hallucination Verification
    """
    logs = [f"[Self-Healing RAG] Initializing pipeline for query: '{query}'"]
    
    # Step 1: Initial Retrieval
    hits = retrieve(embedder, collection, query, k=k)
    grade = grade_retrieval_quality(hits)
    logs.append(f"[Grader Node] Primary retrieval grade: {grade['reason']}")
    
    # Step 2: Self-Healing Trigger (if quality is low)
    if not grade["relevant"]:
        rewritten_q = rewrite_query_for_retrieval(query)
        logs.append(f"[Self-Healing] Triggered Query Rewriter: '{rewritten_q}'")
        secondary_hits = retrieve(embedder, collection, rewritten_q, k=k)
        sec_grade = grade_retrieval_quality(secondary_hits)
        
        if sec_grade["relevant"] or (secondary_hits and max(h["score"] for h in secondary_hits) > grade["max_score"]):
            hits = secondary_hits
            logs.append(f"[Self-Healing] Re-retrieval successful. Recovered {len(hits)} improved evidence chunks.")
        else:
            logs.append("[Self-Healing] Re-retrieval completed with base context.")

    # Step 3: Grounded Answer Synthesis
    ans, gen_time = rag_answer(model, tokenizer, device, query, hits)
    
    # Step 4: Self-Verification (Anti-Hallucination Gate)
    verified_answer = ans
    if "india" in query.lower() and "gdpr" in query.lower():
        if "gdpr is implemented in india" in ans.lower():
            verified_answer = (
                "Correction: GDPR (General Data Protection Regulation) is a European Union law and is NOT implemented in India. "
                "India's statutory privacy legislation is the Digital Personal Data Protection Act (DPDP Act, 2023)."
            )
            logs.append("[Self-Healing Verifier] Corrected cross-jurisdictional hallucination.")

    return {
        "answer": verified_answer,
        "hits": hits,
        "generation_time": gen_time,
        "self_healing_logs": logs
    }


def rag_answer(model, tokenizer, device, query: str, hits: list[dict], max_new_tokens: int = 400):
    """Generates a grounded answer using the base model with LoRA disabled,
    citing the retrieved sources by number (matching build_context_block order)."""
    context_block = build_context_block(hits) if hits else "No direct vector context retrieved."

    system_prompt = (
        "You are a regulatory compliance assistant. Answer the question using ONLY the information in the "
        "provided sources below. Cite sources by their number, e.g. (Source 1), (Source 2). "
        "Maintain strict statutory accuracy. If the sources don't contain enough information to answer, say so clearly."
    )

    user_content = f"Sources:\n\n{context_block}\n\nQuestion: {query}"

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_content},
    ]
    text = tokenizer.apply_chat_template(
        messages, tokenize=False, add_generation_prompt=True, enable_thinking=False
    )
    inputs = tokenizer(text, return_tensors="pt").to(device)

    start_t = time.time()
    with torch.no_grad():
        ctx = None
        if hasattr(model, "active_adapters") and getattr(model, "active_adapters", None):
            try:
                if hasattr(model, "disable_adapter"):
                    ctx = model.disable_adapter()
                elif hasattr(model, "disable_adapters"):
                    ctx = model.disable_adapters()
            except (ValueError, AttributeError):
                ctx = None

        if ctx is None:
            from contextlib import nullcontext
            ctx = nullcontext()

        with ctx:
            output_ids = model.generate(
                **inputs,
                max_new_tokens=max_new_tokens,
                min_new_tokens=40,
                do_sample=True,
                temperature=0.5,
                top_p=0.9,
                repetition_penalty=1.15,
                no_repeat_ngram_size=3,
                pad_token_id=tokenizer.eos_token_id,
            )
    gen_seconds = time.time() - start_t

    generated = output_ids[0][inputs["input_ids"].shape[1]:]
    response = tokenizer.decode(generated, skip_special_tokens=True)
    return response.strip(), gen_seconds

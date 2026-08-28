"""
Core Module: Active Learning & Audit Feedback Collector
------------------------------------------------------
Captures real-time auditor feedback (+1 / -1 ratings, remediation notes),
persists audit evaluations to SQLite, and exports curated negative/correction
samples for continuous LLM fine-tuning without GPU overhead.
Storage: database/compliance_audit.db -> audit_feedback
"""

import os
import json
import sqlite3
from datetime import datetime
from typing import Dict, Any, List, Optional

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_DIR = os.path.join(PROJECT_ROOT, "database")
DB_FILE = os.path.join(DB_DIR, "compliance_audit.db")
DEFAULT_DATASET_EXPORT = os.path.join(PROJECT_ROOT, "domains", "active_learning_dataset.jsonl")


def _get_db_connection() -> sqlite3.Connection:
    """Returns a connection to the SQLite audit database."""
    os.makedirs(DB_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn


def init_feedback_db():
    """Initializes the audit_feedback table in SQLite."""
    with _get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_feedback (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT,
                username TEXT DEFAULT 'guest',
                query TEXT NOT NULL,
                response TEXT NOT NULL,
                framework TEXT DEFAULT 'Auto-Detect',
                rating INTEGER NOT NULL, -- +1 for helpful/accurate, -1 for inaccurate/hallucination
                feedback_reason TEXT DEFAULT '',
                remediation_text TEXT DEFAULT '',
                created_at TEXT NOT NULL
            )
        """)
        conn.commit()


def record_feedback(
    query: str,
    response: str,
    rating: int,
    session_id: str = "default_session",
    username: str = "guest",
    framework: str = "Auto-Detect",
    feedback_reason: str = "",
    remediation_text: str = ""
) -> bool:
    """Records an auditor's evaluation rating for an LLM response."""
    init_feedback_db()
    now_iso = datetime.now().isoformat()
    try:
        with _get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO audit_feedback (
                    session_id, username, query, response, framework,
                    rating, feedback_reason, remediation_text, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                session_id, username, query.strip(), response.strip(),
                framework, rating, feedback_reason.strip(),
                remediation_text.strip(), now_iso
            ))
            conn.commit()
            return True
    except Exception:
        return False


def get_feedback_status_for_message(query: str, response: str) -> Optional[str]:
    """Checks whether feedback was already provided for a specific query & response pair in the database."""
    init_feedback_db()
    if not query or not response:
        return None
    try:
        with _get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT rating FROM audit_feedback WHERE query = ? AND response = ? ORDER BY id DESC LIMIT 1",
                (query.strip(), response.strip())
            )
            row = cursor.fetchone()
            if row:
                return "positive" if row["rating"] > 0 else "negative"
    except Exception:
        pass
    return None


def get_feedback_statistics() -> Dict[str, Any]:
    """Computes total counts, approval rate, and breakdown of positive/negative feedback."""
    init_feedback_db()
    with _get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) as total, SUM(CASE WHEN rating > 0 THEN 1 ELSE 0 END) as positive, SUM(CASE WHEN rating < 0 THEN 1 ELSE 0 END) as negative FROM audit_feedback")
        row = cursor.fetchone()
        total = row["total"] or 0
        pos = row["positive"] or 0
        neg = row["negative"] or 0
        rate = round((pos / total * 100), 1) if total > 0 else 100.0
        return {
            "total_reviews": total,
            "positive_count": pos,
            "negative_count": neg,
            "approval_rate_pct": rate
        }


def get_recent_feedback(limit: int = 50) -> List[Dict[str, Any]]:
    """Fetches recently logged auditor feedback."""
    init_feedback_db()
    with _get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM audit_feedback ORDER BY id DESC LIMIT ?", (limit,))
        rows = cursor.fetchall()
        return [dict(r) for r in rows]


def get_feedback_count_by_framework() -> Dict[str, Dict[str, int]]:
    """Returns feedback counts grouped by framework."""
    init_feedback_db()
    stats = {}
    with _get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT framework,
                   COUNT(*) as total,
                   SUM(CASE WHEN rating > 0 THEN 1 ELSE 0 END) as positive,
                   SUM(CASE WHEN rating < 0 THEN 1 ELSE 0 END) as negative,
                   SUM(CASE WHEN LENGTH(remediation_text) > 0 THEN 1 ELSE 0 END) as with_remediation
            FROM audit_feedback
            GROUP BY framework
        """)
        for row in cursor.fetchall():
            fw = row["framework"] or "Auto-Detect"
            stats[fw] = {
                "total": row["total"] or 0,
                "positive": row["positive"] or 0,
                "negative": row["negative"] or 0,
                "with_remediation": row["with_remediation"] or 0,
            }
    return stats


def export_sft_corrections(framework: Optional[str] = None, output_path: Optional[str] = None) -> tuple[int, str]:
    """
    Exports high-quality auditor corrections (rating < 0 with remediation text)
    formatted for SFT training with instruction/output/text fields.
    """
    init_feedback_db()
    out_file = output_path or os.path.join(PROJECT_ROOT, "domains", "sft_feedback_corrections.jsonl")
    os.makedirs(os.path.dirname(out_file), exist_ok=True)

    query_sql = """
        SELECT query, response, remediation_text, framework
        FROM audit_feedback
        WHERE LENGTH(remediation_text) > 0
    """
    params = []
    if framework and framework.lower() != "all":
        query_sql += " AND LOWER(framework) = LOWER(?)"
        params.append(framework)

    count = 0
    with _get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(query_sql, params)
        rows = cursor.fetchall()
        with open(out_file, "w", encoding="utf-8") as f:
            for r in rows:
                instruction = r["query"].strip()
                output = r["remediation_text"].strip()
                if not instruction or not output:
                    continue
                chat_text = f"<|im_start|>user\n{instruction}<|im_end|>\n<|im_start|>assistant\n{output}<|im_end|>\n"
                item = {
                    "instruction": instruction,
                    "input": "",
                    "output": output,
                    "text": chat_text,
                    "source": "auditor_remediation",
                    "framework": r["framework"]
                }
                f.write(json.dumps(item) + "\n")
                count += 1

    return count, out_file


def export_dpo_pairs(framework: Optional[str] = None, output_path: Optional[str] = None) -> tuple[int, str]:
    """
    Exports preference pairs (prompt, chosen, rejected) for DPO training:
      - Prompt: user query formatted in chat template
      - Chosen: auditor remediation text (or +1 verified response)
      - Rejected: original flawed model output (rated -1)
    """
    init_feedback_db()
    out_file = output_path or os.path.join(PROJECT_ROOT, "domains", "dpo_preference_pairs.jsonl")
    os.makedirs(os.path.dirname(out_file), exist_ok=True)

    count = 0
    with _get_db_connection() as conn:
        cursor = conn.cursor()
        
        # 1. Negative ratings with explicit remediation text (Highest quality pairs)
        query_sql = """
            SELECT query, response, remediation_text, framework
            FROM audit_feedback
            WHERE rating < 0 AND LENGTH(remediation_text) > 0
        """
        params = []
        if framework and framework.lower() != "all":
            query_sql += " AND LOWER(framework) = LOWER(?)"
            params.append(framework)
            
        cursor.execute(query_sql, params)
        remediation_rows = cursor.fetchall()

        # 2. Matching positive (+1) and negative (-1) responses on the same query
        query_contrast_sql = """
            SELECT a.query, a.response as chosen_text, b.response as rejected_text, a.framework
            FROM audit_feedback a
            JOIN audit_feedback b ON a.query = b.query AND a.id != b.id
            WHERE a.rating > 0 AND b.rating < 0
        """
        params_contrast = []
        if framework and framework.lower() != "all":
            query_contrast_sql += " AND LOWER(a.framework) = LOWER(?)"
            params_contrast.append(framework)

        cursor.execute(query_contrast_sql, params_contrast)
        contrast_rows = cursor.fetchall()

        seen_pairs = set()
        with open(out_file, "w", encoding="utf-8") as f:
            # Write remediation-based pairs
            for r in remediation_rows:
                prompt_raw = r["query"].strip()
                chosen_raw = r["remediation_text"].strip()
                rejected_raw = r["response"].strip()
                if not prompt_raw or not chosen_raw or not rejected_raw or chosen_raw == rejected_raw:
                    continue
                pair_key = (prompt_raw, chosen_raw, rejected_raw)
                if pair_key in seen_pairs:
                    continue
                seen_pairs.add(pair_key)

                prompt_fmt = f"<|im_start|>user\n{prompt_raw}<|im_end|>\n<|im_start|>assistant\n"
                chosen_fmt = f"{chosen_raw}<|im_end|>\n"
                rejected_fmt = f"{rejected_raw}<|im_end|>\n"

                item = {
                    "prompt": prompt_fmt,
                    "chosen": chosen_fmt,
                    "rejected": rejected_fmt,
                    "query": prompt_raw,
                    "chosen_response": chosen_raw,
                    "rejected_response": rejected_raw,
                    "framework": r["framework"],
                    "source": "remediation_pair"
                }
                f.write(json.dumps(item) + "\n")
                count += 1

            # Write positive vs negative contrast pairs
            for r in contrast_rows:
                prompt_raw = r["query"].strip()
                chosen_raw = r["chosen_text"].strip()
                rejected_raw = r["rejected_text"].strip()
                if not prompt_raw or not chosen_raw or not rejected_raw or chosen_raw == rejected_raw:
                    continue
                pair_key = (prompt_raw, chosen_raw, rejected_raw)
                if pair_key in seen_pairs:
                    continue
                seen_pairs.add(pair_key)

                prompt_fmt = f"<|im_start|>user\n{prompt_raw}<|im_end|>\n<|im_start|>assistant\n"
                chosen_fmt = f"{chosen_raw}<|im_end|>\n"
                rejected_fmt = f"{rejected_raw}<|im_end|>\n"

                item = {
                    "prompt": prompt_fmt,
                    "chosen": chosen_fmt,
                    "rejected": rejected_fmt,
                    "query": prompt_raw,
                    "chosen_response": chosen_raw,
                    "rejected_response": rejected_raw,
                    "framework": r["framework"],
                    "source": "contrast_pair"
                }
                f.write(json.dumps(item) + "\n")
                count += 1

    return count, out_file


def export_feedback_to_dataset(output_path: Optional[str] = None) -> tuple[int, str]:
    """
    Exports logged negative/remediation feedback into fine-tuning dataset JSONL format.
    Returns (sample_count, export_path).
    """
    init_feedback_db()
    out_file = output_path or DEFAULT_DATASET_EXPORT
    os.makedirs(os.path.dirname(out_file), exist_ok=True)
    
    count = 0
    with _get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM audit_feedback WHERE rating < 0 OR LENGTH(remediation_text) > 0")
        rows = cursor.fetchall()
        
        with open(out_file, "w", encoding="utf-8") as f:
            for r in rows:
                target_ans = r["remediation_text"] if r["remediation_text"] else r["response"]
                sample = {
                    "messages": [
                        {"role": "system", "content": f"You are an expert compliance auditor specializing in {r['framework']}."},
                        {"role": "user", "content": r["query"]},
                        {"role": "assistant", "content": target_ans}
                    ],
                    "metadata": {
                        "feedback_id": r["id"],
                        "original_rating": r["rating"],
                        "feedback_reason": r["feedback_reason"],
                        "source": "auditor_active_learning"
                    }
                }
                f.write(json.dumps(sample) + "\n")
                count += 1
                
    return count, out_file


# Self-initialize on import
init_feedback_db()


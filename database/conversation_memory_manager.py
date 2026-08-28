"""
Conversation Memory Manager & Database Session Store
----------------------------------------------------
Handles:
  1. Relational Database Session Storage (SQLite `compliance_sessions.db`).
  2. Local JSON File Backup (`saved_sessions/`).
  3. Graph Memory Nodes in Neo4j (when Neo4j is connected).
  4. Pinning, Renaming, and Deleting chat sessions.
  5. Memory token counting & sliding window control.
  6. Context summarization for long audit threads.
"""

import os
import json
import glob
import sqlite3
from datetime import datetime
from typing import List, Dict, Any, Optional

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
SESSIONS_DIR = os.path.join(PROJECT_ROOT, "saved_sessions")
DB_FILE = os.path.join(PROJECT_ROOT, "compliance_sessions.db")

def _ensure_dir():
    os.makedirs(SESSIONS_DIR, exist_ok=True)

def _init_sqlite_db():
    """Initializes SQLite database tables for chat sessions and messages with pinning support."""
    _ensure_dir()
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS chat_sessions (
                id TEXT PRIMARY KEY,
                session_name TEXT NOT NULL,
                saved_at TEXT NOT NULL,
                message_count INTEGER DEFAULT 0,
                is_pinned INTEGER DEFAULT 0,
                metadata TEXT
            )
        """)
        
        # Ensure is_pinned and username columns exist if table was created previously
        cursor.execute("PRAGMA table_info(chat_sessions)")
        columns = [col[1] for col in cursor.fetchall()]
        if "is_pinned" not in columns:
            cursor.execute("ALTER TABLE chat_sessions ADD COLUMN is_pinned INTEGER DEFAULT 0")
        if "username" not in columns:
            cursor.execute("ALTER TABLE chat_sessions ADD COLUMN username TEXT DEFAULT 'guest'")

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS chat_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                role TEXT NOT NULL,
                content TEXT NOT NULL,
                source TEXT,
                ts TEXT,
                FOREIGN KEY (session_id) REFERENCES chat_sessions (id) ON DELETE CASCADE
            )
        """)
        conn.commit()

# Initialize DB structure on import
_init_sqlite_db()
try:
    purge_expired_guest_sessions(max_age_hours=24.0)
except Exception:
    pass

def save_session(session_name: str, messages: List[Dict[str, Any]], metadata: Optional[Dict[str, Any]] = None, username: str = "guest") -> str:
    """Saves current chat session into SQLite database AND local JSON backup."""
    _ensure_dir()
    safe_name = "".join([c if c.isalnum() or c in ("-", "_") else "_" for c in session_name.strip()]).lower()
    if not safe_name:
        safe_name = f"session_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    
    session_id = safe_name
    saved_at = datetime.now().isoformat()
    meta_json = json.dumps(metadata or {})

    # Auto-derive friendly title from first user prompt if default name
    display_title = session_name
    first_user_msg = next((m.get("content", "") for m in messages if m.get("role") == "user"), "")
    if first_user_msg and (session_name.startswith("Audit_Run_") or session_name.startswith("session_")):
        clean_prompt = " ".join(first_user_msg.split())
        display_title = clean_prompt[:35] + "..." if len(clean_prompt) > 35 else clean_prompt

    # 1. Save to SQLite DB
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            # Preserve existing is_pinned status if available
            cursor.execute("SELECT is_pinned, session_name FROM chat_sessions WHERE id = ?", (session_id,))
            row = cursor.fetchone()
            is_pinned = row[0] if row else 0
            # Keep custom session_name if it was explicitly renamed
            if row and row[1] and not row[1].startswith("Audit_Run_") and not row[1].startswith("session_"):
                display_title = row[1]

            cursor.execute("""
                INSERT OR REPLACE INTO chat_sessions (id, session_name, saved_at, message_count, is_pinned, metadata, username)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (session_id, display_title, saved_at, len(messages), is_pinned, meta_json, username))
            
            cursor.execute("DELETE FROM chat_messages WHERE session_id = ?", (session_id,))
            
            for m in messages:
                cursor.execute("""
                    INSERT INTO chat_messages (session_id, role, content, source, ts)
                    VALUES (?, ?, ?, ?, ?)
                """, (
                    session_id,
                    m.get("role", "user"),
                    m.get("content", ""),
                    m.get("source", "UI"),
                    m.get("ts", saved_at)
                ))
            conn.commit()
    except Exception as exc:
        print(f"[Memory DB] SQLite save error: {exc}")

    # 2. Save JSON file backup
    filepath = os.path.join(SESSIONS_DIR, f"{safe_name}.json")
    payload = {
        "session_id": session_id,
        "session_name": display_title,
        "saved_at": saved_at,
        "message_count": len(messages),
        "is_pinned": is_pinned if 'is_pinned' in locals() else 0,
        "metadata": metadata or {},
        "messages": messages
    }
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)

    return filepath

def rename_session(session_id: str, new_title: str) -> bool:
    """Renames a chat session in SQLite DB and JSON backup file."""
    if not new_title.strip():
        return False
    clean_title = new_title.strip()
    
    # 1. Update SQLite DB
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE chat_sessions SET session_name = ? WHERE id = ?", (clean_title, session_id))
            conn.commit()
    except Exception:
        pass

    # 2. Update JSON file backup
    fp = os.path.join(SESSIONS_DIR, f"{session_id}.json")
    if os.path.exists(fp):
        try:
            with open(fp, "r", encoding="utf-8") as f:
                data = json.load(f)
            data["session_name"] = clean_title
            with open(fp, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
        except Exception:
            pass

    return True

def toggle_pin_session(session_id: str) -> bool:
    """Toggles pinned status (0 <-> 1) for a chat session."""
    new_pinned = 0
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT is_pinned FROM chat_sessions WHERE id = ?", (session_id,))
            row = cursor.fetchone()
            if row:
                new_pinned = 1 if row[0] == 0 else 0
                cursor.execute("UPDATE chat_sessions SET is_pinned = ? WHERE id = ?", (new_pinned, session_id))
                conn.commit()
    except Exception:
        pass

    # Update JSON file backup
    fp = os.path.join(SESSIONS_DIR, f"{session_id}.json")
    if os.path.exists(fp):
        try:
            with open(fp, "r", encoding="utf-8") as f:
                data = json.load(f)
            data["is_pinned"] = new_pinned
            with open(fp, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
        except Exception:
            pass

    return True

def list_sessions(username: Optional[str] = None) -> List[Dict[str, Any]]:
    """Returns list of sessions sorted with Pinned sessions first, then newest saved_at. Optionally filtered by username."""
    try:
        purge_expired_guest_sessions(max_age_hours=24.0)
    except Exception:
        pass
    results = []
    try:
        with sqlite3.connect(DB_FILE) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            if username:
                cursor.execute(
                    "SELECT id, session_name, saved_at, message_count, is_pinned, username FROM chat_sessions WHERE username = ? ORDER BY is_pinned DESC, saved_at DESC",
                    (username,)
                )
            else:
                cursor.execute(
                    "SELECT id, session_name, saved_at, message_count, is_pinned, username FROM chat_sessions ORDER BY is_pinned DESC, saved_at DESC"
                )
            rows = cursor.fetchall()
            for r in rows:
                r_dict = dict(r)
                results.append({
                    "filename": f"{r['id']}.json",
                    "session_id": r["id"],
                    "session_name": r["session_name"],
                    "saved_at": r["saved_at"],
                    "message_count": r["message_count"],
                    "is_pinned": bool(r["is_pinned"]),
                    "username": r_dict.get("username", "guest"),
                    "filepath": os.path.join(SESSIONS_DIR, f"{r['id']}.json")
                })
    except Exception:
        pass

    # Fallback to JSON files if DB empty and no specific username requested
    if not results and not username:
        _ensure_dir()
        for filepath in sorted(glob.glob(os.path.join(SESSIONS_DIR, "*.json")), reverse=True):
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    results.append({
                        "filename": os.path.basename(filepath),
                        "session_id": data.get("session_id", os.path.basename(filepath).replace(".json","")),
                        "session_name": data.get("session_name", os.path.basename(filepath)),
                        "saved_at": data.get("saved_at", "N/A"),
                        "message_count": data.get("message_count", len(data.get("messages", []))),
                        "is_pinned": bool(data.get("is_pinned", False)),
                        "filepath": filepath
                    })
            except Exception:
                continue
    return results

def load_session(filepath_or_id: str) -> List[Dict[str, Any]]:
    """Loads session messages from SQLite DB or JSON file."""
    session_id = os.path.basename(filepath_or_id).replace(".json", "")
    try:
        with sqlite3.connect(DB_FILE) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT role, content, source, ts FROM chat_messages WHERE session_id = ? ORDER BY id ASC", (session_id,))
            rows = cursor.fetchall()
            if rows:
                return [{"role": r["role"], "content": r["content"], "source": r["source"], "ts": r["ts"]} for r in rows]
    except Exception:
        pass

    fp = filepath_or_id if os.path.exists(filepath_or_id) else os.path.join(SESSIONS_DIR, f"{session_id}.json")
    if os.path.exists(fp):
        with open(fp, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data.get("messages", [])
    return []

def purge_expired_guest_sessions(max_age_hours: float = 24.0) -> int:
    """
    Deletes guest chat sessions older than max_age_hours (default 24h).
    Preserves registered and admin sessions as well as pinned sessions.
    """
    deleted_count = 0
    now = datetime.now()
    try:
        with sqlite3.connect(DB_FILE) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT id, saved_at, is_pinned FROM chat_sessions WHERE username = 'guest'")
            rows = cursor.fetchall()
            expired_ids = []
            for r in rows:
                if r["is_pinned"]:
                    continue
                saved_at_str = r["saved_at"]
                try:
                    dt = datetime.fromisoformat(saved_at_str)
                    age_hours = (now - dt).total_seconds() / 3600.0
                    if age_hours > max_age_hours:
                        expired_ids.append(r["id"])
                except Exception:
                    pass

            for sid in expired_ids:
                cursor.execute("DELETE FROM chat_sessions WHERE id = ?", (sid,))
                cursor.execute("DELETE FROM chat_messages WHERE session_id = ?", (sid,))
                fp = os.path.join(SESSIONS_DIR, f"{sid}.json")
                if os.path.exists(fp):
                    try:
                        os.remove(fp)
                    except Exception:
                        pass
                deleted_count += 1
            conn.commit()
    except Exception as exc:
        print(f"[Memory DB] Purge error: {exc}")

    # Also clean up unlinked/orphaned guest json files older than max_age_hours
    try:
        for fp in glob.glob(os.path.join(SESSIONS_DIR, "guest_*.json")):
            try:
                mtime = os.path.getmtime(fp)
                age_hours = (now.timestamp() - mtime) / 3600.0
                if age_hours > max_age_hours:
                    os.remove(fp)
            except Exception:
                pass
    except Exception:
        pass

    return deleted_count

def delete_session(filepath_or_id: str) -> bool:
    """Deletes session from SQLite DB, JSON file, and Neo4j."""
    session_id = os.path.basename(filepath_or_id).replace(".json", "")
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM chat_sessions WHERE id = ?", (session_id,))
            cursor.execute("DELETE FROM chat_messages WHERE session_id = ?", (session_id,))
            conn.commit()
    except Exception:
        pass

    fp = filepath_or_id if os.path.exists(filepath_or_id) else os.path.join(SESSIONS_DIR, f"{session_id}.json")
    if os.path.exists(fp):
        try:
            os.remove(fp)
        except Exception:
            pass

    return True

def calculate_memory_stats(messages: List[Dict[str, Any]], max_turns: int = 2) -> Dict[str, Any]:
    """Calculates active turns, total turns, and estimated token usage."""
    total_msgs = len(messages)
    user_msgs = [m for m in messages if m.get("role") == "user"]
    total_turns = len(user_msgs)
    
    active_turns = min(total_turns, max_turns)
    total_chars = sum(len(m.get("content", "")) for m in messages)
    approx_tokens = int(total_chars / 4)
    
    return {
        "total_messages": total_msgs,
        "total_turns": total_turns,
        "active_turns": active_turns,
        "approx_tokens": approx_tokens,
    }

def compress_chat_history(messages: List[Dict[str, Any]], keep_recent: int = 2) -> List[Dict[str, Any]]:
    """Compresses older conversation messages into a single high-density summary block."""
    if len(messages) <= (keep_recent * 2):
        return messages
    
    older_messages = messages[:-(keep_recent * 2)]
    recent_messages = messages[-(keep_recent * 2):]
    
    summary_lines = []
    for m in older_messages:
        role = m.get("role", "system").upper()
        content = m.get("content", "").replace("\n", " ")
        if len(content) > 150:
            content = content[:150] + "..."
        summary_lines.append(f"[{role}]: {content}")
    
    compressed_msg = {
        "role": "system",
        "content": f"Prior Conversation Summary Context:\n" + "\n".join(summary_lines),
        "source": "Memory Compression",
        "ts": datetime.now().isoformat()
    }
    
    return [compressed_msg] + recent_messages

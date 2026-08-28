"""
Core Module: Session State Management
--------------------------------------
Initializes Streamlit session state variables and handles session auto-saving / loading.
"""

from datetime import datetime
import streamlit as st

def init_session_state():
    """Initializes global Streamlit session state defaults if not already present."""
    if "messages" not in st.session_state:
        st.session_state.messages = []
    if "last_assessment" not in st.session_state:
        st.session_state.last_assessment = {}
    if "last_mappings" not in st.session_state:
        st.session_state.last_mappings = {}
    if "active_view" not in st.session_state:
        st.session_state.active_view = "audit"
    if "active_chat_framework" not in st.session_state:
        st.session_state.active_chat_framework = "Auto-Detect (Smart Route)"
    if "current_session_id" not in st.session_state:
        st.session_state.current_session_id = f"Audit_Run_{datetime.now().strftime('%b%d_%H%M%S')}"
    if "authenticated" not in st.session_state:
        st.session_state.authenticated = True
    if "user_role" not in st.session_state:
        st.session_state.user_role = "guest"
    if "username" not in st.session_state:
        st.session_state.username = "guest"
    
    from core.system_settings import get_system_setting
    if "use_self_healing_toggle" not in st.session_state:
        st.session_state.use_self_healing_toggle = get_system_setting("self_healing_rag_enabled", False)
    
    sync_user_session()

def sync_user_session():
    """Isolates chat history and sessions per username when switching accounts or logging in."""
    current_username = st.session_state.get("username", "guest")
    loaded_user = st.session_state.get("loaded_user", None)
    
    if loaded_user != current_username:
        st.session_state.loaded_user = current_username
        import database.conversation_memory_manager as cmm
        user_sessions = cmm.list_sessions(username=current_username)
        if user_sessions:
            latest_sid = user_sessions[0]["session_id"]
            st.session_state.current_session_id = latest_sid
            st.session_state.messages = cmm.load_session(latest_sid)
        else:
            prefix = "Guest_Run_" if current_username == "guest" else "Audit_Run_"
            new_id = f"{prefix}{datetime.now().strftime('%b%d_%H%M%S')}"
            st.session_state.current_session_id = new_id
            st.session_state.messages = []

def auto_save_current_session():
    """Auto-saves the active session messages to SQLite / JSON persistence layer for current username."""
    if "current_session_id" in st.session_state and st.session_state.get("messages"):
        try:
            import conversation_memory_manager as cmm
            curr_user = st.session_state.get("username", "guest")
            cmm.save_session(
                session_name=st.session_state.current_session_id,
                messages=st.session_state.messages,
                username=curr_user
            )
        except Exception as exc:
            pass

def format_relative_time(iso_str: str) -> str:
    """Formats ISO datetime string into human-readable relative time (e.g. '5m ago', '2 hours ago')."""
    if not iso_str or iso_str == "N/A":
        return "Recently"
    try:
        dt = datetime.fromisoformat(iso_str)
        now = datetime.now()
        diff = now - dt
        seconds = diff.total_seconds()
        if seconds < 3600:
            mins = int(seconds / 60)
            return f"{max(mins, 1)}m ago"
        elif seconds < 86400:
            hrs = int(seconds / 3600)
            return f"{hrs} hours ago" if hrs > 1 else "1 hour ago"
        elif seconds < 172800:
            return "Yesterday"
        else:
            days = int(seconds / 86400)
            return f"{days} days ago" if days < 30 else dt.strftime("%b %d")
    except Exception:
        return "Recently"

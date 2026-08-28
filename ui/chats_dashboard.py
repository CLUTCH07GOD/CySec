"""
UI Component: Full-Screen Claude-Style Chats Management Dashboard
-----------------------------------------------------------------
Renders full-screen audit search, bulk select/delete mode, and audit thread listing.
"""

from datetime import datetime
import streamlit as st
import conversation_memory_manager as cmm
from core.session_state import auto_save_current_session, format_relative_time

def render_chats_dashboard():
    """Renders the full-screen Claude-style Chats Management Dashboard view."""
    user_role = st.session_state.get("user_role", "guest")
    if user_role == "guest":
        st.warning("🔒 Chats Dashboard is available for Registered and Admin accounts only.")
        if st.button("Return to Audit View"):
            st.session_state.active_view = "audit"
            st.rerun()
        return

    st.markdown(
        """
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 24px;">
            <h1 style="font-size: 2.4rem; font-weight: 700; color: #f8fafc; margin: 0;">Chats</h1>
        </div>
        """,
        unsafe_allow_html=True
    )

    hdr_c1, hdr_c2, hdr_c3 = st.columns([0.50, 0.25, 0.25])
    
    with hdr_c1:
        search_filter = st.text_input(
            "Search chats",
            placeholder="Search chat history...",
            key="dashboard_search_input",
            label_visibility="collapsed"
        )
    with hdr_c2:
        is_select_mode = st.session_state.get("bulk_select_mode", False)
        select_label = "Cancel selection" if is_select_mode else "Select chats"
        if st.button(select_label, width="stretch", key="dashboard_select_toggle_btn"):
            st.session_state.bulk_select_mode = not is_select_mode
            st.rerun()
    curr_user = st.session_state.get("username", "guest")
    with hdr_c3:
        if st.button("New chat", type="primary", width="stretch", key="dashboard_new_chat_btn"):
            auto_save_current_session()
            new_id = f"Audit_Run_{datetime.now().strftime('%b%d_%H%M%S')}"
            st.session_state.current_session_id = new_id
            st.session_state.messages = []
            st.session_state.active_view = "audit"
            cmm.save_session(new_id, [], username=curr_user)
            st.rerun()

    if st.session_state.get("bulk_select_mode", False):
        st.markdown("<div style='margin-top: 12px;'></div>", unsafe_allow_html=True)
        blk_col1, blk_col2 = st.columns([0.70, 0.30])
        with blk_col1:
            st.info("Check boxes next to chats below to perform bulk operations.")
        with blk_col2:
            if st.button("Delete Selected Chats", type="primary", width="stretch", key="bulk_delete_btn"):
                selected_keys = [k for k, v in st.session_state.items() if k.startswith("chk_dash_") and v]
                for k in selected_keys:
                    s_id = k.replace("chk_dash_", "")
                    cmm.delete_session(s_id)
                st.toast("Selected chats deleted!", icon="🗑️")
                st.session_state.bulk_select_mode = False
                st.rerun()

    st.markdown("<div style='margin-top: 20px;'></div>", unsafe_allow_html=True)

    all_threads = cmm.list_sessions(username=curr_user)
    if search_filter.strip():
        q = search_filter.lower().strip()
        all_threads = [t for t in all_threads if q in t["session_name"].lower() or q in t["session_id"].lower()]

    if not all_threads:
        st.markdown(
            """
            <div style="padding: 40px; text-align: center; color: #94a3b8; font-size: 1.05rem;">
                No audit chats found matching your search.
            </div>
            """,
            unsafe_allow_html=True
        )
    else:
        for thread in all_threads:
            t_id = thread["session_id"]
            t_name = thread["session_name"]
            t_pinned = thread.get("is_pinned", False)
            t_time_str = format_relative_time(thread.get("saved_at", ""))
            
            row_c1, row_c2, row_c3 = st.columns([0.62, 0.22, 0.16])
            
            with row_c1:
                if st.session_state.get("bulk_select_mode", False):
                    st.checkbox(f"{'⭐ ' if t_pinned else ''}{t_name}", key=f"chk_dash_{t_id}")
                else:
                    pin_prefix = "⭐ " if t_pinned else ""
                    if st.button(f"{pin_prefix}{t_name}", key=f"dash_open_{t_id}", width="stretch"):
                        auto_save_current_session()
                        st.session_state.current_session_id = t_id
                        st.session_state.messages = cmm.load_session(t_id)
                        st.session_state.active_view = "audit"
                        st.rerun()

            with row_c2:
                st.markdown(f"<div style='color: #94a3b8; font-size: 0.9rem; padding-top: 8px; text-align: right;'>{t_time_str}</div>", unsafe_allow_html=True)

            with row_c3:
                with st.popover("Manage"):
                    st.markdown(f"**{t_name}**")
                    pin_lbl = "Unpin" if t_pinned else "Pin to Top"
                    if st.button(pin_lbl, key=f"dash_pin_{t_id}", width="stretch"):
                        cmm.toggle_pin_session(t_id)
                        st.rerun()
                        
                    new_t_in = st.text_input("Rename Title", value=t_name, key=f"dash_ren_in_{t_id}")
                    if st.button("Apply Rename", key=f"dash_ren_btn_{t_id}", width="stretch"):
                        if new_t_in.strip():
                            cmm.rename_session(t_id, new_t_in.strip())
                            st.rerun()
                            
                    if st.button("Delete Chat", key=f"dash_del_{t_id}", type="primary", width="stretch"):
                        cmm.delete_session(t_id)
                        if st.session_state.get("current_session_id") == t_id:
                            st.session_state.messages = []
                            st.session_state.current_session_id = f"Audit_Run_{datetime.now().strftime('%b%d_%H%M%S')}"
                        st.rerun()

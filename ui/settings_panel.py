"""
UI Component: Sidebar Settings Panel
----------------------------------
Renders response length, conversation memory, export tools, database engine expander, and verification toggles cleanly in the sidebar with role-aware gating.
"""

from datetime import datetime
import json
import os
import pandas as pd
try:
    import conversation_memory_manager as cmm
except ImportError:
    from database import conversation_memory_manager as cmm

LENGTH_PRESETS = {
    "Short": 512,
    "Medium": 1024,
    "Long": 2048,
}

def render_settings_panel(
    available_fw: list[str],
    domains: list[str] = None,
    neo4j_active: bool = False,
    neo4j_utils = None,
    on_db_engine_change_fn = None,
    user_role: str = "guest"
):
    """Renders role-filtered settings panel controls cleanly in the sidebar."""
    
    st.markdown(
        """
        <div style="margin-top: 10px; margin-bottom: 8px;">
            <h3 style="margin: 0; font-size: 1.1rem; color: #f8fafc; font-family: 'Outfit', sans-serif;">Engine Settings</h3>
        </div>
        """,
        unsafe_allow_html=True
    )

    # 1. Database Retrieval Engine Settings Expander (Admin Only)
    if user_role == "admin" and (neo4j_utils is not None or on_db_engine_change_fn is not None):
        with st.expander("**Database Engine Settings**", expanded=False):
            st.caption("View active retrieval database engine and switch mode.")
            
            db_status_color = "#34d399" if neo4j_active else "#fbbf24"
            db_status_text = "Connected (Neo4j Aura Graph + Vector)" if neo4j_active else "Active Mode (ChromaDB Local Vector)"
            
            st.markdown(
                f"""
                <div style="background: rgba(15, 23, 42, 0.8); border: 1px solid {db_status_color}; border-radius: 8px; padding: 8px 12px; font-size: 0.85rem; color: {db_status_color}; font-weight: 600; margin-bottom: 12px;">
                    {db_status_text}
                </div>
                """,
                unsafe_allow_html=True,
            )

            active_eng = st.session_state.get("active_db_engine", "ChromaDB (Local Vector)")
            curr_index = 0 if ("Neo4j" in active_eng and neo4j_active) else 1
            
            st.radio(
                "Active Retrieval Engine",
                options=["Neo4j Aura (Graph + Vector)", "ChromaDB (Local Vector)"],
                index=curr_index,
                key="db_engine_radio",
                on_change=on_db_engine_change_fn,
            )

            if neo4j_active and "Neo4j" in active_eng:
                st.info("Currently using Neo4j Aura Graph + Vector database.")
            else:
                st.info("Currently using ChromaDB local vector store.")
                if "Neo4j" in active_eng and not neo4j_active and neo4j_utils:
                    st.warning("Neo4j server is unreachable at `bolt://localhost:7687` or credentials failed. Falling back to ChromaDB.")
                    with st.popover("Configure Neo4j Credentials"):
                        n_uri = st.text_input("Neo4j URI", value=getattr(neo4j_utils, "NEO4J_URI", ""))
                        n_usr = st.text_input("Username", value=getattr(neo4j_utils, "NEO4J_USER", ""))
                        n_pwd = st.text_input("Password", type="password", value=getattr(neo4j_utils, "NEO4J_PASSWORD", ""))
                        if st.button("Test & Connect to Neo4j", width="stretch"):
                            ok = neo4j_utils.reconnect(n_uri, n_usr, n_pwd)
                            if ok:
                                st.toast("Connected to Neo4j successfully!")
                                st.rerun()
                            else:
                                st.error("Failed to connect to Neo4j with provided URI/Credentials.")

        st.divider()

    # 2. Response Length (All roles) - Compact Horizontal Segmented Control
    st.markdown("<p style='font-size: 0.82rem; font-weight: 700; color: #94a3b8; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 4px;'>Response Length</p>", unsafe_allow_html=True)
    st.radio(
        "length",
        options=list(LENGTH_PRESETS.keys()),
        index=1,
        label_visibility="collapsed",
        horizontal=True,
        key="length_preset_radio"
    )

    # Guest user view ends here
    if user_role == "guest":
        return

    # 3. Conversation Memory (Registered & Admin) - Clean Collapsible Expander
    with st.expander("Conversation Memory", expanded=False):
        st.caption("Control conversational turn context and token memory compression.")
        use_memory = st.toggle("Include recent turns as context", value=True, key="use_memory_toggle")
        memory_turns = st.slider("Past exchanges to include", 1, 5, 2, disabled=not use_memory, key="memory_turns_slider")
        
        mem_stats = cmm.calculate_memory_stats(st.session_state.get("messages", []), max_turns=memory_turns)
        col_m1, col_m2 = st.columns(2)
        col_m1.caption(f"**Active Turns:** `{mem_stats['active_turns']}/{mem_stats['total_turns']}`")
        col_m2.caption(f"**Tokens:** `{mem_stats['approx_tokens']}`")

        if st.session_state.get("messages") and len(st.session_state["messages"]) > 4:
            if st.button("Compress & Summarize Memory", width="stretch", help="Compresses older message turns into a single high-density summary block"):
                before_count = len(st.session_state.messages)
                st.session_state.messages = cmm.compress_chat_history(st.session_state.messages, keep_recent=memory_turns)
                after_count = len(st.session_state.messages)
                st.toast(f"Memory compressed: {before_count} msgs → {after_count} msgs")
                st.rerun()
        
        if st.session_state.get("messages"):
            compressed_msgs = [m for m in st.session_state["messages"] if m.get("source") == "Memory Compression"]
            if compressed_msgs:
                st.caption("Status: **Compressed Context Active**")

    # 4. Export & Session Controls (Registered & Admin) - Unified Clean Bar
    msgs = st.session_state.get("messages", [])
    
    col_act_left, col_act_right = st.columns([1, 1])
    with col_act_left:
        with st.popover("Export ▾", width="stretch", help="Download current chat audit trail"):
            st.markdown("#### 📥 Export Audit Data")
            st.caption("Select format to export active audit conversation:")
            
            chat_df = pd.DataFrame([
                {
                    "role": m["role"],
                    "content": m["content"],
                    "source": m.get("source", "N/A"),
                }
                for m in msgs
            ]) if msgs else pd.DataFrame(columns=["role", "content", "source"])

            c_exp1, c_exp2 = st.columns(2)
            with c_exp1:
                st.download_button(
                    "CSV (.csv)",
                    data=chat_df.to_csv(index=False, encoding="utf-8-sig").encode("utf-8-sig"),
                    file_name="compliance_chat_history.csv",
                    mime="text/csv",
                    width="stretch",
                )
            with c_exp2:
                st.download_button(
                    "JSON (.json)",
                    data=json.dumps(msgs, indent=2).encode("utf-8"),
                    file_name="compliance_chat_history.json",
                    mime="application/json",
                    width="stretch",
                )

            md_text = "# Compliance Engine Chat Audit Trail\n\n" + ("\n\n".join([f"### **{m['role'].upper()}**:\n{m['content']}" for m in msgs]) if msgs else "No messages recorded yet.")
            st.download_button(
                "Markdown (.md)",
                data=md_text.encode("utf-8"),
                file_name="compliance_chat_report.md",
                mime="text/markdown",
                width="stretch",
            )

            try:
                import utils.report_exporter as report_exporter
                docx_sidebar_path = "reports/compliance_audit_export.docx"
                report_exporter.export_docx(
                    md_content=md_text,
                    jurisdiction="nist",
                    framework="csf",
                    output_path=docx_sidebar_path
                )
                if os.path.exists(docx_sidebar_path):
                    with open(docx_sidebar_path, "rb") as f_sb_docx:
                        st.download_button(
                            "Word Report (.docx)",
                            data=f_sb_docx.read(),
                            file_name="compliance_audit_report.docx",
                            mime="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                            key="sidebar_docx_export_btn",
                            type="primary",
                            width="stretch",
                        )
            except Exception:
                pass

    with col_act_right:
        if st.button("Clear Chat", width="stretch", help="Reset active chat conversation"):
            st.session_state.messages = []
            st.rerun()

    saved_sessions_list = cmm.list_sessions()
    with st.expander("Session Archive", expanded=False):
        sess_name_in = st.text_input("Session Name", value=f"Audit_Run_{datetime.now().strftime('%b%d_%H%M')}", key="sess_save_name_input")
        if st.button("Save Current Audit Session", width="stretch"):
            if msgs:
                fp = cmm.save_session(sess_name_in, msgs)
                st.success(f"Saved to `{os.path.basename(fp)}`!")
                st.rerun()
            else:
                st.warning("No messages to save.")

        if saved_sessions_list:
            st.divider()
            sess_opts = {s["filename"]: f"{s['session_name']} ({s['message_count']} msgs - {s['saved_at'][:10]})" for s in saved_sessions_list}
            sel_sess_file = st.selectbox("Load Saved Session", options=list(sess_opts.keys()), format_func=lambda k: sess_opts[k])
            
            col_s1, col_s2 = st.columns(2)
            with col_s1:
                if st.button("Load Session", width="stretch"):
                    matched = next((s for s in saved_sessions_list if s["filename"] == sel_sess_file), None)
                    if matched:
                        loaded_msgs = cmm.load_session(matched["filepath"])
                        st.session_state.messages = loaded_msgs
                        st.success(f"Loaded '{matched['session_name']}'!")
                        st.rerun()
            with col_s2:
                if st.button("Delete File", width="stretch"):
                    matched = next((s for s in saved_sessions_list if s["filename"] == sel_sess_file), None)
                    if matched:
                        cmm.delete_session(matched["filepath"])
                        st.success("Deleted.")
                        st.rerun()

    # 5. Self-Healing RAG (Admin Only)
    if user_role == "admin":
        st.subheader("Self-Healing RAG")
        from core.system_settings import get_system_setting, set_system_setting
        persisted_rag = get_system_setting("self_healing_rag_enabled", False)
        if "use_self_healing_toggle" not in st.session_state:
            st.session_state.use_self_healing_toggle = persisted_rag

        def _on_self_healing_change():
            new_val = st.session_state.get("use_self_healing_toggle", False)
            set_system_setting("self_healing_rag_enabled", new_val)

        st.toggle(
            "Self-Healing RAG (slower, more reliable)",
            value=st.session_state.use_self_healing_toggle,
            key="use_self_healing_toggle",
            help="System-wide setting: Automatically retries with query rewriting if retrieval is weak.",
            on_change=_on_self_healing_change
        )
        st.divider()

    # 6. Verifier Engine Settings Expander (Admin Only)
    if user_role == "admin":
        with st.expander("Verifier Engine Settings", expanded=False):
            st.caption("Configure real-time response verification, hallucination interceptor, and verifier model engine.")
            
            verifier_enabled = st.session_state.get("enable_realtime_verifier", True)
            active_verifier_engine = st.session_state.get("verifier_engine_select", "Cloud API (OpenRouter / Nemotron)")
            
            if not verifier_enabled:
                v_status_color = "#94a3b8"
                v_status_text = "Disabled (Verification Off)"
            elif "CyberSec" in active_verifier_engine:
                v_status_color = "#c084fc"
                v_status_text = "Active Mode (Local Qwen2.5-3B + CyberSec-Assistant-3B LoRA)"
            else:
                v_status_color = "#34d399"
                v_status_text = "Connected (Cloud OpenRouter / Nemotron 3 Ultra)"
                
            st.markdown(
                f"""
                <div style="background: rgba(15, 23, 42, 0.8); border: 1px solid {v_status_color}; border-radius: 8px; padding: 8px 12px; font-size: 0.85rem; color: {v_status_color}; font-weight: 600; margin-bottom: 12px;">
                    {v_status_text}
                </div>
                """,
                unsafe_allow_html=True,
            )

            st.toggle(
                "Enable Real-Time Interceptor",
                value=verifier_enabled,
                key="enable_realtime_verifier",
                help="Enable real-time verification and auto-correction of generated compliance answers."
            )

            if st.session_state.get("enable_realtime_verifier", True):
                curr_v_idx = 1 if "CyberSec" in active_verifier_engine else 0
                
                st.radio(
                    "Active Verifier Engine",
                    options=["Cloud API (OpenRouter / Nemotron)", "Local CyberSec-Assistant-3B (LoRA)"],
                    index=curr_v_idx,
                    key="verifier_engine_select",
                    help="Choose between Cloud API (Nemotron 3 Ultra) or Local GPU model (Qwen2.5-3B + CyberSec-Assistant-3B LoRA)."
                )

                if "CyberSec" in active_verifier_engine:
                    st.info("Currently using Local GPU model (Qwen2.5-3B + CyberSec-Assistant-3B LoRA). 100% offline.")
                else:
                    st.info("Currently using Cloud OpenRouter API (Nemotron 3 Ultra / Gemini).")
                    with st.popover("Configure OpenRouter API Key"):
                        api_k_in = st.text_input("OpenRouter API Key", type="password", value=os.environ.get("OPENROUTER_API_KEY", ""))
                        if st.button("Save OpenRouter API Key", width="stretch"):
                            os.environ["OPENROUTER_API_KEY"] = api_k_in
                            st.toast("OpenRouter API Key saved successfully!")
                            st.rerun()

        st.divider()

    # 7. Ingested Frameworks Expander
    if available_fw:
        with st.expander(f"Ingested Frameworks Knowledge Base ({len(available_fw)})", expanded=False):
            st.caption("Scanned & ingested compliance frameworks ready for RAG query and control assessment.")
            render_ingested_frameworks_kb_cards(available_fw)
        st.divider()

    # 8. Active LoRA Adapters (Admin Only)
    if user_role == "admin" and domains:
        with st.expander(f"Active LoRA Adapters ({len(domains)})", expanded=False):
            st.caption("Fine-tuned domain-specific LoRA adapters registered for intelligent routing.")
            render_active_lora_adapters_cards(domains)
        st.divider()

    # 9. User Directory & Account Governance (Admin Only)
    if user_role == "admin":
        with st.expander("User Directory & Account Governance", expanded=False):
            st.caption("View, manage, modify roles, and audit activity statistics for all registered users.")
            render_user_management_panel()
        st.divider()


FW_KNOWLEDGE_METADATA = {
    "cis/aws_foundations": {"name": "AWS Foundations Benchmark", "code": "CIS AWS", "icon": "", "cat": "Cloud & Infrastructure", "color": "#8b5cf6"},
    "cis/k8s": {"name": "Kubernetes Security Benchmark", "code": "CIS K8s", "icon": "", "cat": "Cloud & Infrastructure", "color": "#8b5cf6"},
    "eu/ai_act": {"name": "EU Artificial Intelligence Act", "code": "EU AI Act", "icon": "", "cat": "European Union (EU)", "color": "#3b82f6"},
    "eu/dora": {"name": "Digital Operational Resilience Act", "code": "EU DORA", "icon": "", "cat": "European Union (EU)", "color": "#3b82f6"},
    "eu/gdpr": {"name": "General Data Protection Regulation", "code": "EU GDPR", "icon": "", "cat": "European Union (EU)", "color": "#3b82f6"},
    "eu/nis2": {"name": "Network & Info Systems Directive 2", "code": "EU NIS2", "icon": "", "cat": "European Union (EU)", "color": "#3b82f6"},
    "india/dpdp": {"name": "Digital Personal Data Protection Act", "code": "DPDP 2023", "icon": "", "cat": "Asia-Pacific / India", "color": "#f59e0b"},
    "international/iso27001": {"name": "Information Security Management", "code": "ISO 27001", "icon": "", "cat": "International Standards", "color": "#10b981"},
    "mitre/atlas": {"name": "Adversarial Threat Landscape for AI", "code": "MITRE ATLAS", "icon": "", "cat": "Threat Intelligence", "color": "#ef4444"},
    "mitre/attack": {"name": "ATT&CK Enterprise Matrix v14", "code": "MITRE ATT&CK", "icon": "", "cat": "Threat Intelligence", "color": "#ef4444"},
    "nist/csf": {"name": "Cybersecurity Framework v2.0", "code": "NIST CSF 2.0", "icon": "", "cat": "US & Federal Standards", "color": "#06b6d4"},
    "owasp/asvs_v5": {"name": "Application Security Verification v5", "code": "OWASP ASVS", "icon": "", "cat": "OWASP AppSec", "color": "#ec4899"},
    "owasp/llm_top10": {"name": "Top 10 Vulnerabilities for LLM Apps", "code": "OWASP LLM 10", "icon": "", "cat": "OWASP AppSec", "color": "#ec4899"},
    "owasp/masvs": {"name": "Mobile Application Security Standard", "code": "OWASP MASVS", "icon": "", "cat": "OWASP AppSec", "color": "#ec4899"},
    "owasp/top10_web": {"name": "Top 10 Web Application Risks", "code": "OWASP Top 10", "icon": "", "cat": "OWASP AppSec", "color": "#ec4899"},
    "us/cisa_cpg": {"name": "CISA Cross-Sector Cyber Goals", "code": "CISA CPG", "icon": "", "cat": "US & Federal Standards", "color": "#06b6d4"},
    "us/hipaa": {"name": "Health Insurance Portability Act", "code": "HIPAA Security", "icon": "", "cat": "US & Federal Standards", "color": "#06b6d4"},
    "us/nist_ai_rmf": {"name": "NIST AI Risk Management Framework", "code": "NIST AI RMF", "icon": "", "cat": "US & Federal Standards", "color": "#06b6d4"},
    "us/nist_sp_800_53": {"name": "Security & Privacy Controls Rev 5", "code": "NIST 800-53", "icon": "", "cat": "US & Federal Standards", "color": "#06b6d4"},
    "us/pci_dss_v4": {"name": "Payment Card Industry Data Security v4.0", "code": "PCI DSS v4", "icon": "", "cat": "Financial & Payment", "color": "#10b981"},
    "us/soc2": {"name": "SOC 2 Type II Trust Services Criteria", "code": "SOC 2 Type II", "icon": "", "cat": "US & Federal Standards", "color": "#06b6d4"},
}

def render_ingested_frameworks_kb_cards(available_fw: list[str]):
    """Renders glassmorphic cards with live search and category filter controls."""
    col_search, col_cat = st.columns([1, 1])
    with col_search:
        search_query = st.text_input(
            "Search Frameworks",
            placeholder="Search standard...",
            key="fw_search_query",
            label_visibility="collapsed"
        ).strip().lower()
    with col_cat:
        category_options = [
            "All Categories",
            "Privacy & Data Protection",
            "Cloud & Infrastructure",
            "Application Security (OWASP)",
            "Cybersecurity & Governance",
            "European Union (EU Directives)",
            "Threat Intelligence & AI"
        ]
        selected_category = st.selectbox(
            "Filter Category",
            options=category_options,
            key="fw_category_filter",
            label_visibility="collapsed"
        )

    category_mapping = {
        "Privacy & Data Protection": ["eu/gdpr", "india/dpdp", "us/hipaa"],
        "Cloud & Infrastructure": ["cis/aws_foundations", "cis/k8s"],
        "Application Security (OWASP)": ["owasp/asvs_v5", "owasp/llm_top10", "owasp/masvs", "owasp/top10_web"],
        "Cybersecurity & Governance": ["nist/csf", "international/iso27001", "us/cisa_cpg", "us/nist_ai_rmf", "us/nist_sp_800_53", "us/pci_dss_v4", "us/soc2"],
        "European Union (EU Directives)": ["eu/ai_act", "eu/dora", "eu/gdpr", "eu/nis2"],
        "Threat Intelligence & AI": ["mitre/atlas", "mitre/attack"]
    }

    filtered_fw = []
    for fw in available_fw:
        meta = FW_KNOWLEDGE_METADATA.get(fw, {
            "name": fw.split("/")[-1].replace("_", " ").title(),
            "code": fw.split("/")[-1].upper(),
            "icon": "",
            "cat": "Other Standards",
            "color": "#38bdf8"
        })

        # Apply category filter
        if selected_category != "All Categories":
            allowed_fw_list = category_mapping.get(selected_category, [])
            if fw not in allowed_fw_list and meta.get("cat") != selected_category:
                continue

        # Apply search query filter
        if search_query:
            match_name = search_query in meta["name"].lower()
            match_code = search_query in meta["code"].lower()
            match_id = search_query in fw.lower()
            match_cat = search_query in meta.get("cat", "").lower()
            if not (match_name or match_code or match_id or match_cat):
                continue

        filtered_fw.append((fw, meta))

    if not filtered_fw:
        st.info("No compliance frameworks match your search or filter criteria.")
        return

    categories = {}
    for fw_id, meta in sorted(filtered_fw, key=lambda x: x[0]):
        cat = meta.get("cat", "Other Standards")
        if cat not in categories:
            categories[cat] = []
        categories[cat].append((fw_id, meta))

    for cat_name, items in categories.items():
        st.markdown(f'<div class="fw-kb-cat-title">{cat_name} ({len(items)})</div>', unsafe_allow_html=True)
        cards_markup = []
        for fw_id, m in items:
            color = m["color"]
            cards_markup.append(f"""<div class="fw-card-glass" style="--fw-theme-color: {color}; --fw-glow-color: {color}40;">
    <div>
        <div class="fw-card-top">
            <span class="fw-card-code">{m['code']}</span>
        </div>
        <div class="fw-card-name">{m['name']}</div>
    </div>
    <div class="fw-card-footer">
        <span class="fw-status-tag"><span class="fw-status-dot"></span> Ready</span>
        <span class="fw-id-tag">{fw_id}</span>
    </div>
</div>""")
        grid_html = f'<div class="fw-kb-grid">{"".join(cards_markup)}</div>'
        st.markdown(grid_html, unsafe_allow_html=True)


LORA_ADAPTER_METADATA = {
    "qwen3-80063br4-lora": {"name": "NIST SP 800-53 Rev 5 Controls", "code": "NIST 800-53", "icon": "", "color": "#06b6d4"},
    "qwen3-asvsv5-lora": {"name": "OWASP AppSec Verification v5", "code": "OWASP ASVS", "icon": "", "color": "#ec4899"},
    "qwen3-cloud-lora": {"name": "Cloud Infra & CIS Benchmarks", "code": "Cloud Security", "icon": "", "color": "#8b5cf6"},
    "qwen3-csf-lora": {"name": "NIST Cybersecurity Framework v2.0", "code": "NIST CSF", "icon": "", "color": "#38bdf8"},
    "qwen3-cwev4-lora": {"name": "CWE Top 25 Software Weaknesses", "code": "CWE Top 25", "icon": "", "color": "#f59e0b"},
    "qwen3-dpdp-lora": {"name": "India DPDP Act Privacy Controls", "code": "DPDP 2023", "icon": "", "color": "#f59e0b"},
    "qwen3-gdpr-lora": {"name": "EU GDPR Privacy & DPO Controls", "code": "EU GDPR", "icon": "", "color": "#3b82f6"},
    "qwen3-iot-lora": {"name": "IoT & Embedded Hardware Security", "code": "IoT Security", "icon": "", "color": "#a855f7"},
    "qwen3-iso27001-lora": {"name": "ISO/IEC 27001:2022 ISMS Controls", "code": "ISO 27001", "icon": "", "color": "#10b981"},
    "qwen3-nis2-lora": {"name": "EU NIS2 Critical Infrastructure", "code": "EU NIS2", "icon": "", "color": "#3b82f6"},
    "qwen3-nistairmf-lora": {"name": "NIST AI Risk Management Controls", "code": "NIST AI RMF", "icon": "", "color": "#06b6d4"},
    "qwen3-wstgv42-lora": {"name": "OWASP Web Security Testing v4.2", "code": "OWASP WSTG", "icon": "", "color": "#ec4899"},
    "qwen3-zerotrust-lora": {"name": "Zero Trust Architecture Controls", "code": "Zero Trust", "icon": "", "color": "#6366f1"},
}

def render_active_lora_adapters_cards(domains: list[str]):
    """Renders glassmorphic cards for registered LoRA adapters."""
    cards_markup = []
    for d in sorted(domains):
        meta = LORA_ADAPTER_METADATA.get(d, {
            "name": d.replace("qwen3-", "").replace("-lora", "").replace("_", " ").title(),
            "code": d.replace("qwen3-", "").replace("-lora", "").upper(),
            "icon": "",
            "color": "#c084fc"
        })
        color = meta["color"]
        cards_markup.append(f"""<div class="fw-card-glass" style="--fw-theme-color: {color}; --fw-glow-color: {color}40;">
    <div>
        <div class="fw-card-top">
            <span class="fw-card-code">{meta['code']}</span>
        </div>
        <div class="fw-card-name">{meta['name']}</div>
    </div>
    <div class="fw-card-footer">
        <span class="adapter-status-tag"><span class="adapter-status-dot"></span> Active LoRA</span>
        <span class="fw-id-tag">{d}</span>
    </div>
</div>""")
    grid_html = f'<div class="fw-kb-grid">{"".join(cards_markup)}</div>'
    st.markdown(grid_html, unsafe_allow_html=True)



def render_user_management_panel():
    """Renders the Admin User Directory & User Management panel."""
    try:
        import auth_manager
    except ImportError:
        try:
            from core import auth_manager
        except ImportError:
            st.error("Auth manager unavailable.")
            return

    users = auth_manager.list_all_users()
    if not users:
        st.info("No registered users found in SQLite database.")
        return

    admin_count = sum(1 for u in users if u["role"] == "admin")
    total_sessions = sum(u.get("sessions_count", 0) for u in users)

    st.markdown(
        f"""
        <div style="background: rgba(30, 41, 59, 0.6); border: 1px solid rgba(148, 163, 184, 0.2); border-radius: 8px; padding: 10px 14px; margin-bottom: 12px;">
            <div style="display: flex; justify-content: space-between; align-items: center; font-size: 0.82rem; color: #cbd5e1; flex-wrap: wrap; gap: 8px;">
                <span>Registered Users: <strong style="color: #60a5fa;">{len(users)}</strong></span>
                <span>Admins: <strong style="color: #f59e0b;">{admin_count}</strong></span>
                <span>Total Sessions: <strong style="color: #34d399;">{total_sessions}</strong></span>
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

    for u in users:
        uname = u["username"]
        role = u["role"]
        email = u.get("email") or "No email provided"
        created_at = (u.get("created_at") or "")[:16].replace("T", " ")
        sessions = u.get("sessions_count", 0)
        messages = u.get("messages_count", 0)

        with st.expander(f"{uname} ({role.upper()})", expanded=False):
            st.markdown(
                f"""
                <div style="font-size: 0.85rem; color: #cbd5e1; line-height: 1.6; margin-bottom: 8px;">
                    <div><strong>Email:</strong> {email}</div>
                    <div><strong>Registered:</strong> {created_at}</div>
                    <div><strong>Activity:</strong> {sessions} chat session(s) | {messages} message(s)</div>
                </div>
                """,
                unsafe_allow_html=True
            )
            
            col1, col2 = st.columns([2, 1])
            with col1:
                curr_idx = ["registered", "admin", "guest"].index(role) if role in ["registered", "admin", "guest"] else 0
                new_role = st.selectbox(
                    "Modify Role",
                    options=["registered", "admin", "guest"],
                    index=curr_idx,
                    key=f"role_sel_{uname}"
                )
                if new_role != role:
                    if st.button(f"Save Role ({uname})", key=f"btn_save_role_{uname}", width="stretch"):
                        ok, msg = auth_manager.update_user_role(uname, new_role)
                        if ok:
                            st.toast(msg)
                            st.rerun()
                        else:
                            st.error(msg)
            with col2:
                if uname.lower() != "admin":
                    with st.popover("🗑️ Delete"):
                        st.warning(f"Delete account **{uname}** and all chat history?")
                        if st.button(f"Confirm Delete ({uname})", key=f"btn_del_{uname}", type="primary", width="stretch"):
                            ok, msg = auth_manager.delete_user_account(uname)
                            if ok:
                                st.toast(msg)
                                st.rerun()
                            else:
                                st.error(msg)
                else:
                    st.caption("🔒 Primary Admin")


def render_mlops_registry_and_active_learning():
    """Renders MLOps Model Registry overview and Active Learning curation controls for Admin."""
    import core.model_registry as model_reg
    import core.feedback_collector as feedback_col
    
    st.markdown(
        """
        <div style="margin-top: 14px; margin-bottom: 8px;">
            <h3 style="margin: 0; font-size: 1.1rem; color: #f8fafc; font-family: 'Outfit', sans-serif;">MLOps & Model Registry</h3>
        </div>
        """,
        unsafe_allow_html=True
    )
    
    with st.expander("**PEFT Model Registry & Lineage**", expanded=False):
        models = model_reg.get_all_registered_models()
        st.caption(f"**Base Model:** `Qwen/Qwen2.5-1.5B-Instruct` | **Active Adapters:** `{len(models)}`")
        
        if models:
            df_models = pd.DataFrame([
                {
                    "Adapter": m["adapter_name"].replace("qwen3-", "").replace("-lora", "").upper(),
                    "Framework": m["framework_slug"],
                    "Rank": f"r={m['lora_rank']}",
                    "Size": f"{m['param_count_mb']} MB",
                    "Score": f"{round(m['evaluation_score'] * 100, 1)}%",
                    "Status": m["status"]
                }
                for m in models
            ])
            st.dataframe(df_models, use_container_width=True, hide_index=True)
        
        if st.button("🔄 Sync On-Disk Adapters", width="stretch", key="sync_adapters_btn"):
            cnt = model_reg.scan_and_register_disk_adapters()
            st.toast(f"Synchronized {cnt} PEFT adapters with Model Registry.")
            st.rerun()

    with st.expander("**Active Learning & Model Alignment (SFT/DPO)**", expanded=False):
        stats = feedback_col.get_feedback_statistics()
        c1, c2 = st.columns(2)
        c1.metric("Auditor Reviews", stats["total_reviews"])
        c2.metric("Approval Rate", f"{stats['approval_rate_pct']}%")
        
        st.caption(f"👍 Positive: `{stats['positive_count']}` | 👎 Needs Correction: `{stats['negative_count']}`")
        
        fw_counts = feedback_col.get_feedback_count_by_framework()
        if fw_counts:
            st.markdown("<div style='margin-top: 8px; font-size: 0.85rem; color: #cbd5e1;'><strong>Per-Framework Alignment Status:</strong></div>", unsafe_allow_html=True)
            for fw, d in fw_counts.items():
                if fw in ("Auto-Detect", "General"):
                    continue
                rems = d.get("with_remediation", 0)
                tot = d.get("total", 0)
                badge = "⚡ DPO Ready" if rems >= 5 else ("🔧 SFT Ready" if tot >= 5 else "⏳ Collecting")
                st.caption(f"• **{fw.upper()}**: Total `{tot}` | Remediations `{rems}` — *{badge}*")

        col_exp1, col_exp2 = st.columns(2)
        with col_exp1:
            if st.button("📥 Export SFT (.jsonl)", width="stretch", key="export_sft_btn"):
                cnt, out_path = feedback_col.export_sft_corrections()
                st.toast(f"Exported {cnt} SFT correction samples.")
        with col_exp2:
            if st.button("🎯 Export DPO (.jsonl)", width="stretch", key="export_dpo_btn"):
                cnt, out_path = feedback_col.export_dpo_pairs()
                st.toast(f"Exported {cnt} DPO preference pairs.")

        if st.button("⚡ Run Continuous Alignment (Agent 10)", type="primary", width="stretch", key="run_alignment_btn"):
            with st.spinner("Analyzing feedback and running alignment pipeline..."):
                try:
                    from agents import agent10_active_learning
                    res = agent10_active_learning.run_continuous_alignment(min_dpo_pairs=3, sft_threshold=5)
                    dpo_cnt = len(res.get("dpo_trained", []))
                    sft_cnt = len(res.get("sft_trained", []))
                    if dpo_cnt > 0 or sft_cnt > 0:
                        st.success(f"Alignment complete: {dpo_cnt} DPO adapters, {sft_cnt} SFT adapters retrained.")
                    else:
                        st.info("Feedback threshold not yet reached for auto-retraining. Log more auditor reviews to trigger.")
                except Exception as e:
                    st.error(f"Alignment run error: {e}")


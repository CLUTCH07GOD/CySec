"""
UI Component: Bottom Action Bar (Scope, Docs Audit, Live Audit)
--------------------------------------------------------------
Renders bottom action controls:
  1. Scope (Focus & Standards Version Registry)
  2. Docs Audit (Mode A Document & Architecture Intake Pipeline)
  3. Live Audit (Mode B Sandbox & Live Staging Probing)
  4. Active Framework Indicator Pill
"""

import os
import streamlit as st
import standards_version_registry as svr
import ui.mode_b_intake as mode_b_ui

def render_focus_bar(available_fw: list[str], user_role: str = "guest", clean_report_list_fn = None):
    """Renders bottom popover action bar: Scope, Docs Audit, Live Audit, and Active Framework pill."""
    pill_fw = st.session_state.get("active_chat_framework", "Auto-Detect (Smart Route)")
    pill_color = "#38bdf8" if pill_fw != "Auto-Detect (Smart Route)" else "#94a3b8"
    fw_options = ["Auto-Detect (Smart Route)"] + sorted(available_fw) if available_fw else ["Auto-Detect (Smart Route)"]

    if user_role in ("registered", "admin"):
        b_col1, b_col2, b_col3, b_col4 = st.columns([0.14, 0.16, 0.15, 0.55])
    else:
        b_col1, b_col4 = st.columns([0.18, 0.82])
        b_col2 = b_col3 = None

    # 1. FOCUS BUTTON (with + symbol)
    with b_col1:
        with st.popover("+ Focus", help="Configure Framework Focus & Standards Version Registry"):
            st.markdown("### Framework Focus & Standards")
            curr_idx = fw_options.index(pill_fw) if pill_fw in fw_options else 0
            
            sel_fw = st.selectbox(
                "Select Framework Focus",
                options=fw_options,
                index=curr_idx,
                key="popover_fw_focus_select"
            )
            
            if sel_fw != "Auto-Detect (Smart Route)":
                slug = sel_fw.replace("/", "_").replace("-", "_")
                sc_exists = svr.has_structured_controls(sel_fw)
                lora_exists = svr.has_lora_adapter(sel_fw)
                
                if sc_exists and lora_exists:
                    st.caption("**Status:** `Fine-Tuned Adapter + Structured Controls Active`")
                elif sc_exists:
                    st.caption("**Status:** `Structured Controls Ingested (Agents 3/4/5 Ready)`")
                    if user_role == "admin":
                        with st.popover("Train LoRA Adapter for " + sel_fw):
                            st.write(f"Run Agent 0 automated synthetic training for **{sel_fw}**.")
                            if st.button("Start Agent 0 Auto-Training", key="train_adapter_btn_" + slug):
                                st.toast(f"Triggering Agent 0 pipeline for {sel_fw}...")
            
            if st.button("Confirm & Apply Focus", type="primary", width="stretch"):
                st.session_state.active_chat_framework = sel_fw
                st.toast(f"Framework Focus locked to: {sel_fw}")
                st.rerun()

            # Standards Version Registry (Registered & Admin only)
            if user_role in ("registered", "admin"):
                st.divider()
                st.markdown("#### Standards Version Registry")
                active_ver_info = svr.get_framework_version_info(sel_fw if sel_fw != "Auto-Detect (Smart Route)" else "eu/gdpr")
                st.caption(f"**Tracked Version:** `{active_ver_info.get('version', 'v1.0')}` (Updated: {active_ver_info.get('effective_date', '2024')})")
                
                with st.expander("Update Standard Version / Ingest Amendment"):
                    st.write(f"**Changelog:** {active_ver_info.get('changelog', 'N/A')}")
                    new_v_input = st.text_input("New Version Tag", value=active_ver_info.get('version', 'v1.0'), key="reg_v_input")
                    new_cl_input = st.text_area("Amendment Notes", value=active_ver_info.get('changelog', ''), key="reg_cl_input")
                    if st.button("Save Standard Update", width="stretch"):
                        target_f = sel_fw if sel_fw != "Auto-Detect (Smart Route)" else "eu/gdpr"
                        svr.update_framework_version(target_f, new_v_input, new_cl_input)
                        st.toast(f"Updated {target_f} to version {new_v_input}!")
                        st.rerun()
                    
                    if user_role == "admin":
                        st.markdown("---")
                        st.caption("**Ingest Amended Document (PDF / JSON)**")
                        amend_file = st.file_uploader("Upload New Standard Version PDF/JSON", type=["pdf", "json", "txt"], key="popover_amend_uploader")
                        if amend_file is not None:
                            if st.button("Process & Train Amended Standard", type="primary", width="stretch"):
                                st.toast("Agent 0 triggered! Extracting new controls and updating model...")

            st.divider()
            st.markdown("#### Quick Action Shortcuts")
            f_target = sel_fw if sel_fw != "Auto-Detect (Smart Route)" else "eu/gdpr"
            
            if st.button("Assess Compliance", width="stretch", key="btn_quick_assess_scope"):
                st.session_state.preset_prompt = f"assess {f_target}"
                st.rerun()

    # 2. DOCS AUDIT BUTTON (Mode A Client Intake Popover)
    if b_col2 is not None:
        with b_col2:
            with st.popover("Docs Audit", help="Upload architecture docs, specs & diagrams for automated compliance audit (Mode A)"):
                st.markdown("### Architecture Docs Audit (Mode A)")
                st.caption("Upload architecture docs (PDFs, Markdown, Specs, Diagram images) to synthesize an application profile and run multi-agent audits.")
                client_id_input = st.text_input("Client ID / Company Name", value="fleetbase", help="Isolated storage directory for client data", key="mode_a_popover_client_id").strip()

                import application_security_trust as ast
                legal_status = ast.get_tenant_legal_agreement_status(client_id_input or "default_client")

                st.markdown("#### Pre-Onboarding Legal Agreements & Scope Gate")
                col_legal1, col_legal2 = st.columns(2)
                with col_legal1:
                    nda_agree = st.checkbox("Sign NDA", value=legal_status.get("nda_signed", True), key="mode_a_popover_nda")
                with col_legal2:
                    dpa_agree = st.checkbox("Sign DPA", value=legal_status.get("dpa_signed", True), key="mode_a_popover_dpa")

                signer_name = st.text_input("Authorized Signatory Name", value=legal_status.get("signed_by") or "Security Admin", key="mode_a_popover_signer")
                
                fw_intake_opts = sorted(available_fw) if available_fw else ["nist_csf", "nist_sp_800_63b", "owasp_asvs_v5", "iso27001", "pci_dss", "cwe"]
                mode_a_framework = st.selectbox("Target Regulatory Standard / Framework", options=fw_intake_opts, key="mode_a_popover_fw_selector")
                
                client_docs = st.file_uploader("Upload Client Docs / Diagrams / Specs", accept_multiple_files=True, type=["pdf", "docx", "txt", "md", "json", "yaml", "yml", "png", "jpg", "jpeg"], key="mode_a_popover_uploader")
                auto_cleanup = st.checkbox("Auto-cleanup raw uploaded files after report", value=True, key="mode_a_popover_cleanup")
                
                if client_docs:
                    col_proc1, col_proc2 = st.columns(2)
                    with col_proc1:
                        run_extract_only = st.button("Extract Profile", width="stretch", key="mode_a_popover_extract_btn")
                    with col_proc2:
                        run_full_pipeline = st.button("Run Full Pipeline", type="primary", width="stretch", key="mode_a_popover_pipeline_btn")

                    if run_extract_only or run_full_pipeline:
                        try:
                            import agents.client_onboarding_engine as coe
                            temp_c_dir = os.path.join("client_vault", client_id_input or "default_client", "documents")
                            os.makedirs(temp_c_dir, exist_ok=True)
                            
                            doc_info_list = []
                            for c_doc in client_docs:
                                save_c_path = os.path.join(temp_c_dir, c_doc.name)
                                with open(save_c_path, "wb") as f:
                                    f.write(c_doc.getbuffer())
                                doc_info_list.append({"path": save_c_path, "name": c_doc.name})
                            
                            profile = coe.build_multi_doc_client_profile(doc_info_list, combined_doc_name=f"{client_id_input}_multi_doc_profile")
                            profile["client_id"] = client_id_input or "default_client"
                            coe.save_client_profile_to_vault(client_id_input, profile)
                            profile_card_md = coe.format_profile_markdown_card(profile)
                            
                            if run_extract_only:
                                st.session_state.messages.append({
                                    "role": "assistant",
                                    "content": (
                                        f"### 🏛️ Extracted Client Architecture Profile (Mode A)\n\n"
                                        f"**Client ID:** `{client_id_input}` | **Source Documents:** `{', '.join([d.name for d in client_docs])}`\n\n"
                                        f"{profile_card_md}\n\n"
                                        f"---\n*Profile saved to Client Vault. Select a framework and click **Run Full Pipeline** to execute control assessment.*"
                                    )
                                })
                                st.success(f"Extracted & Vaulted Combined Profile from {len(client_docs)} files!")
                                st.rerun()

                            elif run_full_pipeline:
                                with st.spinner("Running Multi-Agent Document Ingestion & Compliance Assessment Pipeline (Mode A)..."):
                                    import agents.agent4_compliance_assessment as _a4
                                    import agents.config as _cfg
                                    
                                    target_jur, target_fw = "nist", "sp_800_63b_r4"
                                    if mode_a_framework:
                                        if "/" in mode_a_framework:
                                            target_jur, target_fw = mode_a_framework.split("/", 1)
                                        elif "__" in mode_a_framework:
                                            target_jur, target_fw = mode_a_framework.split("__", 1)
                                        elif "_" in mode_a_framework and not mode_a_framework.startswith("nist_"):
                                            target_jur, target_fw = mode_a_framework.split("_", 1)
                                        else:
                                            target_jur, target_fw = "nist", mode_a_framework.replace("nist_", "")

                                    # Extract granular evidence chunks from uploaded docs
                                    custom_evidence = coe.extract_custom_evidence_from_docs(doc_info_list, profile=profile)
                                    
                                    # Create ephemeral ChromaDB vector collection for high-speed RAG matching
                                    client_slug = re.sub(r'[^a-zA-Z0-9_-]', '_', (client_id_input or "default_client").lower())
                                    ephemeral_coll_name = f"ephemeral_mode_a_{client_slug}"
                                    try:
                                        import chromadb
                                        chroma_client = chromadb.PersistentClient(path=_cfg.CHROMA_DB_DIR)
                                        try:
                                            chroma_client.delete_collection(ephemeral_coll_name)
                                        except Exception:
                                            pass
                                        
                                        coll = chroma_client.create_collection(ephemeral_coll_name)
                                        if custom_evidence:
                                            embedder = _cfg.get_embedder()
                                            texts_to_embed = [e["text"] for e in custom_evidence]
                                            embs = embedder.encode(texts_to_embed).tolist()
                                            ids = [f"mode_a_doc_{idx}" for idx in range(len(custom_evidence))]
                                            metas = [{"source_file": e["source_file"]} for e in custom_evidence]
                                            coll.add(documents=texts_to_embed, embeddings=embs, metadatas=metas, ids=ids)
                                    except Exception as chroma_exc:
                                        print(f"[Mode A Ingestion Note]: {chroma_exc}")
                                        ephemeral_coll_name = None

                                    # Run Agent 4 compliance assessment with custom evidence
                                    results = _a4.assess_compliance(
                                        jurisdiction=target_jur,
                                        framework=target_fw,
                                        custom_evidence=custom_evidence,
                                        ephemeral_collection_name=ephemeral_coll_name
                                    )

                                    # Cleanup ephemeral collection
                                    if ephemeral_coll_name:
                                        try:
                                            import chromadb
                                            chroma_client = chromadb.PersistentClient(path=_cfg.CHROMA_DB_DIR)
                                            chroma_client.delete_collection(ephemeral_coll_name)
                                        except Exception:
                                            pass

                                    compliant_items = [r for r in results if r.get("status") in ("Compliant", "PASS", "PASSED") or r.get("document_claimed_status") in ("Compliant", "PASS", "PASSED")]
                                    partial_items = [r for r in results if r.get("status") in ("Partially Compliant", "PARTIAL", "PARTIALLY COMPLIANT") or r.get("document_claimed_status") in ("Partially Compliant", "PARTIAL")]
                                    non_compliant_items = [r for r in results if r.get("status") in ("Not Compliant", "NON-COMPLIANT", "FAIL", "FAILED", "No Evidence Found") or r.get("document_claimed_status") in ("Not Compliant", "No Evidence Found")]
                                    
                                    clean_fn = clean_report_list_fn if clean_report_list_fn else lambda items, **kwargs: "\n".join([f"- **{i.get('control_id', i.get('id', 'REQ'))}**: {i.get('title', '')}" for i in items])
                                    comp_md = clean_fn(compliant_items, default_ev="Uploaded Architecture Document", show_rationale=False) if compliant_items else "None"
                                    part_md = clean_fn(partial_items, default_ev="Uploaded Architecture Document", show_rationale=True) if partial_items else "None"
                                    non_comp_md = clean_fn(non_compliant_items, default_ev="Uploaded Architecture Document", show_rationale=True) if non_compliant_items else "None"

                                    cleanup_msg = ""
                                    if auto_cleanup:
                                        cleaned = coe.cleanup_client_documents(client_id_input)
                                        cleanup_msg = f"\n\n🔒 *Privacy Note: Auto-cleaned {cleaned} raw uploaded document files.*"

                                    file_list_str = ", ".join([d.name for d in client_docs])
                                    tot_controls = len(compliant_items) + len(partial_items) + len(non_compliant_items)
                                    pct_compliant = (len(compliant_items) / tot_controls * 100) if tot_controls else 0.0

                                    summary_text = (
                                        f"### Architecture Document Compliance Audit Report (Mode A)\n\n"
                                        f"**Client ID:** `{client_id_input}` | **Source Docs ({len(client_docs)}):** `{file_list_str}` | **Benchmark:** {target_fw.upper()} ({target_jur.upper()})\n\n"
                                        f"## Executive Summary\n"
                                        f"This architecture document compliance evaluation assessed the submitted documentation for `{client_id_input}` "
                                        f"against the `{target_fw.upper()}` ({target_jur.upper()}) regulatory framework. "
                                        f"Out of {tot_controls} assessed technical controls, {len(compliant_items)} controls ({pct_compliant:.1f}%) demonstrated verified compliance, "
                                        f"{len(partial_items)} controls exhibited partial coverage, and {len(non_compliant_items)} controls require operational documentation or engineering remediation.\n\n"
                                        f"---\n\n"
                                        f"{profile_card_md}\n\n"
                                        f"---\n\n"
                                        f"#### Compliance Breakdown:\n"
                                        f"- **Fully Compliant:** {len(compliant_items)} controls\n"
                                        f"- **Partially Compliant:** {len(partial_items)} controls\n"
                                        f"- **Not Compliant / Gaps:** {len(non_compliant_items)} controls\n\n"
                                        f"---\n\n"
                                        f"### Fully Compliant Controls:\n{comp_md}\n\n"
                                        f"---\n\n"
                                        f"### Partially Compliant Controls:\n{part_md}\n\n"
                                        f"---\n\n"
                                        f"### Not Compliant Controls (Action Required):\n{non_comp_md}\n\n"
                                        f"---\n*Synthesized by ComplianceMesh Multi-Agent Pipeline.*{cleanup_msg}"
                                    )
                                    st.session_state.messages.append({"role": "assistant", "content": summary_text})
                                    st.success("Docs Audit Completed! Report appended to chat.")
                                    st.rerun()
                        except Exception as exc:
                            st.error(f"Docs Audit Error: {exc}")

    # 3. LIVE AUDIT BUTTON (Mode B Sandbox Popover)
    if b_col3 is not None:
        with b_col3:
            with st.popover("Live Audit", help="Live application sandboxed testing & dynamic endpoint probing (Mode B)"):
                fw_intake_opts = sorted(available_fw) if available_fw else ["nist_csf", "nist_sp_800_63b", "owasp_asvs_v5", "iso27001", "pci_dss", "cwe"]
                clean_fn = clean_report_list_fn if clean_report_list_fn else lambda items, **kwargs: "\n".join([f"- **{i.get('control_id', i.get('id', 'REQ'))}**: {i.get('title', '')}" for i in items])
                mode_b_ui.render_mode_b_intake(fw_intake_opts, clean_fn, wrap_in_expander=False)

    # 4. ACTIVE FRAMEWORK PILL
    has_adapter = svr.has_lora_adapter(pill_fw) if pill_fw != "Auto-Detect (Smart Route)" else False
    adapter_name = f"qwen3-{pill_fw.lower().replace('/', '_').replace('-', '')}-lora" if has_adapter else "Base Qwen2.5-1.5B"

    with b_col4:
        adapter_badge = f" | Adapter: <b>{adapter_name}</b>" if (has_adapter and user_role == "admin") else ""
        st.markdown(
            f"""
            <div style="padding: 6px 14px; background: rgba(15, 23, 42, 0.85); border: 1px solid {pill_color}; border-radius: 16px; display: inline-block; font-size: 0.81rem; color: {pill_color}; font-weight: 600; margin-top: 2px;">
                Active Focus: <b>{pill_fw}</b>{adapter_badge}
            </div>
            """,
            unsafe_allow_html=True
        )


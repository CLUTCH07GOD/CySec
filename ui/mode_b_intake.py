"""
UI Component: Mode B Client Intake & Live Application Sandboxed Audit
---------------------------------------------------------------------
Handles:
  1. Local Sandbox Container Code Inspection (Dockerfile / Manifest Upload).
  2. Scoped Staging Endpoint URL & Token Probing (Agent Z Orchestrator).
  3. Scope Authorization Gate & Hostname Confirmation.
"""

import os
import shutil
import tempfile
import subprocess
from urllib.parse import urlparse
import streamlit as st

def render_mode_b_intake(fw_intake_opts, clean_report_list_fn, wrap_in_expander: bool = False):
    """Renders the Client Intake: Live Application Access & Sandbox (Mode B) UI block."""
    def _render_content():
        st.markdown("### Live Application Access & Sandbox (Mode B)")
        st.caption("Executes untrusted client code / container manifests inside an isolated container sandbox with `--net=none`, strict cgroups & dynamic vulnerability scanning.")
        mode_b_client_id = st.text_input("Mode B Client ID", value="fleetbase_live", key="mode_b_client_id").strip()
        mode_b_framework = st.selectbox("Target Regulatory Standard / Framework for Dynamic Audit Report", options=fw_intake_opts, key="mode_b_fw_selector")
        
        access_grant_method = st.radio(
            "Select Client Access Provisioning Method:",
            [
                "1. Repository Archive / Dockerfile / Code Manifest Upload (Local Sandbox Container Run)",
                "2. Scoped Staging Endpoint URL + Read-Only API Token (Live Endpoint Probing)",
                "3. Direct GitHub / GitLab Remote Repository Audit (Automated API Ingestion)",
                "4. Temporary Cloud IAM Role / Service Account Key (Read-Only Infra Audit)"
            ]
        )

        staging_url_val = ""
        api_token_val = ""
        mode_b_files = None
        git_repo_url = ""
        git_auth_token = ""

        operator_id_val = "security_admin"
        confirm_hostname_typed = ""
        scope_affirm_checked = True

        if "1." in access_grant_method:
            mode_b_files = st.file_uploader("Upload Client App Repository / Manifests / Dockerfile / Specs", accept_multiple_files=True, key="mode_b_uploader")
        elif "2." in access_grant_method:
            staging_url_val = st.text_input("Staging Application URL", value="https://staging-api.fleetbase.io", help="Non-production staging URL")
            api_token_val = st.text_input("Read-Only Test API Token / Bearer Key", type="password")
            
            # Scope Authorization Gate UI Elements (ONLY shown when pasting a URL + token)
            st.markdown("#### 🔒 Target Authorization Gate & Audit Verification")
            col_auth1, col_auth2 = st.columns(2)
            with col_auth1:
                operator_id_val = st.text_input("Auditor / Operator Name", value="security_admin", key="mode_b_operator_id")
            with col_auth2:
                confirm_hostname_typed = st.text_input("Type target hostname to confirm scope authorization", help="Type exact hostname e.g. 127.0.0.1 or staging-api.fleetbase.io", key="mode_b_typed_confirm").strip()
                
            scope_affirm_checked = st.checkbox("I affirm under organizational policy that I am authorized to test this target URL.", value=False, key="mode_b_scope_affirm")
        elif "3." in access_grant_method:
            st.info("🐙 Ingest and audit client repositories directly via GitHub / GitLab API connectors.")
            c_git1, c_git2 = st.columns([0.65, 0.35])
            with c_git1:
                git_repo_url = st.text_input("Repository URL (GitHub / GitLab)", value="https://github.com/org/compliance-target-repo", key="mode_b_git_url")
            with c_git2:
                git_auth_token = st.text_input("Personal Access Token (PAT)", type="password", help="Optional for public repositories; required for private repositories", key="mode_b_git_pat")
        else:
            st.info("🔑 Client provides temporary AWS SecurityAudit IAM Role ARN or GCP Read-Only JSON Key.")
            st.text_input("AWS SecurityAudit Role ARN", value="arn:aws:iam::123456789012:role/ComplianceAuditReadOnlyRole")

        if mode_b_files or staging_url_val or git_repo_url or "4." in access_grant_method:
            if st.button("⚡ Run Agent 0 Sandboxed Dynamic Audit", type="primary", width="stretch", key="btn_run_mode_b_audit"):
                if "1." in access_grant_method:
                    # Option 1: Source Code / Dockerfile / Manifest Upload Sandbox Pipeline
                    try:
                        with st.spinner("🚀 Agent 0 spinning up ephemeral sandbox & running code/manifest security scans..."):
                            import importlib
                            import agents.agent0_mode_b_sandbox as mode_b
                            importlib.reload(mode_b)
                            file_payload = []
                            if mode_b_files:
                                for f in mode_b_files:
                                    file_payload.append({
                                        "name": f.name,
                                        "content": f.getvalue()
                                    })

                            results = mode_b.run_mode_b_pipeline(mode_b_client_id, file_payload)
                            
                            # Run Agent 4 Compliance Assessment & Agent 3 Control Mapping
                            import agents.agent3_control_mapping as _a3
                            import agents.agent4_compliance_assessment as _a4
                            importlib.reload(_a4)
                            importlib.reload(_a3)
                            
                            target_jur, target_fw = "nist", "sp_800_63b_r4"
                            if mode_b_framework:
                                if "/" in mode_b_framework:
                                    target_jur, target_fw = mode_b_framework.split("/", 1)
                                elif "__" in mode_b_framework:
                                    target_jur, target_fw = mode_b_framework.split("__", 1)
                                elif "_" in mode_b_framework and not mode_b_framework.startswith("nist_"):
                                    target_jur, target_fw = mode_b_framework.split("_", 1)
                                else:
                                    target_jur, target_fw = "nist", mode_b_framework.replace("nist_", "")

                            custom_ev = results.get("custom_evidence", [])
                            eph_coll = results.get("ephemeral_collection")
                            comp_results = _a4.assess_compliance(target_jur, target_fw, custom_evidence=custom_ev, ephemeral_collection_name=eph_coll)
                            
                            # Clean up temporary ephemeral vector collection
                            mode_b.cleanup_ephemeral_collection(mode_b_client_id)
                            
                            compliant_items = [r for r in comp_results if r.get("status") in ("Compliant", "PASS", "PASSED") or r.get("document_claimed_status") in ("Compliant", "PASS", "PASSED")]
                            partial_items = [r for r in comp_results if r.get("status") in ("Partially Compliant", "PARTIAL", "PARTIALLY COMPLIANT") or r.get("document_claimed_status") in ("Partially Compliant", "PARTIAL")]
                            non_compliant_items = [r for r in comp_results if r.get("status") in ("Not Compliant", "NON-COMPLIANT", "FAIL", "FAILED", "No Evidence Found") or r.get("document_claimed_status") in ("Not Compliant", "No Evidence Found")]

                            sec_issues = results.get("secret_findings", [])
                            cve_issues = results.get("cve_vulnerabilities", [])
                            live_probes = results.get("live_control_probes", [])

                            sec_md = "\n".join([f"- ⚠️ **[{i['severity']}] {i['type']}** in `{i['file']}`: {i['detail']}" for i in sec_issues]) or "- ✅ No hardcoded credentials detected."
                            cve_md = "\n".join([f"- 🚨 **[{i['severity']}] {i['type']}** in `{i['file']}`: {i['detail']}" for i in cve_issues]) or "- ✅ No manifest vulnerability CVEs detected."
                            live_probes_md = "\n".join([
                                f"- **{p.get('control_id', 'REQ')} — {p.get('control_name', 'Control')}**: [{p.get('status', 'UNTESTED')}]\n  *Test Type:* `{p.get('test_type', 'static')}`\n  *Evidence:* {p.get('evidence', '')}"
                                for p in live_probes
                            ]) or "- None"

                            comp_md = clean_report_list_fn(compliant_items, default_ev="Uploaded Repo Archive", show_rationale=False) if compliant_items else "None"
                            part_md = clean_report_list_fn(partial_items, default_ev="Uploaded Repo Archive", show_rationale=True) if partial_items else "None"
                            non_comp_md = clean_report_list_fn(non_compliant_items, default_ev="Uploaded Repo Archive", show_rationale=True) if non_compliant_items else "None"

                            sandbox_type = results.get("sandbox_type", "Linux Namespace Sandbox")
                            access_scope = results.get("network_egress_status", "DISABLED (--net=none isolated namespace)")

                            report_md = (
                                f"### 🛡️ Agent 0 — Mode B Sandboxed Code Compliance Audit Report\n\n"
                                f"**Client ID:** `{mode_b_client_id}` | **Isolation Sandbox:** `{sandbox_type}`\n"
                                f"**Network Egress Policy:** `{access_scope}` | **Timestamp:** `{results.get('timestamp', '')}`\n\n"
                                f"#### 🔑 Credential & Secret Scanning Findings:\n{sec_md}\n\n"
                                f"---\n\n"
                                f"#### 🛡️ Dependency & CVE Vulnerability Findings:\n{cve_md}\n\n"
                                f"---\n\n"
                                f"#### ⚡ Dynamic Control Inspection Matrix:\n{live_probes_md}\n\n"
                                f"---\n\n"
                                f"#### 📊 Compliance Breakdown ({target_fw.upper()} / {target_jur.upper()}):\n"
                                f"- ✅ Fully Compliant: {len(compliant_items)} controls\n"
                                f"- ⚠️ Partially Compliant: {len(partial_items)} controls\n"
                                f"- ❌ Gaps / Not Compliant: {len(non_compliant_items)} controls\n\n"
                                f"---\n\n"
                                f"### ✅ Fully Compliant Controls:\n{comp_md}\n\n"
                                f"---\n\n"
                                f"### ⚠️ Partially Compliant Controls:\n{part_md}\n\n"
                                f"---\n\n"
                                f"### ❌ Not Compliant Controls (Action Required):\n{non_comp_md}\n"
                            )
                            st.session_state.messages.append({"role": "assistant", "content": report_md})
                            st.success("🎉 Code Inspection Sandbox Audit Completed!")
                            st.rerun()
                    except Exception as exc:
                        st.error(f"Mode B Code Inspection Error: {exc}")

                elif "2." in access_grant_method:
                    # Option 2: Live Staging URL + Token Probing (Agent Z Orchestrator)
                    target_url_to_use = staging_url_val if staging_url_val else os.getenv("VERIFICATION_TARGET_URL", "http://127.0.0.1:8000")
                    expected_host = urlparse(target_url_to_use).netloc or target_url_to_use

                    if not scope_affirm_checked:
                        st.error("⛔ Scope Authorization Gate Blocked: You must check the authorization affirmation box before executing dynamic verification.")
                    elif confirm_hostname_typed.lower() != expected_host.lower():
                        st.error(f"⛔ Scope Authorization Gate Blocked: Typed hostname '{confirm_hostname_typed}' does not match target host '{expected_host}'. Please type '{expected_host}' into the scope confirmation box.")
                    else:
                        try:
                            with st.spinner("🚀 Spinning up Agent Z Orchestrator & running dynamic live audit..."):
                                target_jur, target_fw = "nist", "sp_800_63b_r4"
                                if mode_b_framework:
                                    if "/" in mode_b_framework:
                                        target_jur, target_fw = mode_b_framework.split("/", 1)
                                    elif "__" in mode_b_framework:
                                        target_jur, target_fw = mode_b_framework.split("__", 1)
                                    elif "_" in mode_b_framework and not mode_b_framework.startswith("nist_"):
                                        target_jur, target_fw = mode_b_framework.split("_", 1)
                                    else:
                                        target_jur, target_fw = "nist", mode_b_framework.replace("nist_", "")

                                is_scope_valid = bool(scope_affirm_checked and confirm_hostname_typed.lower() == expected_host.lower())
                                from agents.agent_z_verification_orchestrator import AgentZOrchestrator
                                orchestrator = AgentZOrchestrator(
                                    target_url=target_url_to_use,
                                    api_token=api_token_val,
                                    framework=f"{target_jur}/{target_fw}",
                                    scope_confirmed=is_scope_valid,
                                    operator=operator_id_val or "security_admin"
                                )
                                z_findings = orchestrator.execute_and_normalize()

                            import agents.agent3_control_mapping as _a3
                            import agents.agent4_compliance_assessment as _a4

                            comp_results = _a4.assess_compliance(target_jur, target_fw)
                            compliant_items = [r for r in comp_results if r.get("status") in ("Compliant", "PASS", "PASSED") or r.get("document_claimed_status") in ("Compliant", "PASS", "PASSED")]
                            partial_items = [r for r in comp_results if r.get("status") in ("Partially Compliant", "PARTIAL", "PARTIALLY COMPLIANT") or r.get("document_claimed_status") in ("Partially Compliant", "PARTIAL")]
                            non_compliant_items = [r for r in comp_results if r.get("status") in ("Not Compliant", "NON-COMPLIANT", "FAIL", "FAILED", "No Evidence Found") or r.get("document_claimed_status") in ("Not Compliant", "No Evidence Found")]

                            live_probes_md = "\n".join([
                                f"- **{p.get('control_id')} — {p.get('title')}**: [{p.get('status')}]\n  *Evidence Source:* `{p.get('evidence_source')}`\n  *Evidence Summary:* {p.get('evidence_summary')}"
                                for p in z_findings
                            ]) or "- None"

                            comp_md = clean_report_list_fn(compliant_items, default_ev="Live Sandbox Audit", show_rationale=False) if compliant_items else "None"
                            part_md = clean_report_list_fn(partial_items, default_ev="Live Sandbox Audit", show_rationale=True) if partial_items else "None"
                            non_comp_md = clean_report_list_fn(non_compliant_items, default_ev="Live Sandbox Audit", show_rationale=True) if non_compliant_items else "None"

                            report_md = (
                                f"### 🛡️ Agent Z — Mode B Dynamic Application Compliance Audit Report\n\n"
                                f"**Target URL:** `{target_url_to_use}` | **Auditor Operator:** `{operator_id_val}`\n"
                                f"**Scope Authorization Status:** `VERIFIED & CONFIRMED`\n"
                                f"**Target Framework Benchmark:** {target_fw.upper()} ({target_jur.upper()})\n\n"
                                f"#### ⚡ Live Control-by-Control Application Probing Matrix:\n{live_probes_md}\n\n"
                                f"---\n\n"
                                f"#### 📊 Compliance Summary ({target_fw.upper()} / {target_jur.upper()}):\n"
                                f"- ✅ Fully Compliant: {len(compliant_items)}\n"
                                f"- ⚠️ Partially Compliant: {len(partial_items)}\n"
                                f"- ❌ Gaps / Not Compliant: {len(non_compliant_items)}\n\n"
                                f"### ✅ Fully Compliant Controls:\n{comp_md}\n\n"
                                f"### ⚠️ Partially Compliant Controls:\n{part_md}\n\n"
                                f"### ❌ Not Compliant Controls:\n{non_comp_md}\n"
                            )
                            st.session_state.messages.append({"role": "assistant", "content": report_md})
                            st.success("🎉 Live Staging Endpoint Verification Completed!")
                            st.rerun()
                        except Exception as exc:
                            st.error(f"Mode B Live Probing Error: {exc}")

                elif "3." in access_grant_method:
                    # Option 3: Direct GitHub / GitLab Remote Repository Audit
                    if not git_repo_url or "http" not in git_repo_url:
                        st.error("⛔ Please enter a valid GitHub or GitLab repository URL.")
                    else:
                        try:
                            with st.spinner(f"🚀 Ingesting remote repository from {git_repo_url} via Agent 1b..."):
                                import tempfile
                                import importlib
                                import agents.agent1b_code_ingestion as a1b
                                import agents.agent4_compliance_assessment as _a4
                                importlib.reload(a1b)
                                importlib.reload(_a4)

                                target_jur, target_fw = "nist", "sp_800_63b_r4"
                                if mode_b_framework:
                                    if "/" in mode_b_framework:
                                        target_jur, target_fw = mode_b_framework.split("/", 1)
                                    elif "__" in mode_b_framework:
                                        target_jur, target_fw = mode_b_framework.split("__", 1)
                                    elif "_" in mode_b_framework and not mode_b_framework.startswith("nist_"):
                                        target_jur, target_fw = mode_b_framework.split("_", 1)
                                    else:
                                        target_jur, target_fw = "nist", mode_b_framework.replace("nist_", "")

                                # Sanitize Git URL if copied directly from browser address bar (/tree/main, /blob/main, etc.)
                                clean_git_url = git_repo_url.strip().rstrip("/")
                                for marker in ["/tree/", "/blob/", "/src/"]:
                                    if marker in clean_git_url:
                                        clean_git_url = clean_git_url.split(marker)[0]
                                clean_git_url = clean_git_url.rstrip("/")

                                # Create ephemeral temp dir to clone repo
                                tmp_dir = tempfile.mkdtemp(prefix="git_audit_")
                                clone_url = clean_git_url
                                if git_auth_token and "github.com" in clean_git_url:
                                    clone_url = clean_git_url.replace("https://", f"https://{git_auth_token}@")
                                elif git_auth_token and "gitlab.com" in clean_git_url:
                                    clone_url = clean_git_url.replace("https://", f"https://oauth2:{git_auth_token}@")

                                clone_cmd = ["git", "clone", "--depth", "1", clone_url, tmp_dir]
                                clone_proc = subprocess.run(clone_cmd, capture_output=True, text=True)

                                if clone_proc.returncode != 0:
                                    st.error(f"Failed to clone repository: {clone_proc.stderr}")
                                else:
                                    scan_meta = a1b.scan_repo_structure(tmp_dir)
                                    sec_findings = a1b.run_static_tool_scans(tmp_dir)
                                    extracted_patterns = a1b.extract_config_patterns(tmp_dir)
                                    try:
                                        a1b.process_and_store_findings(mode_b_client_id, sec_findings, extracted_patterns, scan_meta)
                                    except Exception:
                                        pass

                                    # Harvest extracted repository files and structured safeguards
                                    custom_ev = []
                                    for pat in extracted_patterns:
                                        custom_ev.append({
                                            "source_file": f"{pat.get('file_path')}:L{pat.get('line')}",
                                            "text": f"Extracted Security Control [{pat.get('pattern_type')} - {pat.get('cwe_id')}]: {pat.get('description')}\nCode Snippet: {pat.get('snippet')}"
                                        })

                                    valid_exts = {".py", ".js", ".ts", ".jsx", ".tsx", ".php", ".go", ".java", ".rs", ".tf", ".yaml", ".yml", ".json", ".sh", ".dockerfile", ".toml"}
                                    ignored_filenames = {"license", "license.md", "license.txt", "code_of_conduct.md", "code_of_conduct", "pull_request_template.md", "contributing.md", "release.md", "changelog.md", "pnpm-lock.yaml", "package-lock.json", "yarn.lock", "composer.lock", "cargo.lock", "poetry.lock", "gemfile.lock"}
                                    ignored_dir_fragments = {"translations", "locales", "locale", "i18n", "lang", "node_modules", "vendor", ".git", "dist", "build", "coverage", ".next", ".nuxt", "__pycache__"}

                                    for root, _, files in os.walk(tmp_dir):
                                        for f in files:
                                            f_lower = f.lower()
                                            ext = os.path.splitext(f)[1].lower()
                                            is_dockerfile = f_lower in ("dockerfile", "dockerfile.dev", "dockerfile.prod")
                                            is_env = f_lower in (".env.example", ".env.sample", ".env.template", ".env")
                                            is_security_doc = f_lower in ("security.md", "security.txt", "security_policy.md")
                                            
                                            if f_lower in ignored_filenames or ("template" in f_lower and ext == ".md"):
                                                continue

                                            fpath = os.path.join(root, f)
                                            rel_path = os.path.relpath(fpath, tmp_dir)
                                            
                                            parts = set(p.lower() for p in rel_path.split(os.sep))
                                            if parts.intersection(ignored_dir_fragments):
                                                continue

                                            if ext in valid_exts or is_dockerfile or is_env or is_security_doc:
                                                try:
                                                    with open(fpath, "r", encoding="utf-8", errors="ignore") as f_obj:
                                                        content = f_obj.read()
                                                        if content.strip():
                                                            custom_ev.append({
                                                                "source_file": rel_path,
                                                                "text": content[:5000]
                                                            })
                                                except Exception:
                                                    pass

                                    # Ephemeral Vector DB Indexing for Option 3
                                    eph_coll_name = f"ephemeral_evidence_{mode_b_client_id}"
                                    try:
                                        import chromadb
                                        try:
                                            import agents.config as config
                                        except ImportError:
                                            import config
                                        c_client = chromadb.PersistentClient(path=config.CHROMA_DB_DIR)
                                        try:
                                            c_client.delete_collection(eph_coll_name)
                                        except Exception:
                                            pass
                                        if custom_ev:
                                            e_coll = c_client.create_collection(eph_coll_name)
                                            embedder = config.get_embedder()
                                            c_ids = [f"git_ev_{idx+1}" for idx in range(len(custom_ev))]
                                            c_docs = [ev["text"][:1500] for ev in custom_ev]
                                            c_metas = [{"source_file": ev["source_file"], "client_id": mode_b_client_id} for ev in custom_ev]
                                            c_embs = embedder.encode(c_docs).tolist()
                                            e_coll.add(ids=c_ids, documents=c_docs, embeddings=c_embs, metadatas=c_metas)
                                    except Exception as chroma_e:
                                        print(f"[Option 3 Chroma Note]: {chroma_e}")

                                    comp_results = _a4.assess_compliance(target_jur, target_fw, custom_evidence=custom_ev, ephemeral_collection_name=eph_coll_name)
                                    
                                    # Clean up ephemeral vector collection
                                    try:
                                        c_client.delete_collection(eph_coll_name)
                                    except Exception:
                                        pass

                                    compliant_items = [r for r in comp_results if r.get("status") in ("Compliant", "PASS", "PASSED") or r.get("document_claimed_status") in ("Compliant", "PASS", "PASSED")]
                                    partial_items = [r for r in comp_results if r.get("status") in ("Partially Compliant", "PARTIAL", "PARTIALLY COMPLIANT") or r.get("document_claimed_status") in ("Partially Compliant", "PARTIAL")]
                                    non_compliant_items = [r for r in comp_results if r.get("status") in ("Not Compliant", "NON-COMPLIANT", "FAIL", "FAILED", "No Evidence Found") or r.get("document_claimed_status") in ("Not Compliant", "No Evidence Found")]

                                    shutil.rmtree(tmp_dir, ignore_errors=True)

                                    findings_md = "\n".join([
                                        f"- ⚠️ **[{f.get('severity', 'MEDIUM')}] {f.get('finding_id', f.get('cwe_id', 'Finding'))}**: `{f.get('file_path', f.get('file', ''))}`" + (f" (L{f.get('line')})" if f.get('line') else "") + f" — {f.get('description', f.get('message', ''))}"
                                        for f in sec_findings[:8]
                                    ]) or "- ✅ No hardcoded secrets or manifest vulnerabilities identified in initial scan."

                                    comp_md = clean_report_list_fn(compliant_items, default_ev="Git Remote Code Intake", show_rationale=False) if compliant_items else "None"
                                    part_md = clean_report_list_fn(partial_items, default_ev="Git Remote Code Intake", show_rationale=True) if partial_items else "None"
                                    non_comp_md = clean_report_list_fn(non_compliant_items, default_ev="Git Remote Code Intake", show_rationale=True) if non_compliant_items else "None"

                                    report_md = (
                                        f"### 🐙 Remote Repository Automated Compliance Audit Report\n\n"
                                        f"**Repository Target:** `{git_repo_url}` | **Languages Detected:** `{', '.join(scan_meta.get('languages', [])) or 'Multi-stack'}`\n"
                                        f"**Has Dockerfile:** `{scan_meta.get('has_dockerfile')}` | **Has CI/CD Pipeline:** `{scan_meta.get('has_ci')}`\n"
                                        f"**Target Framework Benchmark:** {target_fw.upper()} ({target_jur.upper()})\n\n"
                                        f"#### 🔍 Static Security & Secret Findings:\n{findings_md}\n\n"
                                        f"---\n\n"
                                        f"#### 📊 Compliance Status Matrix ({target_fw.upper()} / {target_jur.upper()}):\n"
                                        f"- ✅ Fully Compliant: {len(compliant_items)}\n"
                                        f"- ⚠️ Partially Compliant: {len(partial_items)}\n"
                                        f"- ❌ Gaps / Not Compliant: {len(non_compliant_items)}\n\n"
                                        f"### ✅ Fully Compliant Controls:\n{comp_md}\n\n"
                                        f"### ⚠️ Partially Compliant Controls:\n{part_md}\n\n"
                                        f"### ❌ Not Compliant Controls:\n{non_comp_md}\n"
                                    )
                                    st.session_state.messages.append({"role": "assistant", "content": report_md})
                                    st.success(f"🎉 Remote Repository Audit for {git_repo_url} Completed!")
                                    st.rerun()
                        except Exception as exc:
                            st.error(f"Remote Git Ingestion Audit Error: {exc}")

    if wrap_in_expander:
        with st.expander("Client Intake: Live Application Access & Sandbox (Mode B)"):
            _render_content()
    else:
        _render_content()

# Graph Report - jupyter_projects  (2026-08-27)

## Corpus Check
- 439 files · ~51,012,962 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 2718 nodes · 3207 edges · 136 communities (125 shown, 11 thin omitted)
- Extraction: 99% EXTRACTED · 1% INFERRED · 0% AMBIGUOUS · INFERRED: 24 edges (avg confidence: 0.86)
- Token cost: 0 input · 0 output

## Community Hubs (Navigation)
- agentic_router.py
- app.py
- AgentYDynamicProbes
- probe_url_with_browser
- agent1_ingestion.py
- conversation_memory_manager.py
- feedback_collector.py
- auth_manager.py
- agent6_data_synthesis.py
- neo4j_utils.py
- remediation_tracker_engine.py
- agent1b_code_ingestion.py
- application_security_trust.py
- agent3_control_mapping.py
- rag_utils.py
- robustness_governance.py
- mcp_server.py
- pipeline_logger.py
- ci_eval_runner.py
- report_exporter.py
- agent5_report_generation.py
- render_focus_bar
- model_registry.py
- ComplianceMesh
- AsyncPipelineManager
- get_system_setting
- TestComplianceCIEvaluation
- agent9_reward_model.py
- ComplianceEngine
- validate_password_nist_800_63b
- client_onboarding_engine.py
- settings_panel.py
- evaluate_rag.py
- governance/standards_version_registry.py
- convert_ciso_libraries.py
- explainability.py
- google_auth.py
- sanitize_control_item
- agent0_live_verification.py
- retry_utils.py
- local_cybersec_verifier.py
- test_structured_controls_validation.py
- email_dispatcher.py
- test_protected_routes_access_control
- test_malformed_input_error_handling
- test_password_policy_nist_800_63b
- test_session_cookie_attributes
- Model Card for Model ID
- Model Card for Model ID
- Model Card for Model ID
- Model Card for Model ID
- Model Card for Model ID
- Model Card for Model ID
- Model Card for Model ID
- Model Card for Model ID
- Model Card for Model ID
- Model Card for Model ID
- Model Card for Model ID
- Model Card for Model ID
- Model Card for Model ID
- Model Card for Model ID
- Model Card for Model ID
- Model Card for Model ID
- Model Card for Model ID
- Model Card for Model ID
- Model Card for Model ID
- Model Card for Model ID
- Model Card for Model ID
- Model Card for Model ID
- Model Card for Model ID
- Model Card for Model ID
- Model Card for Model ID
- Model Card for Model ID
- Model Card for Model ID
- Model Card for Model ID
- Model Card for Model ID
- Model Card for Model ID
- Model Card for Model ID
- Model Card for Model ID
- Model Card for Model ID
- Model Card for Model ID
- Model Card for Model ID
- Model Card for Model ID
- Model Card for Model ID
- Model Card for Model ID
- Model Card for Model ID
- agent4_compliance_assessment.py
- session_state.py
- agent2_knowledge_base.py
- 📋 Industry-Grade Compliance Platform — Master Implementation Task List (Updated)
- AgentZOrchestrator
- 🛡️ Autonomous Multi-Agent Compliance & Cybersecurity Auditing Platform
- AgentXDiscovery
- agent0_master_orchestrator.py
- gemini_verifier.py
- model_loading.py
- 📁 Directory Structure & File Placement Guide
- config.py
- orchestrator.py
- Model Card for qwen3-80063br4-lora
- Model Card for qwen3-asvsv5-lora
- Model Card for qwen3-cloud-lora
- Model Card for qwen3-csf-lora
- Model Card for qwen3-cwev4-lora
- Model Card for qwen3-dpdp-lora
- Model Card for qwen3-gdpr-lora
- Model Card for qwen3-iot-lora
- Model Card for qwen3-iso27001-lora
- Model Card for qwen3-nis2-lora
- Model Card for qwen3-nistairmf-lora
- Model Card for qwen3-wstgv42-lora
- Model Card for qwen3-zerotrust-lora
- {{ report_title }}
- {{ report_title }}
- agent_y_dynamic_probes.py
- Compliance Report — NIST / CSF
- Compliance Report — NIST / CSF
- Compliance Report — NIST / CSF
- evaluate_router.py
- OWASP ASVS v5.0 (Application Security Verification Standard) Reference Document
- test_evaluation_ci.py
- intro_splash.py
- realtime_verifier.py
- NIST SP 800-63B Revision 4 (2025) Reference Document
- rules/graphify.md
- workflows/graphify.md
- test_p_loop_979dbb0d.md
- test_p_loop_out_39c8f356.md
- test_tr_19a14edc.md

## God Nodes (most connected - your core abstractions)
1. `ComplianceMesh` - 25 edges
2. `probe_url_with_browser()` - 22 edges
3. `_finding()` - 18 edges
4. `_get_db_connection()` - 15 edges
5. `Model Card for Model ID` - 15 edges
6. `Model Card for Model ID` - 15 edges
7. `Model Card for Model ID` - 15 edges
8. `Model Card for Model ID` - 15 edges
9. `Model Card for Model ID` - 15 edges
10. `Model Card for Model ID` - 15 edges

## Surprising Connections (you probably didn't know these)
- `node_ingestion_and_indexing()` --calls--> `ingest_single_file()`  [EXTRACTED]
  agentic_router.py → agents/agent1_ingestion.py
- `node_mapping_agent()` --calls--> `map_controls()`  [EXTRACTED]
  agentic_router.py → agents/agent3_control_mapping.py
- `node_assessment_agent()` --calls--> `assess_compliance()`  [EXTRACTED]
  agentic_router.py → agents/agent4_compliance_assessment.py
- `node_assessment_agent()` --calls--> `build_report()`  [EXTRACTED]
  agentic_router.py → agents/agent5_report_generation.py
- `node_live_verification_agent()` --calls--> `AgentXDiscovery`  [EXTRACTED]
  agentic_router.py → agents/agent_x_discovery.py

## Import Cycles
- None detected.

## Communities (136 total, 11 thin omitted)

### Community 0 - "agentic_router.py"
Cohesion: 0.15
Nodes (23): build_master_compliance_graph(), get_initial_state(), MasterAgentState, node_assessment_agent(), node_client_onboarding(), node_general_llm(), node_live_verification_agent(), node_mapping_agent() (+15 more)

### Community 1 - "app.py"
Cohesion: 0.08
Nodes (33): answer_hybrid(), _auto_ingest_on_startup(), _clean_report_list(), detect_intent(), format_framework_display_name(), _format_pointwise_explanation(), _format_pointwise_remediation(), get_country_flag_and_label() (+25 more)

### Community 2 - "AgentYDynamicProbes"
Cohesion: 0.23
Nodes (9): AgentYDynamicProbes, Any, Enforces rate limiting delay and checks if circuit breaker is tripped., Wrapper around requests enforcing rate limits, circuit breaker, and no-redirect…, Loads controls from structured_controls matching self.framework., Category 1: Password Policy Verification., Category 2: Access Control Verification (SPA-aware)., Category 4: Error Handling & Info Leakage Verification. (+1 more)

### Community 3 - "probe_url_with_browser"
Cohesion: 0.08
Nodes (46): _finding(), _handle_check_console_errors(), _handle_check_robots_txt(), _handle_check_security_txt(), _handle_inspect_cookies(), _handle_inspect_cors(), _handle_inspect_forms(), _handle_inspect_headers() (+38 more)

### Community 4 - "agent1_ingestion.py"
Cohesion: 0.13
Nodes (22): compute_file_hash(), discover_documents(), extract_controls_pattern_based(), extract_text(), extract_text_with_confidence(), guess_pattern_key(), ingest_single_file(), main() (+14 more)

### Community 5 - "conversation_memory_manager.py"
Cohesion: 0.11
Nodes (23): calculate_memory_stats(), compress_chat_history(), delete_session(), _ensure_dir(), _init_sqlite_db(), list_sessions(), load_session(), purge_expired_guest_sessions() (+15 more)

### Community 6 - "feedback_collector.py"
Cohesion: 0.09
Nodes (38): get_alignment_status(), main(), Any, Agent 10 — Automated Active Learning & Continuous Alignment Orchestrator…, Summarizes feedback volume and alignment readiness across all compliance…, Executes the continuous alignment pipeline for candidate frameworks., run_continuous_alignment(), collect_dpo_dataset() (+30 more)

### Community 7 - "auth_manager.py"
Cohesion: 0.09
Nodes (37): authenticate_or_register_google_user(), authenticate_user(), delete_user_account(), generate_email_otp(), _get_db_connection(), get_user_profile(), get_user_role(), _hash_password() (+29 more)

### Community 8 - "agent6_data_synthesis.py"
Cohesion: 0.09
Nodes (34): _Cfg, _entry(), _framework_slug(), load_assessments(), load_mappings(), load_structured_controls(), main(), _make_text() (+26 more)

### Community 9 - "neo4j_utils.py"
Cohesion: 0.08
Nodes (31): close_driver(), force_disable(), get_driver(), is_neo4j_available(), Any, Neo4j Graph & Vector Utilities -------------------------------- Handles…, Creates the vector index in Neo4j if it does not already exist. Uses native…, Retrieves top-k relevant document chunks from Neo4j using Vector Search… (+23 more)

### Community 10 - "remediation_tracker_engine.py"
Cohesion: 0.06
Nodes (40): consolidate_multi_framework_assessments(), generate_consolidated_report_markdown(), llm_classify_adapter(), Any, Adapter Classification & Selection Registry…, Automated LLM Classifier: Uses LLM (Qwen) to dynamically infer jurisdiction,…, Scans adapters/ directory and writes or extends metadata.json inside each…, Given a client's detected jurisdiction, industry vertical, application type,… (+32 more)

### Community 11 - "agent1b_code_ingestion.py"
Cohesion: 0.09
Nodes (32): cleanup_ephemeral_collection(), probe_staging_api_endpoint(), Any, Agent 0 — Mode B: Live Application Sandboxed Execution & Dynamic Compliance…, Option 2: Scoped Staging Endpoint Probing. Runs automated HTTP/REST probes…, Executes the untrusted application inside the sandbox environment, runs live…, Spawns a sandboxed ephemeral container execution wrapper with Linux Namespace /…, End-to-End Mode B Automation orchestrated by Agent 0: 1. Creates isolated temp… (+24 more)

### Community 12 - "application_security_trust.py"
Cohesion: 0.11
Nodes (23): execute_gdpr_data_deletion(), get_dynamic_platform_security_posture(), _get_last_audit_hash(), get_tenant_audit_trail(), get_tenant_legal_agreement_status(), get_tenant_vault_dir(), log_security_event(), purge_expired_tenant_data() (+15 more)

### Community 13 - "agent3_control_mapping.py"
Cohesion: 0.23
Nodes (13): classify_similarity(), cosine_sim(), get_adapter_for_framework(), get_controls_for(), llm_confirm_and_explain_mapping(), load_structured_controls_for(), main(), map_controls() (+5 more)

### Community 14 - "rag_utils.py"
Cohesion: 0.10
Nodes (24): build_context_block(), grade_retrieval_quality(), list_available_filters(), rag_answer(), RAG Utilities — Retrieval + Grounded Generation + Self-Healing RAG Engine…, Self-Healing Grader Node: Assesses similarity and quality of retrieved evidence., Self-Healing Query Rewriter Node: Expands abbreviations and regulatory terms., Self-Healing RAG Pipeline (Self-RAG / CRAG): 1. Primary Vector Retrieval 2.… (+16 more)

### Community 15 - "robustness_governance.py"
Cohesion: 0.11
Nodes (17): auto_escalate_critical(), evaluate_hallucination_and_error_rate(), execute_human_sign_off(), get_pending_reviews(), log_adapter_run_lineage(), Any, Robustness & Governance Framework Engine…, Returns all reports currently pending human expert review. (+9 more)

### Community 16 - "mcp_server.py"
Cohesion: 0.12
Nodes (23): extract_tables(), _extract_tables_impl(), extract_text(), _extract_text_impl(), get_metadata(), _get_metadata_impl(), Any, query_compliance() (+15 more)

### Community 17 - "pipeline_logger.py"
Cohesion: 0.12
Nodes (21): clear_logs(), _ensure_dir(), get_recent_logs(), get_stage_summary(), _load_from_disk_if_empty(), log_error(), log_info(), log_stage() (+13 more)

### Community 18 - "ci_eval_runner.py"
Cohesion: 0.15
Nodes (15): calculate_token_overlap(), evaluate_control_recall(), evaluate_faithfulness(), Any, Automated Evaluation CI Runner (Ragas-Style Grounding & EvalOps Suite)…, Computes Jaccard word-level overlap between two strings on CPU., Estimates answer faithfulness / grounding against retrieved context on CPU., Checks citation rate of mandatory standard control tokens. (+7 more)

### Community 19 - "report_exporter.py"
Cohesion: 0.09
Nodes (31): render_agent_details(), export_docx(), export_pdf(), export_report(), extract_audit_findings_matrix(), extract_canonical_control_id(), find_latest_report(), _inline_md() (+23 more)

### Community 20 - "agent5_report_generation.py"
Cohesion: 0.26
Nodes (11): build_report(), generate_consolidated_multi_framework_report(), generate_remediation(), load_all_mappings(), load_assessment(), main(), Agent 5 — Report Generation Agent ------------------------------------- Takes…, Bypassed Verification Gate: Directly returns the generated compliance report… (+3 more)

### Community 21 - "render_focus_bar"
Cohesion: 0.13
Nodes (16): get_framework_version_info(), has_lora_adapter(), has_structured_controls(), Any, Standards Version Registry Module --------------------------------- Tracks…, Checks whether structured control JSON files exist for the given framework., Checks whether a fine-tuned LoRA adapter directory exists for the framework., Retrieves metadata and version information for a given framework standard. (+8 more)

### Community 22 - "model_registry.py"
Cohesion: 0.21
Nodes (15): get_all_registered_models(), _get_db_connection(), get_model_details(), init_registry_db(), Any, Connection, Core Module: Model Registry & Adapter Metadata Engine…, Retrieves all registered models and adapters with full metadata. (+7 more)

### Community 23 - "ComplianceMesh"
Cohesion: 0.04
Nodes (48): 1. Clone and enter the repository, 1. Interactive Compliance Chat & Real-Time Probing, 1. Multi-Modal Evidence Intake, 2. Create and activate a virtual environment, 2. Mode A — Document & Policy Assessment, 2. Multi-Agent Reasoning Pipeline, 3. Domain-Specific LoRA Adapters & MLOps, 3. Install dependencies (+40 more)

### Community 24 - "AsyncPipelineManager"
Cohesion: 0.18
Nodes (8): AsyncPipelineManager, Any, Manages asynchronous query queues, batch jobs, and background workers., Executes a synchronous function in the background worker thread pool and waits…, Submits a background task to the thread pool with tracking., Checks the execution status of a submitted background task., Executes an end-to-end multi-stage pipeline asynchronously: 1. Concurrent…, Future

### Community 25 - "get_system_setting"
Cohesion: 0.21
Nodes (11): Core Module: Decoupled Headless Compliance Engine…, _ensure_settings_file(), get_system_setting(), load_system_settings(), Core Module: Persistent System Settings Manager…, Ensures that the settings JSON file exists., Reads and returns all system settings from disk., Gets a specific global system setting value. (+3 more)

### Community 26 - "TestComplianceCIEvaluation"
Cohesion: 0.13
Nodes (8): Validates Agent 10 continuous alignment status calculation., Validates decoupled compliance engine routing and metadata generation., Validates async pipeline execution and background worker submission., Validates that automated CI benchmark runner achieves >= 80% accuracy and Ragas…, Validates SQLite model registry scanning, versioning, and adapter metrics., Validates auditor feedback capture, statistics, and dataset JSONL export., Validates Agent 9 Reward Model scoring accuracy and refusal penalty., TestComplianceCIEvaluation

### Community 27 - "agent9_reward_model.py"
Cohesion: 0.21
Nodes (13): get_embedder(), main(), Any, rank_candidate_responses(), Agent 9 — Reward Model & Rejection Sampling Scorer (RLHF-Lite)…, Evaluates response quality using reward model components. Returns: {…, Best-of-N rejection sampling ranker. Ranks candidate responses by descending…, Lazy loader for lightweight scoring embedder. (+5 more)

### Community 28 - "ComplianceEngine"
Cohesion: 0.18
Nodes (8): ComplianceEngine, Any, Unified headless engine orchestrating RAG, LoRA routing, and verification., Lazy loader for model weights and embedders., Returns list of registered framework IDs., Routes a compliance query to target framework and intent., Executes an end-to-end compliance query against RAG knowledge base & LoRA…, Verifies whether an answer is grounded in the retrieved compliance context.

### Community 29 - "validate_password_nist_800_63b"
Cohesion: 0.19
Nodes (9): Any, NIST SP 800-63B Revision 4 (2025) Password Policy Validator…, Validates a password against NIST SP 800-63B Revision 4 standards. Returns:…, validate_password_nist_800_63b(), OWASP ASVS v5.0 (V2 Authentication) & NIST SP 800-63B Rev. 4 Local Test Suite…, ASVS V2.1.1 & NIST 800-63B: Verifies password length floor (>= 15 chars single…, NIST 800-63B Rev 4: All-numeric passwords >= 15 chars MUST be accepted (no…, ASVS V2.1.7 & NIST 800-63B: Verifies password is checked against breach… (+1 more)

### Community 30 - "client_onboarding_engine.py"
Cohesion: 0.20
Nodes (11): build_client_application_profile(), build_multi_doc_client_profile(), cleanup_client_documents(), extract_embedded_diagram_text(), Client Onboarding Engine (Mode A: Document & Architecture Diagram Intake)…, Ingests multiple client architecture documents (.md, .pdf, .txt, .png, .jpg),…, Scans a PDF or standalone image file (.png, .jpg, .jpeg) for architecture…, Saves client document, extracted profile, and training data into a dedicated,… (+3 more)

### Community 31 - "settings_panel.py"
Cohesion: 0.21
Nodes (11): UI Component: Sidebar Settings Panel ---------------------------------- Renders…, Renders role-filtered settings panel controls cleanly in the sidebar., Renders glassmorphic cards with live search and category filter controls., Renders glassmorphic cards for registered LoRA adapters., Renders the Admin User Directory & User Management panel., Renders MLOps Model Registry overview and Active Learning curation controls for…, render_active_lora_adapters_cards(), render_ingested_frameworks_kb_cards() (+3 more)

### Community 32 - "evaluate_rag.py"
Cohesion: 0.24
Nodes (10): evaluate_grounding(), evaluate_retrieval(), extract_framework_from_adapter_name(), load_eval_questions(), main(), RAG Evaluation — Retrieval & Generation Quality Assessment…, Evaluates grounding quality by generating answers and checking them. Limited to…, Load held-out questions with their expected framework from train.jsonl. (+2 more)

### Community 33 - "governance/standards_version_registry.py"
Cohesion: 0.29
Nodes (10): get_framework_version_info(), is_assessment_outdated(), load_registry(), Loads the standards version registry from disk or initializes defaults., Persists the registry to JSON disk storage., Gets version info for a specific framework (e.g. 'eu/gdpr')., Updates standard version and logs timestamp for re-running assessments., Checks whether a past assessment was run on an outdated version of the… (+2 more)

### Community 34 - "convert_ciso_libraries.py"
Cohesion: 0.29
Nodes (9): convert_ciso_mapping_yaml(), convert_ciso_yaml_to_controls(), ensure_ciso_lib_available(), main(), Any, CISO Assistant YAML Converter & Cleanup Script…, Converts a CISO Assistant requirement_mapping_sets YAML to cross-framework JSON…, Ensures CISO Assistant library directory is cloned via sparse checkout if… (+1 more)

### Community 35 - "explainability.py"
Cohesion: 0.27
Nodes (9): build_explainability_report(), compute_confidence(), Explainability — RAG Answer Transparency & Confidence Scoring…, Condenses a self-healing trace into a human-readable summary. Returns None if…, Builds a complete explainability report from RAG outputs. Args: query: The…, Computes an overall answer confidence score (0.0 – 1.0) based on: - Average…, Returns a clean list of source summaries for display. Each entry has:…, summarize_sources() (+1 more)

### Community 36 - "google_auth.py"
Cohesion: 0.22
Nodes (8): decode_jwt_payload_unverified(), get_google_auth_redirect_url(), Any, Core Module: Google OAuth 2.0 & Identity Services Integration…, Decodes the JWT payload without signature verification for client-side tokens.…, Renders Google Identity Services (GIS) HTML button and One-Tap prompt. Uses…, Generates standard Google OAuth 2.0 authorization URL for browser redirect., render_google_identity_button()

### Community 37 - "sanitize_control_item"
Cohesion: 0.31
Nodes (8): Any, Report Sanitizer & Post-Processing Module…, Strips LLM conversational chatter, instructions, and prompt leaks., Removes contradictory 'None required.' prefixes/suffixes from non-compliant…, Sanitizes an individual compliance assessment item., sanitize_control_item(), sanitize_remediation(), sanitize_text()

### Community 38 - "agent0_live_verification.py"
Cohesion: 0.46
Nodes (7): load_control_mappings(), log_audit_event(), main(), Any, Agent 0 — Live Application Verification Lane Orchestrator…, run_pytest_protocol_substep(), run_zap_baseline_substep()

### Community 39 - "retry_utils.py"
Cohesion: 0.32
Nodes (7): Exception, flaky_function(), Retry Utilities — Configurable Retry Decorator…, Raise this to indicate a transient failure that should be retried., Decorator that retries a function on specified exceptions. Args: max_retries:…, retry(), RetryableError

### Community 40 - "local_cybersec_verifier.py"
Cohesion: 0.32
Nodes (7): get_base_model_identifier(), load_local_cybersec_verifier(), Verification Module: Local CyberSec-Assistant-3B Verifier…, Returns local model directory if it exists, otherwise Hugging Face model hub id., Loads and caches the Qwen2.5-3B + CyberSec-Assistant-3B model on GPU/CPU., Verifies compliance draft using the local CyberSec-Assistant-3B model. Respects…, verify_and_heal_local()

### Community 41 - "test_structured_controls_validation.py"
Cohesion: 0.40
Nodes (3): parametrize, Test suite to validate ground-truth quality of all JSON files in…, test_structured_controls_schema_and_quality()

### Community 42 - "email_dispatcher.py"
Cohesion: 0.50
Nodes (3): Core Module: Email OTP Dispatcher Service…, Dispatches a 6-digit OTP code to the recipient's email inbox via SMTP. If SMTP…, send_otp_email()

### Community 53 - "Model Card for Model ID"
Cohesion: 0.05
Nodes (37): Bias, Risks, and Limitations, Citation [optional], Compute Infrastructure, Direct Use, Downstream Use [optional], Environmental Impact, Evaluation, Factors (+29 more)

### Community 54 - "Model Card for Model ID"
Cohesion: 0.05
Nodes (37): Bias, Risks, and Limitations, Citation [optional], Compute Infrastructure, Direct Use, Downstream Use [optional], Environmental Impact, Evaluation, Factors (+29 more)

### Community 55 - "Model Card for Model ID"
Cohesion: 0.05
Nodes (37): Bias, Risks, and Limitations, Citation [optional], Compute Infrastructure, Direct Use, Downstream Use [optional], Environmental Impact, Evaluation, Factors (+29 more)

### Community 56 - "Model Card for Model ID"
Cohesion: 0.05
Nodes (37): Bias, Risks, and Limitations, Citation [optional], Compute Infrastructure, Direct Use, Downstream Use [optional], Environmental Impact, Evaluation, Factors (+29 more)

### Community 57 - "Model Card for Model ID"
Cohesion: 0.05
Nodes (37): Bias, Risks, and Limitations, Citation [optional], Compute Infrastructure, Direct Use, Downstream Use [optional], Environmental Impact, Evaluation, Factors (+29 more)

### Community 58 - "Model Card for Model ID"
Cohesion: 0.05
Nodes (37): Bias, Risks, and Limitations, Citation [optional], Compute Infrastructure, Direct Use, Downstream Use [optional], Environmental Impact, Evaluation, Factors (+29 more)

### Community 59 - "Model Card for Model ID"
Cohesion: 0.05
Nodes (37): Bias, Risks, and Limitations, Citation [optional], Compute Infrastructure, Direct Use, Downstream Use [optional], Environmental Impact, Evaluation, Factors (+29 more)

### Community 60 - "Model Card for Model ID"
Cohesion: 0.05
Nodes (37): Bias, Risks, and Limitations, Citation [optional], Compute Infrastructure, Direct Use, Downstream Use [optional], Environmental Impact, Evaluation, Factors (+29 more)

### Community 61 - "Model Card for Model ID"
Cohesion: 0.05
Nodes (37): Bias, Risks, and Limitations, Citation [optional], Compute Infrastructure, Direct Use, Downstream Use [optional], Environmental Impact, Evaluation, Factors (+29 more)

### Community 62 - "Model Card for Model ID"
Cohesion: 0.05
Nodes (37): Bias, Risks, and Limitations, Citation [optional], Compute Infrastructure, Direct Use, Downstream Use [optional], Environmental Impact, Evaluation, Factors (+29 more)

### Community 63 - "Model Card for Model ID"
Cohesion: 0.05
Nodes (37): Bias, Risks, and Limitations, Citation [optional], Compute Infrastructure, Direct Use, Downstream Use [optional], Environmental Impact, Evaluation, Factors (+29 more)

### Community 64 - "Model Card for Model ID"
Cohesion: 0.05
Nodes (37): Bias, Risks, and Limitations, Citation [optional], Compute Infrastructure, Direct Use, Downstream Use [optional], Environmental Impact, Evaluation, Factors (+29 more)

### Community 65 - "Model Card for Model ID"
Cohesion: 0.05
Nodes (37): Bias, Risks, and Limitations, Citation [optional], Compute Infrastructure, Direct Use, Downstream Use [optional], Environmental Impact, Evaluation, Factors (+29 more)

### Community 66 - "Model Card for Model ID"
Cohesion: 0.05
Nodes (37): Bias, Risks, and Limitations, Citation [optional], Compute Infrastructure, Direct Use, Downstream Use [optional], Environmental Impact, Evaluation, Factors (+29 more)

### Community 67 - "Model Card for Model ID"
Cohesion: 0.05
Nodes (37): Bias, Risks, and Limitations, Citation [optional], Compute Infrastructure, Direct Use, Downstream Use [optional], Environmental Impact, Evaluation, Factors (+29 more)

### Community 68 - "Model Card for Model ID"
Cohesion: 0.05
Nodes (37): Bias, Risks, and Limitations, Citation [optional], Compute Infrastructure, Direct Use, Downstream Use [optional], Environmental Impact, Evaluation, Factors (+29 more)

### Community 69 - "Model Card for Model ID"
Cohesion: 0.05
Nodes (37): Bias, Risks, and Limitations, Citation [optional], Compute Infrastructure, Direct Use, Downstream Use [optional], Environmental Impact, Evaluation, Factors (+29 more)

### Community 70 - "Model Card for Model ID"
Cohesion: 0.05
Nodes (37): Bias, Risks, and Limitations, Citation [optional], Compute Infrastructure, Direct Use, Downstream Use [optional], Environmental Impact, Evaluation, Factors (+29 more)

### Community 71 - "Model Card for Model ID"
Cohesion: 0.05
Nodes (37): Bias, Risks, and Limitations, Citation [optional], Compute Infrastructure, Direct Use, Downstream Use [optional], Environmental Impact, Evaluation, Factors (+29 more)

### Community 72 - "Model Card for Model ID"
Cohesion: 0.05
Nodes (37): Bias, Risks, and Limitations, Citation [optional], Compute Infrastructure, Direct Use, Downstream Use [optional], Environmental Impact, Evaluation, Factors (+29 more)

### Community 73 - "Model Card for Model ID"
Cohesion: 0.05
Nodes (37): Bias, Risks, and Limitations, Citation [optional], Compute Infrastructure, Direct Use, Downstream Use [optional], Environmental Impact, Evaluation, Factors (+29 more)

### Community 74 - "Model Card for Model ID"
Cohesion: 0.05
Nodes (37): Bias, Risks, and Limitations, Citation [optional], Compute Infrastructure, Direct Use, Downstream Use [optional], Environmental Impact, Evaluation, Factors (+29 more)

### Community 75 - "Model Card for Model ID"
Cohesion: 0.05
Nodes (37): Bias, Risks, and Limitations, Citation [optional], Compute Infrastructure, Direct Use, Downstream Use [optional], Environmental Impact, Evaluation, Factors (+29 more)

### Community 76 - "Model Card for Model ID"
Cohesion: 0.05
Nodes (37): Bias, Risks, and Limitations, Citation [optional], Compute Infrastructure, Direct Use, Downstream Use [optional], Environmental Impact, Evaluation, Factors (+29 more)

### Community 77 - "Model Card for Model ID"
Cohesion: 0.05
Nodes (37): Bias, Risks, and Limitations, Citation [optional], Compute Infrastructure, Direct Use, Downstream Use [optional], Environmental Impact, Evaluation, Factors (+29 more)

### Community 78 - "Model Card for Model ID"
Cohesion: 0.05
Nodes (37): Bias, Risks, and Limitations, Citation [optional], Compute Infrastructure, Direct Use, Downstream Use [optional], Environmental Impact, Evaluation, Factors (+29 more)

### Community 79 - "Model Card for Model ID"
Cohesion: 0.05
Nodes (37): Bias, Risks, and Limitations, Citation [optional], Compute Infrastructure, Direct Use, Downstream Use [optional], Environmental Impact, Evaluation, Factors (+29 more)

### Community 80 - "Model Card for Model ID"
Cohesion: 0.05
Nodes (37): Bias, Risks, and Limitations, Citation [optional], Compute Infrastructure, Direct Use, Downstream Use [optional], Environmental Impact, Evaluation, Factors (+29 more)

### Community 81 - "Model Card for Model ID"
Cohesion: 0.05
Nodes (37): Bias, Risks, and Limitations, Citation [optional], Compute Infrastructure, Direct Use, Downstream Use [optional], Environmental Impact, Evaluation, Factors (+29 more)

### Community 82 - "Model Card for Model ID"
Cohesion: 0.05
Nodes (37): Bias, Risks, and Limitations, Citation [optional], Compute Infrastructure, Direct Use, Downstream Use [optional], Environmental Impact, Evaluation, Factors (+29 more)

### Community 83 - "Model Card for Model ID"
Cohesion: 0.05
Nodes (37): Bias, Risks, and Limitations, Citation [optional], Compute Infrastructure, Direct Use, Downstream Use [optional], Environmental Impact, Evaluation, Factors (+29 more)

### Community 84 - "Model Card for Model ID"
Cohesion: 0.05
Nodes (37): Bias, Risks, and Limitations, Citation [optional], Compute Infrastructure, Direct Use, Downstream Use [optional], Environmental Impact, Evaluation, Factors (+29 more)

### Community 85 - "Model Card for Model ID"
Cohesion: 0.05
Nodes (37): Bias, Risks, and Limitations, Citation [optional], Compute Infrastructure, Direct Use, Downstream Use [optional], Environmental Impact, Evaluation, Factors (+29 more)

### Community 86 - "Model Card for Model ID"
Cohesion: 0.05
Nodes (37): Bias, Risks, and Limitations, Citation [optional], Compute Infrastructure, Direct Use, Downstream Use [optional], Environmental Impact, Evaluation, Factors (+29 more)

### Community 87 - "Model Card for Model ID"
Cohesion: 0.05
Nodes (37): Bias, Risks, and Limitations, Citation [optional], Compute Infrastructure, Direct Use, Downstream Use [optional], Environmental Impact, Evaluation, Factors (+29 more)

### Community 88 - "Model Card for Model ID"
Cohesion: 0.05
Nodes (37): Bias, Risks, and Limitations, Citation [optional], Compute Infrastructure, Direct Use, Downstream Use [optional], Environmental Impact, Evaluation, Factors (+29 more)

### Community 89 - "Model Card for Model ID"
Cohesion: 0.05
Nodes (37): Bias, Risks, and Limitations, Citation [optional], Compute Infrastructure, Direct Use, Downstream Use [optional], Environmental Impact, Evaluation, Factors (+29 more)

### Community 90 - "Model Card for Model ID"
Cohesion: 0.05
Nodes (37): Bias, Risks, and Limitations, Citation [optional], Compute Infrastructure, Direct Use, Downstream Use [optional], Environmental Impact, Evaluation, Factors (+29 more)

### Community 91 - "Model Card for Model ID"
Cohesion: 0.05
Nodes (37): Bias, Risks, and Limitations, Citation [optional], Compute Infrastructure, Direct Use, Downstream Use [optional], Environmental Impact, Evaluation, Factors (+29 more)

### Community 92 - "agent4_compliance_assessment.py"
Cohesion: 0.18
Nodes (19): assess_compliance(), best_matching_evidence(), clean_title(), cosine_sim(), ensure_complete_sentences(), filter_and_select_best_controls(), generate_no_evidence_explanation(), get_controls_for() (+11 more)

### Community 93 - "session_state.py"
Cohesion: 0.17
Nodes (15): auto_save_current_session(), format_relative_time(), init_session_state(), Core Module: Session State Management --------------------------------------…, Initializes global Streamlit session state defaults if not already present., Isolates chat history and sessions per username when switching accounts or…, Auto-saves the active session messages to SQLite / JSON persistence layer for…, Formats ISO datetime string into human-readable relative time (e.g. '5m ago',… (+7 more)

### Community 94 - "agent2_knowledge_base.py"
Cohesion: 0.20
Nodes (16): node_ingestion_and_indexing(), Agents 1, 1B & 2: Ingests documents/code & builds knowledge base vectors., build_chroma_collection(), build_chroma_mappings_collection(), generate_unique_ids(), load_all_controls(), load_all_mappings(), main() (+8 more)

### Community 95 - "📋 Industry-Grade Compliance Platform — Master Implementation Task List (Updated)"
Cohesion: 0.12
Nodes (16): 10. Automated Remote Git Ingestion *(New Advancement)*, 11. Benchmark S2Score (300–850 Index) & NIST CSF Reporting *(New Advancement)*, 12. 1-Click Multi-Format Export Engine *(New Advancement)*, 13. 100% Sovereign Local GPU Acceleration *(New Advancement)*, 1. Multi-Country / Multi-Framework Compliance Coverage, 2. Client Onboarding — Dual-Mode Intake, 3. Adapter Classification & Selection, 4. Application Security & Trust Posture (+8 more)

### Community 96 - "AgentZOrchestrator"
Cohesion: 0.19
Nodes (7): Agent X: Autonomous Discovery & Fingerprinting Agent Performs Phase 1 discovery…, AgentZOrchestrator, main(), Any, Agent Z: Autonomous Verification Orchestrator & Normalizer Coordinates Agent X…, Returns a safe SHA256 hash digest of the token for audit trails without…, Verifies if tenant has signed required NDA/DPA and Mode B Execution…

### Community 97 - "🛡️ Autonomous Multi-Agent Compliance & Cybersecurity Auditing Platform"
Cohesion: 0.13
Nodes (14): 🚀 1. Ephemeral ChromaDB Vector RAG Engine, 1. Executive Summary, 🛡️ 2. Universal Multi-Language Security AST Extraction, 2. Updated 5-Layer System Architecture, 3. Comprehensive Multi-Agent Fleet Breakdown, 🌐 3. Direct Remote Git Ingestion & URL Auto-Sanitization, 📊 4. Benchmark NIST CSF & S2Score Reporting (300–850 Index), 4. Key Advancements Implemented (Beyond Initial Task List) (+6 more)

### Community 98 - "AgentXDiscovery"
Cohesion: 0.23
Nodes (7): AgentXDiscovery, Any, Phase 4: Static Dockerfile non-root & dependency security hygiene check., Domain Boundary Enforcer: Ensures link stays strictly within authorized target…, Phase 1: OpenAPI / Swagger spec auto-parsing with domain boundary enforcement., Phase 1 & 3: Auto-detect auth, user, and public endpoints using heuristics., Phase 2: Audit response security headers & cookie attributes.

### Community 99 - "agent0_master_orchestrator.py"
Cohesion: 0.22
Nodes (11): main(), Agent 0 — End-to-End Master Automation Orchestrator…, Runs the complete end-to-end automation pipeline. Args: file_path: Path to the…, run_agent0_pipeline(), _slug(), _framework_slug(), get_device(), main() (+3 more)

### Community 100 - "gemini_verifier.py"
Cohesion: 0.24
Nodes (10): call_openrouter_api(), evaluate_and_heal_with_gemini(), Any, Nemotron Self-Healing Evaluator & RAG Ingestion Engine…, Evaluates report draft strictly using Nemotron 3 Ultra. Provides complete…, Upserts Gemini's verified ground-truth answer directly into ChromaDB vector…, Real-Time Processing Interceptor Layer: Evaluates response from local model…, Calls OpenRouter REST API strictly using Nemotron 3 Ultra models. (+2 more)

### Community 101 - "model_loading.py"
Cohesion: 0.28
Nodes (8): get_device(), load_model_and_tokenizer(), load_router(), cache_resource, Core Module: Model Loading & RAG Indexing…, Builds SentenceTransformer embeddings, centroid vectors, and RAG knowledge…, Detects available hardware acceleration device (cuda, mps, or cpu)., Cached loader for base LLM model, tokenizer, and PEFT adapters.

### Community 102 - "📁 Directory Structure & File Placement Guide"
Cohesion: 0.25
Nodes (7): 1. `compliance_standards_docs/nist_sp_800_63b/`, 2. `compliance_standards_docs/owasp_asvs_v5/`, 3. `compliance_standards_docs/owasp_wstg/`, 4. `compliance_standards_docs/cwe_taxonomy/`, Compliance Standards & Verification Guidelines Directory, 📁 Directory Structure & File Placement Guide, ⚡ How Agent 0 Auto-Ingests These Documents

### Community 103 - "config.py"
Cohesion: 0.38
Nodes (6): get_device(), get_langchain_llm(), get_llm(), Shared configuration and model loaders for all 5 agents. Import this instead of…, Returns (model, tokenizer, device). Cached across calls within a process., Wraps the local causal LM in a LangChain HuggingFacePipeline, cached to prevent…

### Community 104 - "orchestrator.py"
Cohesion: 0.38
Nodes (6): main(), Orchestrator — wires Agents 1-5 into a single pipeline.…, Sequential fallback — no LangGraph dependency required., LangGraph-based orchestration — same steps as run_pipeline_plain, expressed as…, run_pipeline_langgraph(), run_pipeline_plain()

### Community 105 - "Model Card for qwen3-80063br4-lora"
Cohesion: 0.33
Nodes (5): Citations, Framework versions, Model Card for qwen3-80063br4-lora, Quick start, Training procedure

### Community 106 - "Model Card for qwen3-asvsv5-lora"
Cohesion: 0.33
Nodes (5): Citations, Framework versions, Model Card for qwen3-asvsv5-lora, Quick start, Training procedure

### Community 107 - "Model Card for qwen3-cloud-lora"
Cohesion: 0.33
Nodes (5): Citations, Framework versions, Model Card for qwen3-cloud-lora, Quick start, Training procedure

### Community 108 - "Model Card for qwen3-csf-lora"
Cohesion: 0.33
Nodes (5): Citations, Framework versions, Model Card for qwen3-csf-lora, Quick start, Training procedure

### Community 109 - "Model Card for qwen3-cwev4-lora"
Cohesion: 0.33
Nodes (5): Citations, Framework versions, Model Card for qwen3-cwev4-lora, Quick start, Training procedure

### Community 110 - "Model Card for qwen3-dpdp-lora"
Cohesion: 0.33
Nodes (5): Citations, Framework versions, Model Card for qwen3-dpdp-lora, Quick start, Training procedure

### Community 111 - "Model Card for qwen3-gdpr-lora"
Cohesion: 0.33
Nodes (5): Citations, Framework versions, Model Card for qwen3-gdpr-lora, Quick start, Training procedure

### Community 112 - "Model Card for qwen3-iot-lora"
Cohesion: 0.33
Nodes (5): Citations, Framework versions, Model Card for qwen3-iot-lora, Quick start, Training procedure

### Community 113 - "Model Card for qwen3-iso27001-lora"
Cohesion: 0.33
Nodes (5): Citations, Framework versions, Model Card for qwen3-iso27001-lora, Quick start, Training procedure

### Community 114 - "Model Card for qwen3-nis2-lora"
Cohesion: 0.33
Nodes (5): Citations, Framework versions, Model Card for qwen3-nis2-lora, Quick start, Training procedure

### Community 115 - "Model Card for qwen3-nistairmf-lora"
Cohesion: 0.33
Nodes (5): Citations, Framework versions, Model Card for qwen3-nistairmf-lora, Quick start, Training procedure

### Community 116 - "Model Card for qwen3-wstgv42-lora"
Cohesion: 0.33
Nodes (5): Citations, Framework versions, Model Card for qwen3-wstgv42-lora, Quick start, Training procedure

### Community 117 - "Model Card for qwen3-zerotrust-lora"
Cohesion: 0.33
Nodes (5): Citations, Framework versions, Model Card for qwen3-zerotrust-lora, Quick start, Training procedure

### Community 118 - "{{ report_title }}"
Cohesion: 0.33
Nodes (5): Actionable Remediation Plan, Compliance Scorecard, Control Assessment & Evidence Matrix, Executive Summary, {{ report_title }}

### Community 119 - "{{ report_title }}"
Cohesion: 0.33
Nodes (5): Actionable Remediation Plan, Compliance Scorecard, Detailed Audit Findings, Executive Summary, {{ report_title }}

### Community 120 - "agent_y_dynamic_probes.py"
Cohesion: 0.40
Nodes (3): is_safe_target_url(), Agent Y: Framework-Guided Dynamic Verification Agent Loads control definitions…, Validates target URL and IP destination against SSRF attacks.

### Community 121 - "Compliance Report — NIST / CSF"
Cohesion: 0.40
Nodes (4): Compliance Report — NIST / CSF, Fully Compliant Controls, Gap Analysis, Summary

### Community 122 - "Compliance Report — NIST / CSF"
Cohesion: 0.40
Nodes (4): Compliance Report — NIST / CSF, Fully Compliant Controls, Gap Analysis, Summary

### Community 123 - "Compliance Report — NIST / CSF"
Cohesion: 0.40
Nodes (4): Compliance Report — NIST / CSF, Fully Compliant Controls, Gap Analysis, Summary

### Community 124 - "evaluate_router.py"
Cohesion: 0.50
Nodes (4): load_questions(), main(), Router Evaluation — Confusion Matrix, Precision/Recall/F1…, Load `count` questions starting at line `start` from a domain's train.jsonl.

### Community 125 - "OWASP ASVS v5.0 (Application Security Verification Standard) Reference Document"
Cohesion: 0.50
Nodes (3): Key Sections:, OWASP ASVS v5.0 (Application Security Verification Standard) Reference Document, Structure & Verification Levels:

### Community 127 - "intro_splash.py"
Cohesion: 0.50
Nodes (3): UI Component: High-Tech Glassmorphic App Intro & Splash Screen…, Renders a sleek high-tech splash screen on initial session launch., render_intro_splash_if_needed()

### Community 128 - "realtime_verifier.py"
Cohesion: 0.50
Nodes (3): Verification Module: Real-Time Ground Truth Interceptor…, Runs real-time factual verification on the LLM response. Supports both…, run_realtime_verification()

## Knowledge Gaps
- **1112 isolated node(s):** `_Cfg`, `graphify`, `Workflow: graphify`, `Comprehensive Final Project Architecture & Engineering Report`, `1. Executive Summary` (+1107 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **11 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `get_system_setting()` connect `get_system_setting` to `app.py`, `ComplianceEngine`, `session_state.py`, `settings_panel.py`?**
  _High betweenness centrality (0.008) - this node is a cross-community bridge._
- **Why does `ComplianceEngine` connect `ComplianceEngine` to `get_system_setting`?**
  _High betweenness centrality (0.007) - this node is a cross-community bridge._
- **Why does `AsyncPipelineManager` connect `AsyncPipelineManager` to `test_evaluation_ci.py`?**
  _High betweenness centrality (0.005) - this node is a cross-community bridge._
- **What connects `_Cfg`, `graphify`, `Workflow: graphify` to the rest of the system?**
  _1112 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `agentic_router.py` be split into smaller, more focused modules?**
  _Cohesion score 0.14855072463768115 - nodes in this community are weakly interconnected._
- **Should `app.py` be split into smaller, more focused modules?**
  _Cohesion score 0.0761904761904762 - nodes in this community are weakly interconnected._
- **Should `probe_url_with_browser` be split into smaller, more focused modules?**
  _Cohesion score 0.07801418439716312 - nodes in this community are weakly interconnected._
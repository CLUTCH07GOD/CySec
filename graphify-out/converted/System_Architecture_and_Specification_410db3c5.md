<!-- converted from System_Architecture_and_Specification.docx -->

System Architecture & Technical Specification
Multi-Domain Compliance & Cybersecurity Assistant Platform
1. Problem Statement
Organisations operating across global jurisdictions face an increasingly complex, fragmented landscape of cybersecurity and data privacy regulations (e.g., EU GDPR, EU NIS2, India DPDP Act 2023, ISO/IEC 27001, NIST CSF 2.0, NIST SP 800 Series). Traditional LLM and manual compliance approaches suffer from four critical challenges:
1. Information Silos & Legal Complexity: Compliance standards are published in dense narrative legal documents (PDFs) spanning hundreds of pages. Cross-referencing control requirements between frameworks requires weeks of manual legal analysis.
2. Model Hallucinations & Out-of-Date Knowledge: Standard Large Language Models (LLMs) hallucinate control requirements, confuse historical directives (e.g. mistaking India's 2023 DPDP Act for the 1995 EU Data Protection Directive), or lack domain precision.
3. Inefficient Monolithic Fine-Tuning: Fine-tuning a single monolithic model across all legal frameworks causes severe catastrophic forgetting, high training costs, and complete retraining requirements whenever a new standard is published.
4. Latency & Execution Bottlenecks: Running heavy multi-agent compliance audits or cross-mappings for simple conversational questions causes unacceptable user latency.
2. Problem Objectives
• Automate End-to-End Standard Lifecycle (Agent 0): Provide a one-click automated pipeline that ingests raw regulatory PDFs, extracts structured security controls, computes cross-framework mappings, synthesizes domain instruction datasets, and fine-tunes domain-specific LoRA adapters without manual code changes.
• Eliminate Model Hallucinations via Dual-Path Routing: Implement an intelligent hybrid routing engine: direct narrow in-domain inquiries to specialized LoRA adapters, while routing general, cross-domain, or full-form queries to a base model operating with model.disable_adapter() over top-retrieved ChromaDB vector snippets.
• Provide Real-Time Multi-Agent Auditing: Execute compliance assessment (Agent 4), cross-framework mapping (Agent 3), and executive report generation (Agent 5) concurrently using thread pools alongside streaming LLM text generation.
• Ensure Scalable Multi-Domain Architecture: Support modular, plug-and-play domain adapters across all major global jurisdictions (eu, india, nist, international, us).
3. Complete Unified Architecture & Workflow
The diagram below demonstrates the complete end-to-end system workflow across all 5 operational layers — from raw PDF upload and offline training data synthesis to online intent routing, dual-path LLM generation, and shared storage.



4. The Technical Solution
A. Modular LoRA Adapter Fine-Tuning (Agent 7)
Instead of retraining the entire base model, lightweight LoRA adapters (rank r=16, alpha=32) are trained independently per framework domain (qwen3-gdpr-lora, qwen3-dpdp-lora, qwen3-iso27001-lora, etc.) on top of Qwen/Qwen2.5-1.5B-Instruct. This reduces storage footprint to ~25MB per domain and eliminates catastrophic forgetting.
B. Dense Centroid Router Engine (SentenceTransformers)
Queries are converted into 384-dimensional dense embeddings using all-MiniLM-L6-v2 and evaluated against domain question centroids using cosine similarity. The router achieves 91% overall classification accuracy across all 8 supported regulatory domains.
C. Dual-Path RAG Generation Engine (answer_hybrid)
To prevent overfit adapter weights from interfering with retrieval-augmented generation, high-confidence in-domain queries route directly to LoRA adapter weights, while general, informational, or comparison questions invoke model.disable_adapter() so the un-biased base model grounds its response directly on top-3 retrieved ChromaDB vector snippets.
D. Master Automation Orchestrator (Agent 0)
A single programmatic master controller (agent0_master_orchestrator.py) automates PDF parsing, vector store chunking, cross-framework mapping, training data synthesis, GPU LoRA fine-tuning, and live dynamic adapter registration.
5. Router Evaluation Metrics & Confusion Matrix
The dense centroid router was quantitatively evaluated across 160 held-out evaluation questions (20 per domain) across all 8 active regulatory adapters. The router achieved an overall classification accuracy of 91.0% and a weighted F1-score of 91.0%.
Confusion Matrix Visualization
The heatmap below illustrates the multi-class domain confusion matrix across all 8 adapters:

6. Future Scopes & Development Roadmap
1. Optical Character Recognition (OCR) Support: Integrate PaddleOCR / Tesseract into Agent 1 for processing scanned image-based regulatory documents.
2. Continuous Delta Analysis: Expand Agent 3 to automatically generate continuous compliance delta reports whenever regulatory authorities publish standard updates.
3. Edge & Air-Gapped Deployment: Quantize LoRA adapters and the base model to 4-bit GGUF / ONNX formats for offline, air-gapped deployment on local edge hardware.
4. Automated Infrastructure Remediation: Extend Agent 5 report output to generate automated Terraform, AWS IAM, and Kubernetes security policy remediation scripts.
| LAYER 1: ENTRY POINT & INGESTION LAYER
• User Natural Language Query (Streamlit Chat UI)
• PDF/TXT Compliance Standard File Upload |
| --- |
| LAYER 2: OFFLINE AUTOMATED PIPELINE (AGENT 0 ORCHESTRATOR)
• Step 1: Agent 1 PDF Ingestion & Regex Control Extraction -> structured_controls/*.json
• Step 2: Vector Store Chunking & Embedding -> ChromaDB (ingest_standards.py)
• Step 3: Agent 3 Cross-Framework Control Mapping -> mappings/*.json
• Step 4: Agent 6 Instruction Dataset Synthesis -> adapters/qwen3-*-lora/train.jsonl
• Step 5: Agent 7 LoRA Adapter Fine-Tuning on Qwen2.5-1.5B-Instruct (PEFT r=16, a=32)
• Step 6: Dynamic Adapter & Centroid Router Registration |
| LAYER 3: ONLINE REAL-TIME ORCHESTRATION & CLASSIFICATION
• Sentence-Transformer Centroid Router (all-MiniLM-L6-v2, 384d Cosine Similarity)
• Intent Classification Engine (detect_intent: list_frameworks | assess | map | report | llm_chat)
• Three Clean Execution Paths:
   - Path A: Ingested Frameworks List -> Instant UI Response
   - Path B: Compliance Audit -> Parallel Agent Thread Pool
   - Path C: Dual-Path LLM Synthesis -> Adapter-only (High Conf) or Base Model + RAG |
| LAYER 4: CONCURRENT COMPLIANCE AGENT POOL (PARALLEL WORKERS)
• Agent 3 (Semantic Control Mapper): Computes inter-standard overlap & equivalence
• Agent 4 (Compliance Assessment): Evaluates evidence against controls (Compliant / Partial / Non-Compliant)
• Agent 5 (Executive Report Generator): Formats executive Markdown reports & remediation plans |
| LAYER 5: SHARED GROUND-TRUTH STORAGE LAYER
• Raw PDF Standards: standards/<jurisdiction>/<framework>/*.pdf
• Structured Controls: structured_controls/<jurisdiction>__<framework>.json
• Cross-Framework Mappings: mappings/*.json
• Vector Database: ChromaDB persistent collection (chroma_db/)
• LoRA Weights: adapters/qwen3-*-lora/adapter_model.safetensors
• Generated Reports: reports/*_report_*.md |
| LAYER 6: CONVERGED USER RESPONSE LAYER
• Real-Time Streaming LLM Token Generation (st.write_stream)
• Expandable Compliance Assessment Dataframes & Downloadable Reports
• Response Length Presets (Short / Medium / Long) & Turn Memory Context |
| Domain Adapter | Precision | Recall | F1-Score | Support |
| --- | --- | --- | --- | --- |
| qwen3-cloud-lora | 0.94 | 0.85 | 0.89 | 20 |
| qwen3-csf-lora | 0.83 | 1.00 | 0.91 | 20 |
| qwen3-dpdp-lora | 0.84 | 0.80 | 0.82 | 20 |
| qwen3-gdpr-lora | 0.83 | 0.95 | 0.88 | 20 |
| qwen3-iot-lora | 0.95 | 0.95 | 0.95 | 20 |
| qwen3-iso27001-lora | 0.95 | 0.95 | 0.95 | 20 |
| qwen3-nis2-lora | 0.94 | 0.80 | 0.86 | 20 |
| qwen3-zerotrust-lora | 1.00 | 0.95 | 0.97 | 20 |
| Overall Accuracy / Macro Avg | 0.91 | 0.91 | 0.91 | 160 |
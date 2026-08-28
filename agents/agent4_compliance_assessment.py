"""
Agent 4 — Compliance Assessment Agent
----------------------------------------
Takes organizational evidence (text files describing what the org actually
does — policies, procedures, system descriptions) and checks it against
each control in a chosen framework, producing a status per control:

    Compliant | Partially Compliant | Not Compliant | No Evidence Found

For each control, the best-matching evidence snippet is retrieved by
embedding similarity, then the LLM judges compliance status given the
control requirement + that evidence.

Evidence files go in: evidence/*.txt (one file per policy/procedure/system
description — plain text, as much detail as you have).

Run with:
    python agents/agent4_compliance_assessment.py --framework nist/csf
"""

import os
import re
import json
import glob
import argparse

import numpy as np
import chromadb
try:
    import agents.config as config
except ImportError:
    import config


def load_evidence(custom_evidence: list[dict] = None) -> list[dict]:
    # When client repository files are provided, audit EXCLUSIVELY against the repository evidence
    if custom_evidence is not None:
        return custom_evidence

    evidence = []
    # Fallback to local evidence directory only if no repository files were uploaded
    if os.path.exists(config.EVIDENCE_DIR):
        for path in sorted(glob.glob(f"{config.EVIDENCE_DIR}/*.txt")):
            with open(path, encoding="utf-8", errors="ignore") as f:
                text = f.read()
            evidence.append({"source_file": os.path.basename(path), "text": text})

    # Check isolated client_vault profiles in real time
    vault_pattern = os.path.join("client_vault", "*", "profiles", "*.json")
    for path in sorted(glob.glob(vault_pattern)):
        try:
            with open(path, encoding="utf-8") as f:
                pdata = json.load(f)
                ev_text = pdata.get("evidence_summary") or json.dumps(pdata)
                c_name = pdata.get("client_id") or os.path.basename(os.path.dirname(os.path.dirname(path)))
                evidence.append({"source_file": f"Client_Vault_{c_name}_{pdata.get('doc_name', 'Doc')}", "text": ev_text})
        except Exception:
            pass

    return evidence


def get_controls_for(collection, jurisdiction: str, framework: str) -> list[dict]:
    results = collection.get(
        where={"$and": [{"jurisdiction": jurisdiction}, {"framework": framework}]},
        include=["documents", "metadatas"],
    )
    return [{**meta, "text": doc} for doc, meta in zip(results["documents"], results["metadatas"])]


def cosine_sim(a, b) -> float:
    a, b = np.array(a), np.array(b)
    return float(np.dot(a, b) / (np.linalg.norm(a) * np.linalg.norm(b)))


PLACEHOLDER_PATTERNS = [
    r"\[INSERT\s+ACTUAL\s+EVIDENCE",
    r"\[INSERT\s+",
    r"\[TODO:",
    r"\[PLACEHOLDER",
    r"REQUIRES ACTUAL.*EVIDENCE",
    r"TEMPLATE\s*[-—]\s*REQUIRES",
]


def is_placeholder_evidence(text: str) -> bool:
    """Detects template/placeholder markers in evidence text to prevent gaming the compliance engine."""
    for pattern in PLACEHOLDER_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            return True
    return False


def best_matching_evidence(embedder, control_text: str, evidence: list[dict]):
    if not evidence:
        return None, 0.0
    # Filter out placeholder/template evidence before matching
    real_evidence = [e for e in evidence if not is_placeholder_evidence(e["text"])]
    if not real_evidence:
        return None, 0.0
    control_emb = embedder.encode([control_text])[0]
    evidence_embs = embedder.encode([e["text"] for e in real_evidence])
    scores = [cosine_sim(control_emb, e_emb) for e_emb in evidence_embs]
    best_idx = int(np.argmax(scores))
    return real_evidence[best_idx], scores[best_idx]


ASSESSMENT_PROMPT = """You are a senior cybersecurity auditor. Evaluate the organizational evidence / code implementation against the control requirement.

CRITICAL ANTI-HALLUCINATION INSTRUCTION:
- Rely strictly on the explicit facts present in the provided Organizational Evidence.
- Do NOT assume, fabricate, or hallucinate safeguards, capabilities, or external legal regulations (e.g. do NOT mention EU AI Act unless explicitly named in the control text).
- Match the exact framework standard named in the Control Requirement. Do NOT swap framework names or invent fictional laws (e.g. UK AI Act).
- Evaluation Criteria:
  * Assign 'Compliant' if the evidence/codebase directly satisfies the technical safeguard requirements.
  * Assign 'Partially Compliant' if the evidence implements core technical safeguards (e.g. password validation, authentication logic, RBAC access controls, session cookie flags, CORS rules, input sanitization, or vulnerability reporting) but requires additional operational documentation or broader policy coverage.
  * Assign 'Not Compliant' only if the evidence lacks relevant technical safeguards or is completely unrelated.

Control Requirement: {control_text}

Organizational Evidence: {evidence_text}

Provide your response in EXACTLY this format:
Status: <Compliant | Partially Compliant | Not Compliant>
Explanation: <3-4 detailed sentences providing a grounded auditor explanation evaluating compliance based strictly on provided evidence.>
Remediation: <1-2 clear, actionable sentences detailing step-by-step guidance for the client to achieve full compliance, or 'None required.' if compliant.>"""

NO_EVIDENCE_PROMPT = """You are a senior cybersecurity auditor. Evaluate the following security control requirement and provide an in-depth auditor assessment explaining why missing evidence creates a compliance gap.

Control ID: {ctrl_id}
Control Title: {ctrl_title}
Control Requirement: {ctrl_text}

Provide your response in EXACTLY this format:
Explanation: <3-4 clear, detailed sentences explaining what technical/security safeguards this control requires, why they are essential for compliance, and how the absence of organizational evidence leaves this control unverified.>
Remediation: <1-2 clear, actionable step-by-step guidance sentences instructing the organization on what policies, configurations, or audit artifacts must be implemented to establish full compliance.>"""


def ensure_complete_sentences(text: str) -> str:
    text = text.strip()
    if not text:
        return text
    # Clean garbled digit-splitting artifacts (e.g. Recital 91\n2\n0\n1 -> Recital 91 2 0 1)
    text = re.sub(r'\n(\d+)\b', r' \1', text)
    if text[-1] in ".!?":
        return text
    last_punct = max(text.rfind('.'), text.rfind('!'), text.rfind('?'))
    if last_punct > 20:
        return text[:last_punct + 1]
    return text + "."


def strip_placeholders(text: str) -> str:
    text = text.strip()
    # Strip LLM instruction leaks
    text = re.sub(r"CRITICAL ANTI-HALLUCINATION INSTRUCTION:?", "", text, flags=re.IGNORECASE)
    text = re.sub(r"CRITICAL CONTROL REQUIREMENT:?", "", text, flags=re.IGNORECASE)
    # Strip matches like: <3-4 clear, detailed sentences...> or <1-2 clear, actionable step-by-step...>
    text = re.sub(r"^<[^>]+>\s*", "", text)
    # Strip any matching bracket instructions like [Insert ...] or (Insert ...)
    text = re.sub(r"^\[[^\]]+\]\s*", "", text)
    text = re.sub(r"^\([^)]+\)\s*", "", text)
    # Clean up any leftover leading tags
    text = re.sub(r"^<[^>]+>\s*", "", text)
    return text.strip()


def generate_no_evidence_explanation(ctrl_id: str, ctrl_title: str, ctrl_text: str) -> dict:
    """Generates a rich, LLM-driven auditor explanation & remediation when no evidence file is provided or matched."""
    try:
        prompt = NO_EVIDENCE_PROMPT.format(ctrl_id=ctrl_id, ctrl_title=ctrl_title, ctrl_text=ctrl_text)
        raw = config.generate(prompt, max_new_tokens=400)

        explanation_match = re.search(r"Explanation:\s*(.+?)(?=Remediation:|$)", raw, re.IGNORECASE | re.DOTALL)
        remediation_match = re.search(r"Remediation:\s*(.+)", raw, re.IGNORECASE | re.DOTALL)

        raw_explanation = explanation_match.group(1).strip() if explanation_match else ""
        raw_remediation = remediation_match.group(1).strip() if remediation_match else ""

        raw_explanation = strip_placeholders(raw_explanation)
        raw_remediation = strip_placeholders(raw_remediation)

        if not raw_explanation or len(raw_explanation) < 30:
            raw_explanation = (
                f"Control safeguard '{ctrl_title}' ({ctrl_id}) mandates verifiable technical safeguards and operational procedures. "
                f"Currently, no organizational evidence was identified matching this requirement with sufficient semantic confidence, "
                f"leaving the control safeguard unverified and exposed to compliance auditing gaps."
            )
        if not raw_remediation or len(raw_remediation) < 15:
            raw_remediation = f"Develop and publish formal operational documentation, security logs, or architectural procedures proving active enforcement of control {ctrl_id} ({ctrl_title})."

        explanation = ensure_complete_sentences(raw_explanation)
        remediation = ensure_complete_sentences(raw_remediation)
        return {"status": "No Evidence Found", "explanation": explanation, "remediation": remediation}
    except Exception:
        return {
            "status": "No Evidence Found",
            "explanation": f"Control safeguard '{ctrl_title}' ({ctrl_id}) mandates verifiable security controls. No matching organizational evidence was found in the vault, leaving the safeguard unverified.",
            "remediation": f"Provide evidence documentation detailing organizational implementation for control {ctrl_id} ({ctrl_title})."
        }


def judge_compliance(control_text: str, evidence_text: str) -> dict:
    prompt = ASSESSMENT_PROMPT.format(control_text=control_text, evidence_text=evidence_text)
    raw = config.generate(prompt, max_new_tokens=450)

    status_match = re.search(r"Status:\s*(Compliant|Partially Compliant|Not Compliant)", raw, re.IGNORECASE)
    explanation_match = re.search(r"Explanation:\s*(.+?)(?=Remediation:|$)", raw, re.IGNORECASE | re.DOTALL)
    remediation_match = re.search(r"Remediation:\s*(.+)", raw, re.IGNORECASE | re.DOTALL)

    status = status_match.group(1) if status_match else "Not Compliant"
    raw_explanation = explanation_match.group(1).strip() if explanation_match else raw.strip()[:600]
    raw_remediation = remediation_match.group(1).strip() if remediation_match else ("None required." if status == "Compliant" else "Implement required control safeguards per standard.")

    raw_explanation = strip_placeholders(raw_explanation)
    raw_remediation = strip_placeholders(raw_remediation)

    # Post-processing: If status is NOT Compliant, strip conflicting 'None required.' sentences
    if status in ["Not Compliant", "Partially Compliant"]:
        raw_remediation = re.sub(r"^None required\.?\s*", "", raw_remediation, flags=re.IGNORECASE)
        raw_remediation = re.sub(r"\s*None required\.?$", "", raw_remediation, flags=re.IGNORECASE)

    explanation = ensure_complete_sentences(raw_explanation)
    remediation = ensure_complete_sentences(raw_remediation)

    import report_sanitizer
    sanitized_rem = report_sanitizer.sanitize_remediation(status, remediation)
    sanitized_exp = report_sanitizer.sanitize_text(explanation)

    return {"status": status, "explanation": sanitized_exp, "remediation": sanitized_rem}


WSTG_TITLE_MAP = {
    # Information Gathering
    "WSTG-INFO-01": "Search Engine Discovery Reconnaissance",
    "WSTG-INFO-02": "Web Server Fingerprinting",
    "WSTG-INFO-03": "Webserver Metafiles Review",
    "WSTG-INFO-04": "Webserver Applications Enumeration",
    "WSTG-INFO-05": "Webpage Content Review for Information Leakage",
    "WSTG-INFO-06": "Identify Application Entry Points",
    "WSTG-INFO-07": "Map Execution Paths",
    "WSTG-INFO-08": "Web Application Framework Fingerprinting",
    "WSTG-INFO-09": "Web Application Fingerprinting",
    "WSTG-INFO-10": "Map Application Architecture",
    # Configuration and Deployment Management
    "WSTG-CONF-01": "Network Infrastructure Configuration Testing",
    "WSTG-CONF-02": "Application Platform Configuration Testing",
    "WSTG-CONF-03": "File Extensions Handling Testing",
    "WSTG-CONF-04": "Review Old Backup and Unreferenced Files",
    "WSTG-CONF-05": "Enumerate Admin Interfaces",
    "WSTG-CONF-06": "Test HTTP Methods",
    "WSTG-CONF-07": "HTTP Strict Transport Security Testing",
    "WSTG-CONF-08": "RIA Cross Domain Policy Testing",
    "WSTG-CONF-09": "File Permission Testing",
    "WSTG-CONF-10": "Subdomain Takeover Testing",
    "WSTG-CONF-11": "Cloud Storage Testing",
    # Identity Management
    "WSTG-IDNT-01": "Role Definitions Testing",
    "WSTG-IDNT-02": "User Registration Process Testing",
    "WSTG-IDNT-03": "Account Provisioning Process Testing",
    "WSTG-IDNT-04": "Account Enumeration and Guessing Testing",
    "WSTG-IDNT-05": "Username Policy Testing",
    # Authentication
    "WSTG-ATHN-01": "Credentials Transport Encryption Testing",
    "WSTG-ATHN-02": "Default Credentials Testing",
    "WSTG-ATHN-03": "Lock Out Mechanism Testing",
    "WSTG-ATHN-04": "Authentication Schema Bypass Testing",
    "WSTG-ATHN-05": "Remember Password Vulnerability Testing",
    "WSTG-ATHN-06": "Browser Cache Weaknesses Testing",
    "WSTG-ATHN-07": "Weak Password Policy Testing",
    "WSTG-ATHN-08": "Weak Security Question/Answer Testing",
    "WSTG-ATHN-09": "Weak Password Reset Testing",
    "WSTG-ATHN-10": "Alternative Channel Authentication Testing",
    # Authorization
    "WSTG-ATHZ-01": "Directory Traversal Testing",
    "WSTG-ATHZ-02": "Authorization Schema Bypass Testing",
    "WSTG-ATHZ-03": "Privilege Escalation Testing",
    "WSTG-ATHZ-04": "Insecure Direct Object References (IDOR) Testing",
    # Session Management
    "WSTG-SESS-01": "Session Management Schema Testing",
    "WSTG-SESS-02": "Cookies Attributes Testing",
    "WSTG-SESS-03": "Session Fixation Testing",
    "WSTG-SESS-04": "Exposed Session Variables Testing",
    "WSTG-SESS-05": "Cross Site Request Forgery (CSRF) Testing",
    "WSTG-SESS-06": "Logout Functionality Testing",
    "WSTG-SESS-07": "Session Timeout Testing",
    "WSTG-SESS-08": "Session Variable Overloading Testing",
    "WSTG-SESS-09": "Session Hijacking Testing",
    # Input Validation
    "WSTG-INPV-01": "Reflected Cross Site Scripting Testing",
    "WSTG-INPV-02": "Stored Cross Site Scripting Testing",
    "WSTG-INPV-03": "HTTP Verb Tampering Testing",
    "WSTG-INPV-04": "HTTP Parameter Pollution Testing",
    "WSTG-INPV-05": "SQL Injection Testing",
    "WSTG-INPV-06": "LDAP Injection Testing",
    "WSTG-INPV-07": "XML Injection Testing",
    "WSTG-INPV-08": "SSI Injection Testing",
    "WSTG-INPV-09": "XPath Injection Testing",
    "WSTG-INPV-10": "IMAP/SMTP Injection Testing",
    "WSTG-INPV-11": "Code Injection Testing",
    "WSTG-INPV-12": "Command Injection Testing",
    "WSTG-INPV-13": "Format String Injection Testing",
    "WSTG-INPV-14": "Incubated Vulnerability Testing",
    "WSTG-INPV-15": "HTTP Splitting/Smuggling Testing",
    "WSTG-INPV-16": "HTTP Incoming Requests Testing",
    "WSTG-INPV-17": "Host Header Injection Testing",
    "WSTG-INPV-18": "Server-side Template Injection Testing",
    "WSTG-INPV-19": "Server-Side Request Forgery (SSRF) Testing",
    # Error Handling
    "WSTG-ERRH-01": "Improper Error Handling Testing",
    "WSTG-ERRH-02": "Stack Traces Testing",
    # Weak Cryptography
    "WSTG-CRYP-01": "Weak TLS/SSL Testing",
    "WSTG-CRYP-02": "Padding Oracle Testing",
    "WSTG-CRYP-03": "Unencrypted Sensitive Data Transmission Testing",
    "WSTG-CRYP-04": "Weak Encryption Algorithms Testing",
    # Business Logic
    "WSTG-BUSL-01": "Business Logic Data Validation Testing",
    "WSTG-BUSL-02": "Forge Requests Capability Testing",
    "WSTG-BUSL-03": "Integrity Checks Testing",
    "WSTG-BUSL-04": "Process Timing Testing",
    "WSTG-BUSL-05": "Function Use Limits Testing",
    "WSTG-BUSL-06": "Work Flows Circumvention Testing",
    "WSTG-BUSL-07": "Defenses Against Application Misuse Testing",
    "WSTG-BUSL-08": "Unexpected File Types Upload Testing",
    "WSTG-BUSL-09": "Malicious Files Upload Testing",
    # Client-side
    "WSTG-CLNT-01": "DOM-Based Cross Site Scripting Testing",
    "WSTG-CLNT-02": "JavaScript Execution Testing",
    "WSTG-CLNT-03": "HTML Injection Testing",
    "WSTG-CLNT-04": "Client-side URL Redirect Testing",
    "WSTG-CLNT-05": "CSS Injection Testing",
    "WSTG-CLNT-06": "Client-side Resource Manipulation Testing",
    "WSTG-CLNT-07": "Cross Site Flashing Testing",
    "WSTG-CLNT-08": "Clickjacking Testing",
    "WSTG-CLNT-09": "WebSockets Testing",
    "WSTG-CLNT-10": "Web Messaging Testing",
    "WSTG-CLNT-11": "Local Storage Testing",
    "WSTG-CLNT-12": "Browser SQL Injection Testing",
    "WSTG-CLNT-13": "Cross Site Script Inclusion (XSSI) Testing",
}


def clean_title(title: str, control_id: str = "") -> str:
    if control_id:
        cid_clean = control_id.strip().upper()
        if cid_clean in WSTG_TITLE_MAP:
            return WSTG_TITLE_MAP[cid_clean]
    if not title:
        return ""
    # Strip raw HTTP header noise or page number / port artifacts
    title = re.sub(r"(Date|Content-Type|Content-Length|ETag|Connection|Server|X-Powered-By):[^\n]*", "", title, flags=re.IGNORECASE)
    title = re.sub(r"Web Security Testing Guide v\d+(\.\d+)?", "", title, flags=re.IGNORECASE)
    # Strip embedded noise keywords at start of title (e.g. Remediation, Summary, :43982)
    title = re.sub(r"^(\d+\.\d+(\.\d+)?|:\d+|Remediation|Summary|Description|Objective|Test\s+Objectives)\s*[-:]?\s*", "", title, flags=re.IGNORECASE)
    title = re.sub(r"^\d+\.\d+(\.\d+)?\s*", "", title)  # strip leftover numbers
    title = re.sub(r"^\s*[-:]\s*", "", title)
    title = re.sub(r"\n+", " ", title)
    title = re.sub(r"\s+", " ", title).strip()
    
    # Clean incomplete trailing single letters or dangling fragments
    title = re.sub(r"[\s,]+[a-zA-Z]{1,2}$", "", title)
    title = title.strip()

    return title if len(title) > 3 else "Control Safeguard Requirement"


def is_valid_control(c: dict) -> bool:
    """Intelligent filter to select meaningful, actionable security controls and discard PDF preamble noise."""
    title = (c.get("title") or "").strip()
    desc = (c.get("description") or "").strip()
    ctrl_id = (c.get("control_id") or "").strip()
    
    # Reject fragment IDs like 0.4, 0.0.4, 0.0.1 which are PDF page/table artifact fragments
    if re.match(r"^0\.\d+(\.\d+)?$", ctrl_id) or ctrl_id.startswith("0.0."):
        return False
        
    # Reject empty or micro titles/descriptions
    if len(title) < 5 and len(desc) < 15:
        return False
        
    # Reject raw PDF page header/footer fragments
    noise_patterns = [
        r"^\d+\s+NIST\s+SP",
        r"Date:\s*",
        r"Content-Type:",
        r"^July\s+\d{4}",
        r"^NIST\s+SP\s+800",
        r"Table of Contents",
        r"Revision\s+\d+",
        r"^\d+$"
    ]
    for pattern in noise_patterns:
        if re.search(pattern, title, re.IGNORECASE):
            return False
            
    # Reject incomplete fragment titles
    if (title.lower().startswith("is ") or title.lower().startswith("the ") or title.lower().startswith("itself ")) and len(desc) < 30:
        return False
            
    return True


def filter_and_select_best_controls(controls: list[dict], max_controls: int = 150) -> list[dict]:
    """Selects the highest quality, non-redundant core controls for evaluation."""
    valid = [c for c in controls if is_valid_control(c)]
    
    # Deduplicate by control_id or title
    seen_ids = set()
    deduped = []
    for c in valid:
        cid = c.get("control_id") or c.get("title")
        if cid and cid not in seen_ids:
            seen_ids.add(cid)
            deduped.append(c)
            
    # Prioritize critical security controls if list is large
    if len(deduped) > max_controls:
        keywords = ["auth", "access", "encrypt", "password", "token", "session", "log", "mfa", "privilege", "key", "tls", "secret", "user", "role", "audit", "storage", "test", "vulnerability"]
        def control_priority(c):
            t = (c.get("title", "") + " " + c.get("description", "")).lower()
            kw_hits = sum(1 for kw in keywords if kw in t)
            return (kw_hits, len(c.get("description", "")))
            
        deduped.sort(key=control_priority, reverse=True)
        return deduped[:max_controls]
        
    return deduped


def assess_compliance(jurisdiction: str, framework: str, evidence_similarity_threshold: float = 0.45, custom_evidence: list[dict] = None, ephemeral_collection_name: str = None) -> list[dict]:
    controls = []
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    structured_dir = os.path.join(project_root, "structured_controls")
    sc_path = os.path.join(structured_dir, f"{jurisdiction}__{framework}.json")
    
    # Smart file resolution for structured_controls
    target_file = None
    if os.path.exists(sc_path):
        target_file = sc_path
    else:
        # Search for matching file in structured_controls directory
        pattern = f"{jurisdiction}__*{framework}*.json"
        candidates = glob.glob(os.path.join(structured_dir, pattern))
        if not candidates:
            # Try searching by framework substring alone
            candidates = glob.glob(os.path.join(structured_dir, f"*{framework}*.json"))
        if candidates:
            target_file = candidates[0]

    if target_file and os.path.exists(target_file):
        try:
            with open(target_file, encoding="utf-8") as f:
                controls = json.load(f)
        except Exception:
            controls = []

    if not controls:
        try:
            import chromadb.api.client
            chromadb.api.client.SharedSystemClient.clear_system_cache()
            client = chromadb.PersistentClient(path=config.CHROMA_DB_DIR)
            collection = client.get_or_create_collection("controls")
            controls = get_controls_for(collection, jurisdiction, framework)
        except Exception as exc:
            print(f"ChromaDB lookup note: {exc}")
            controls = []

    # Apply smart control filtering to select top high-impact security controls
    controls = filter_and_select_best_controls(controls, max_controls=35)

    embedder = config.get_embedder()
    evidence = load_evidence(custom_evidence=custom_evidence)

    if not controls:
        print(f"No controls found for {jurisdiction}/{framework}. Run Agent 1 + Agent 2 first.")
        return []
    if not evidence and not ephemeral_collection_name:
        print(f"No evidence files found in '{config.EVIDENCE_DIR}/'. Add .txt files describing your org's controls.")

    # Connect to Ephemeral Vector Collection in ChromaDB if available
    chroma_coll = None
    if ephemeral_collection_name:
        try:
            import chromadb
            client = chromadb.PersistentClient(path=config.CHROMA_DB_DIR)
            chroma_coll = client.get_collection(ephemeral_collection_name)
        except Exception as coll_exc:
            print(f"[Agent 4 RAG Note]: Could not load ephemeral vector collection: {coll_exc}")
            chroma_coll = None

    effective_threshold = 0.20 if (custom_evidence is not None and evidence_similarity_threshold == 0.45) else evidence_similarity_threshold

    results = []
    for c in controls:
        ctrl_id = c.get("control_id") or "UNKNOWN"
        ctrl_title = clean_title(c.get("title") or "", ctrl_id)
        ctrl_text = c.get("text") or f"{ctrl_id}: {ctrl_title}. {c.get('description', '')}"
        
        # Check if special restrictions/leads exist for this framework & control
        leads_path = os.path.join(project_root, "compliance_leads", f"{jurisdiction}__{framework}_leads.json")
        special_restriction_text = ""
        if os.path.exists(leads_path):
            try:
                with open(leads_path, "r", encoding="utf-8") as lf:
                    leads_data = json.load(lf)
                    matching_lead = next((ld for ld in leads_data if ld.get("control_id") == ctrl_id), None)
                    if matching_lead and matching_lead.get("special_restrictions"):
                        special_restriction_text = " [Mandatory Restriction: " + "; ".join(matching_lead["special_restrictions"]) + "]"
            except Exception:
                pass

        ctrl_text_enriched = ctrl_text + special_restriction_text

        # Check for matching dynamic scan findings targeting this control
        dyn_evidence_file = os.path.join(project_root, "unified_verification_findings.json")
        dyn_findings = []
        if os.path.exists(dyn_evidence_file):
            try:
                with open(dyn_evidence_file, "r", encoding="utf-8") as f:
                    dyn_findings = json.load(f)
            except Exception:
                dyn_findings = []

        # STRICT MATCHING: Find dynamic finding targeting exact control_id
        matching_dyn = [df for df in dyn_findings if df.get("control_id") == ctrl_id]
        tool_verified_status = matching_dyn[0]["status"] if matching_dyn else "NO_DATA"
        tool_verified_source = matching_dyn[0]["evidence_source"] if matching_dyn else None

        # STAGE 1: Fast Vector RAG Retrieval from Ephemeral ChromaDB Collection
        if chroma_coll and chroma_coll.count() > 0:
            try:
                n_res = min(3, chroma_coll.count())
                q_embs = embedder.encode([ctrl_text_enriched]).tolist()
                q_res = chroma_coll.query(
                    query_embeddings=q_embs,
                    n_results=n_res
                )
                if q_res and q_res.get("documents") and q_res["documents"][0]:
                    docs = q_res["documents"][0]
                    metas = q_res["metadatas"][0]
                    distances = q_res.get("distances", [[0.0]])[0] if q_res.get("distances") else [0.0] * len(docs)
                    top_dist = distances[0] if distances else 0.5
                    top_sim = max(0.0, 1.0 - (top_dist / 2.0)) if top_dist > 1.0 else (1.0 - top_dist)
                    
                    if top_sim >= effective_threshold:
                        compound_parts = []
                        source_files = []
                        for d_text, d_meta in zip(docs, metas):
                            sf = d_meta.get("source_file", "unknown")
                            if sf not in source_files:
                                source_files.append(sf)
                            compound_parts.append(f"Source Code: {sf}\nCode Snippet: {d_text}")
                        
                        compound_evidence_text = "\n\n---\n\n".join(compound_parts)
                        match = {
                            "source_file": source_files[0] if len(source_files) == 1 else f"{source_files[0]} (+ {len(source_files)-1} related files)",
                            "text": compound_evidence_text
                        }
                        score = top_sim
                    else:
                        match = None
                        score = top_sim
                else:
                    match = None
                    score = 0.0
            except Exception as rag_err:
                print(f"[Agent 4 RAG Query Note]: {rag_err}")
                match, score = best_matching_evidence(embedder, ctrl_text_enriched, evidence)
        else:
            match, score = best_matching_evidence(embedder, ctrl_text_enriched, evidence)

        evidence_type = "document_claim"
        
        # 1. GROUNDING RULE: If dynamic probe ran and passed/failed/not_applicable, DO NOT allow LLM document speculation to override
        if matching_dyn and tool_verified_status in ["PASS", "FAIL", "NOT_APPLICABLE"]:
            df_item = matching_dyn[0]
            if tool_verified_status == "PASS":
                doc_status = "Compliant"
                doc_remediation = "None required."
            elif tool_verified_status == "NOT_APPLICABLE":
                doc_status = "Not Applicable"
                doc_remediation = "None required."
            else:
                doc_status = "Not Compliant"
                doc_remediation = "Fix vulnerabilities identified in active scan."
            doc_explanation = (
                f"⚡ [Dynamic Scan Verified] Tool '{df_item.get('evidence_source', 'Probe')}' evaluated control requirement {ctrl_id}. "
                f"Status: {tool_verified_status}. Evidence: {df_item.get('evidence_summary', 'Dynamic probe complete.')}"
            )
            doc_source = df_item.get("evidence_source", "Dynamic Scan")
            evidence_type = "dynamic_scan"
        elif match is None or score < effective_threshold:
            # 2. Strict Threshold Rule: If document similarity score < effective_threshold, classify as No Evidence Found instead of over-generalizing
            no_ev = generate_no_evidence_explanation(ctrl_id, ctrl_title, ctrl_text_enriched)
            doc_status = "No Evidence Found"
            doc_explanation = no_ev["explanation"]
            doc_remediation = no_ev["remediation"]
            doc_source = None
            evidence_type = "untested"
        else:
            judged = judge_compliance(ctrl_text_enriched, match["text"])
            doc_status = judged["status"]
            doc_explanation = judged["explanation"]
            doc_remediation = judged["remediation"]
            doc_source = match["source_file"]
            if "Unified_Finding" in str(doc_source):
                evidence_type = "dynamic_scan"

        # Check for Mismatch signal
        is_mismatch = False
        mismatch_note = ""
        if doc_status in ["Compliant", "PASS"] and tool_verified_status == "FAIL":
            is_mismatch = True
            mismatch_note = "⚠️ MISMATCH DETECTED: Document claims compliance, but live dynamic test returned FAIL!"

        import report_sanitizer
        item = {
            "control_id": ctrl_id,
            "title": ctrl_title,
            "status": doc_status,
            "document_claimed_status": doc_status,
            "explanation": doc_explanation,
            "rationale": doc_explanation,
            "remediation": doc_remediation,
            "evidence_source": doc_source or "Vault Profile",
            "evidence_type": evidence_type,
            "tool_verified_status": tool_verified_status,
            "is_mismatch": is_mismatch,
            "mismatch_note": mismatch_note
        }
        results.append(report_sanitizer.sanitize_control_item(item))

    return results


def main():
    parser = argparse.ArgumentParser(description="Agent 4: Compliance Assessment")
    parser.add_argument("--framework", required=True, help="e.g. nist/csf")
    args = parser.parse_args()

    jurisdiction, framework = args.framework.split("/")
    results = assess_compliance(jurisdiction, framework)

    os.makedirs(config.ASSESSMENTS_DIR, exist_ok=True)
    out_path = os.path.join(config.ASSESSMENTS_DIR, f"{jurisdiction}__{framework}_assessment.json")
    with open(out_path, "w") as f:
        json.dump(results, f, indent=2)

    print(f"\nAssessed {len(results)} control(s) -> {out_path}")


if __name__ == "__main__":
    main()

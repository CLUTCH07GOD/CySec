"""
Client Onboarding Engine (Mode A: Document & Architecture Diagram Intake)
-------------------------------------------------------------------------
Handles intake of client-submitted architecture docs, network diagrams,
data flow diagrams, and security policy documents.

Features:
  1. PDF & Text Extraction (plain text + policy parsing)
  2. Diagram Vision / OCR Extraction (extracts text from embedded images, network topology nodes, data flow arrows)
  3. Structured Client Application Profile Schema (stores real client security evidence for Agent 4)
"""

import os
import re
import json
from pypdf import PdfReader

try:
    from PIL import Image
    import pytesseract
    OCR_AVAILABLE = True
except ImportError:
    OCR_AVAILABLE = False


def extract_embedded_diagram_text(doc_path: str) -> list[str]:
    """
    Scans a PDF or standalone image file (.png, .jpg, .jpeg) for architecture diagrams
    and runs OCR / Multimodal Image-to-Text vision processing to extract labels
    from network topology, data flow arrows, and system blocks.
    """
    diagram_texts = []
    if not os.path.exists(doc_path):
        return diagram_texts

    ext = doc_path.lower().rsplit(".", 1)[-1]

    # Handle standalone image files (.png, .jpg, .jpeg)
    if ext in ["png", "jpg", "jpeg"]:
        if OCR_AVAILABLE:
            try:
                image = Image.open(doc_path)
                ocr_txt = pytesseract.image_to_string(image)
                if ocr_txt.strip():
                    diagram_texts.append(f"[Standalone Architecture Diagram OCR ({os.path.basename(doc_path)})]: {ocr_txt.strip()}")
                else:
                    diagram_texts.append(f"[Architecture Diagram ({os.path.basename(doc_path)})]: Processed by Vision Engine")
            except Exception as exc:
                diagram_texts.append(f"[Diagram Vision Notice]: {exc}")
        return diagram_texts

    # Handle PDFs with embedded diagram images
    if ext == "pdf":
        try:
            reader = PdfReader(doc_path)
            for page_idx, page in enumerate(reader.pages):
                for img_obj in page.images:
                    img_bytes = img_obj.data
                    img_name = img_obj.name
                    
                    if OCR_AVAILABLE:
                        import io
                        try:
                            image = Image.open(io.BytesIO(img_bytes))
                            ocr_txt = pytesseract.image_to_string(image)
                            if ocr_txt.strip():
                                diagram_texts.append(f"[Diagram Page {page_idx+1} ({img_name})]: {ocr_txt.strip()}")
                        except Exception:
                            pass
                    else:
                        diagram_texts.append(f"[Diagram Page {page_idx+1} ({img_name}) Detected]")
        except Exception as exc:
            print(f"Diagram extraction notice for {doc_path}: {exc}")

    return diagram_texts


def build_client_application_profile(doc_path: str, doc_name: str = None) -> dict:
    """
    Extracts text and diagram data from a client-submitted architecture or security doc
    and constructs a structured Client Application Profile.
    """
    doc_name = doc_name or os.path.basename(doc_path)
    plain_text = ""

    # 1. Plain Text Extraction
    if doc_path.lower().endswith(".pdf"):
        try:
            reader = PdfReader(doc_path)
            plain_text = "\n".join(page.extract_text() or "" for page in reader.pages)
        except Exception as exc:
            plain_text = f"Error reading PDF: {exc}"
    else:
        try:
            with open(doc_path, "r", encoding="utf-8", errors="ignore") as f:
                plain_text = f.read()
        except Exception:
            plain_text = ""

    # 2. Vision / OCR Extraction for Embedded Architecture Diagrams
    diagram_text_list = extract_embedded_diagram_text(doc_path)
    combined_diagram_text = "\n".join(diagram_text_list)

    combined_corpus = f"{plain_text}\n\n=== EXTRACTED DIAGRAM & TOPOLOGY LABELS ===\n{combined_diagram_text}".lower()

    # 3. Rule-based & Keyword Entity Extraction for Schema
    data_types = []
    if any(w in combined_corpus for w in ["pii", "personal data", "name", "email", "ssn", "passport"]):
        data_types.append("Personal Identifiable Information (PII)")
    if any(w in combined_corpus for w in ["phi", "health", "patient", "medical", "ehr"]):
        data_types.append("Protected Health Information (PHI)")
    if any(w in combined_corpus for w in ["card", "pci", "credit", "cvv", "payment"]):
        data_types.append("Payment Card Data (PCI)")
    if any(w in combined_corpus for w in ["credentials", "password", "hash", "jwt", "token"]):
        data_types.append("User Credentials & Tokens")
    if not data_types:
        data_types.append("General Business & System Data")

    storage_locations = []
    if "aws" in combined_corpus or "s3" in combined_corpus:
        storage_locations.append("AWS Cloud (us-east-1 / S3 / RDS)")
    if "azure" in combined_corpus or "blob" in combined_corpus:
        storage_locations.append("Azure Cloud Blob / SQL")
    if "gcp" in combined_corpus or "bigquery" in combined_corpus:
        storage_locations.append("Google Cloud Platform (GCP)")
    if "postgres" in combined_corpus or "mysql" in combined_corpus or "database" in combined_corpus:
        storage_locations.append("Relational Database (PostgreSQL/MySQL)")
    if not storage_locations:
        storage_locations.append("On-Premises / Hybrid Data Center")

    implemented_controls = []
    if any(w in combined_corpus for w in ["aes", "aes-256", "at rest", "encrypted"]):
        implemented_controls.append("AES-256 Data Encryption at Rest")
    if any(w in combined_corpus for w in ["tls", "ssl", "https", "tls 1.3", "in transit"]):
        implemented_controls.append("TLS 1.3 Encryption in Transit")
    if any(w in combined_corpus for w in ["mfa", "multi-factor", "2fa", "sso", "oauth"]):
        implemented_controls.append("Multi-Factor Authentication (MFA) & OAuth2")
    if any(w in combined_corpus for w in ["log", "180 days", "audit", "syslog", "siem"]):
        implemented_controls.append("System Audit Logging & Retention (180+ Days)")
    if any(w in combined_corpus for w in ["backup", "disaster", "failover", "replica"]):
        implemented_controls.append("Automated Daily Backups & Disaster Recovery")

    third_parties = []
    for tp in ["stripe", "auth0", "datadog", "cloudflare", "okta", "twilio", "aws", "azure"]:
        if tp in combined_corpus:
            third_parties.append(tp.capitalize())

    # 4. Construct Real Structured Evidence Summary for Agent 4
    evidence_summary = (
        f"Real Client Architecture Profile ({doc_name}):\n"
        f"- Data Types: {', '.join(data_types)}\n"
        f"- Storage Locations: {', '.join(storage_locations)}\n"
        f"- Implemented Controls: {', '.join(implemented_controls)}\n"
        f"- Third-Party Services: {', '.join(third_parties) if third_parties else 'None'}\n"
        f"- Full Document & Diagram Summary: {plain_text[:800]}..."
    )

    profile = {
        "doc_name": doc_name,
        "data_types": data_types,
        "storage_locations": storage_locations,
        "implemented_controls": implemented_controls,
        "third_party_integrations": third_parties,
        "extracted_diagram_labels": diagram_text_list,
        "evidence_summary": evidence_summary,
        "raw_text_snippet": plain_text[:2000]
    }

    return profile


def build_multi_doc_client_profile(doc_info_list: list[dict], combined_doc_name: str = "multi_doc_architecture_profile") -> dict:
    """
    Ingests multiple client architecture documents (.md, .pdf, .txt, .png, .jpg),
    aggregates extracted text and diagram labels, and constructs a unified Client Profile.
    doc_info_list item format: {"path": str, "name": str}
    """
    all_texts = []
    all_diagram_labels = []
    file_names = []

    for item in doc_info_list:
        path = item["path"]
        name = item.get("name", os.path.basename(path))
        file_names.append(name)
        
        # Text extraction
        if path.lower().endswith(".pdf"):
            try:
                reader = PdfReader(path)
                txt = "\n".join(page.extract_text() or "" for page in reader.pages)
            except Exception:
                txt = ""
        else:
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    txt = f.read()
            except Exception:
                txt = ""
        
        all_texts.append(f"=== DOCUMENT: {name} ===\n{txt}")
        
        # Diagram OCR
        d_labels = extract_embedded_diagram_text(path)
        all_diagram_labels.extend(d_labels)

    combined_plain_text = "\n\n".join(all_texts)
    combined_diagram_text = "\n".join(all_diagram_labels)
    combined_corpus = f"{combined_plain_text}\n\n=== EXTRACTED DIAGRAM & TOPOLOGY LABELS ===\n{combined_diagram_text}".lower()

    # LLM-based Extraction Pass
    try:
        from . import config
    except ImportError:
        import config

    llm_prompt = (
        f"You are a Senior Security Auditor reviewing client architecture documents.\n\n"
        f"Document Content Snippet:\n{combined_plain_text[:2000]}\n\n"
        f"Extracted Diagram Labels:\n{combined_diagram_text[:500]}\n\n"
        f"Extract structured security profile data in JSON format with keys:\n"
        f"\"data_types\": [list of data types handled (e.g. PII, PHI, PCI, User Credentials)],\n"
        f"\"storage_locations\": [list of databases and cloud platforms (e.g. AWS S3, Azure, PostgreSQL, Redis)],\n"
        f"\"implemented_controls\": [list of security controls present (e.g. AES-256, TLS 1.3, MFA, Audit Logging)],\n"
        f"\"third_party_integrations\": [list of third-party SaaS/vendor tools (e.g. Stripe, Auth0, Cloudflare)]\n"
        f"Reply ONLY with the raw JSON object."
    )

    llm_res = config.generate(llm_prompt, max_new_tokens=300)
    data_types, storage_locations, implemented_controls, third_parties = [], [], [], []

    try:
        import json
        json_match = re.search(r"\{.*\}", llm_res, re.DOTALL)
        if json_match:
            parsed = json.loads(json_match.group(0))
            data_types = parsed.get("data_types", [])
            storage_locations = parsed.get("storage_locations", [])
            implemented_controls = parsed.get("implemented_controls", [])
            third_parties = parsed.get("third_party_integrations", [])
    except Exception:
        pass

    # Fallback to corpus scanning if LLM extraction returned empty
    if not data_types:
        if any(w in combined_corpus for w in ["pii", "personal data", "name", "email", "ssn", "passport"]):
            data_types.append("Personal Identifiable Information (PII)")
        if any(w in combined_corpus for w in ["phi", "health", "patient", "medical", "ehr"]):
            data_types.append("Protected Health Information (PHI)")
        if any(w in combined_corpus for w in ["card", "pci", "credit", "cvv", "payment"]):
            data_types.append("Payment Card Data (PCI)")
        if any(w in combined_corpus for w in ["credentials", "password", "hash", "jwt", "token"]):
            data_types.append("User Credentials & Tokens")
        if not data_types:
            data_types.append("General Business & System Data")

    if not storage_locations:
        if "aws" in combined_corpus or "s3" in combined_corpus:
            storage_locations.append("AWS Cloud (us-east-1 / S3 / RDS)")
        if "azure" in combined_corpus or "blob" in combined_corpus:
            storage_locations.append("Azure Cloud Blob / SQL")
        if "gcp" in combined_corpus or "bigquery" in combined_corpus:
            storage_locations.append("Google Cloud Platform (GCP)")
        if "postgresql" in combined_corpus or "postgres" in combined_corpus:
            storage_locations.append("PostgreSQL Database")
        if "redis" in combined_corpus:
            storage_locations.append("Redis In-Memory Data Store")
        if not storage_locations:
            storage_locations.append("On-Premises / Internal Data Center")

    if not implemented_controls:
        if any(w in combined_corpus for w in ["aes-256", "aes256", "at rest"]):
            implemented_controls.append("AES-256 Encryption at Rest")
        if any(w in combined_corpus for w in ["tls 1.3", "tls1.3", "https", "ssl"]):
            implemented_controls.append("TLS 1.3 Encryption in Transit")
        if any(w in combined_corpus for w in ["mfa", "multi-factor", "2fa", "sso", "oauth"]):
            implemented_controls.append("Multi-Factor Authentication (MFA) & OAuth2")
        if any(w in combined_corpus for w in ["log", "180 days", "audit", "syslog", "siem"]):
            implemented_controls.append("System Audit Logging & Retention (180+ Days)")
        if any(w in combined_corpus for w in ["backup", "disaster", "failover", "replica"]):
            implemented_controls.append("Automated Daily Backups & Disaster Recovery")

    if not third_parties:
        for tp in ["stripe", "auth0", "datadog", "cloudflare", "okta", "twilio", "aws", "azure"]:
            if tp in combined_corpus:
                third_parties.append(tp.capitalize())

    evidence_summary = (
        f"Multi-Document Client Architecture Profile ({len(file_names)} Files: {', '.join(file_names)}):\n"
        f"- Data Types: {', '.join(data_types)}\n"
        f"- Storage Locations: {', '.join(storage_locations)}\n"
        f"- Implemented Controls: {', '.join(implemented_controls)}\n"
        f"- Third-Party Services: {', '.join(third_parties) if third_parties else 'None'}\n"
        f"- Full Multi-Doc Summary: {combined_plain_text[:1500]}..."
    )

    profile = {
        "doc_name": combined_doc_name,
        "source_files": file_names,
        "data_types": data_types,
        "storage_locations": storage_locations,
        "implemented_controls": implemented_controls,
        "third_party_integrations": third_parties,
        "extracted_diagram_labels": all_diagram_labels,
        "evidence_summary": evidence_summary,
        "raw_text_snippet": combined_plain_text[:3000]
    }

    return profile


CLIENT_VAULT_DIR = "client_vault"


def save_client_profile_to_vault(client_id: str, profile: dict, raw_file_bytes: bytes = None, filename: str = None) -> dict:
    """
    Saves client document, extracted profile, and training data into a dedicated,
    isolated client vault directory (`client_vault/<client_id>/`).
    """
    client_slug = re.sub(r'[^a-zA-Z0-9_-]', '_', client_id.lower().strip()) if client_id else "default_client"
    client_dir = os.path.join(CLIENT_VAULT_DIR, client_slug)
    
    docs_dir = os.path.join(client_dir, "documents")
    profiles_dir = os.path.join(client_dir, "profiles")
    adapters_dir = os.path.join(client_dir, "adapters")
    
    os.makedirs(docs_dir, exist_ok=True)
    os.makedirs(profiles_dir, exist_ok=True)
    os.makedirs(adapters_dir, exist_ok=True)

    if raw_file_bytes and filename:
        raw_path = os.path.join(docs_dir, filename)
        with open(raw_path, "wb") as f:
            f.write(raw_file_bytes)

    prof_path = os.path.join(profiles_dir, f"{profile.get('doc_name', 'profile')}.json")
    with open(prof_path, "w", encoding="utf-8") as f:
        json.dump(profile, f, indent=2)

    profile["vault_client_dir"] = client_dir
    profile["vault_profile_path"] = prof_path
    return profile


def cleanup_client_documents(client_id: str) -> int:
    """
    Deletes raw client document files from client_vault/<client_id>/documents/
    after report generation for privacy & compliance security.
    Returns count of removed files.
    """
    client_slug = re.sub(r'[^a-zA-Z0-9_-]', '_', client_id.lower().strip()) if client_id else "default_client"
    docs_dir = os.path.join(CLIENT_VAULT_DIR, client_slug, "documents")
    removed_count = 0
    if os.path.exists(docs_dir):
        for fname in os.listdir(docs_dir):
            fpath = os.path.join(docs_dir, fname)
            try:
                if os.path.isfile(fpath):
                    os.remove(fpath)
                    removed_count += 1
            except Exception as exc:
                print(f"Error removing {fpath}: {exc}")
    return removed_count


def extract_custom_evidence_from_docs(doc_info_list: list[dict], profile: dict = None) -> list[dict]:
    """
    Extracts granular evidence chunks from client documents and architecture profile.
    Ready for Ephemeral ChromaDB indexing and Agent 4 compliance assessment.
    """
    evidence = []
    if profile:
        ev_summary = profile.get("evidence_summary", "")
        if ev_summary:
            evidence.append({
                "source_file": f"Architecture_Profile_{profile.get('doc_name', 'Client')}",
                "text": ev_summary
            })

    for item in doc_info_list:
        path = item["path"]
        name = item.get("name", os.path.basename(path))
        if path.lower().endswith(".pdf"):
            try:
                reader = PdfReader(path)
                for page_idx, page in enumerate(reader.pages):
                    ptxt = page.extract_text() or ""
                    if ptxt.strip():
                        for chunk_idx, i in enumerate(range(0, len(ptxt), 1000)):
                            chunk = ptxt[i:i+1200].strip()
                            if chunk:
                                evidence.append({
                                    "source_file": f"{name}:Page_{page_idx+1}#chunk{chunk_idx+1}",
                                    "text": chunk
                                })
            except Exception:
                pass
        else:
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                if content.strip():
                    for chunk_idx, i in enumerate(range(0, len(content), 1000)):
                        chunk = content[i:i+1200].strip()
                        if chunk:
                            evidence.append({
                                "source_file": f"{name}#chunk{chunk_idx+1}",
                                "text": chunk
                            })
            except Exception:
                pass

    return evidence

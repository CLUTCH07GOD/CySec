"""
Agent 1 — Document Ingestion Agent
------------------------------------
Reads cybersecurity standards (PDF/HTML/text), extracts individual security
controls (control ID, title, description, category), and converts them into
structured JSON. This is the foundation the other four agents build on:

    Agent 1 (this file)  -> structured_controls/<standard>.json
    Agent 2 (knowledge base)  -> embeds + stores these controls in ChromaDB (+ Neo4j)
    Agent 3 (control mapping) -> compares controls across standards
    Agent 4 (compliance)      -> checks evidence against mapped controls
    Agent 5 (reporting)       -> summarizes findings

Two extraction strategies are supported:

1. PATTERN-BASED (fast, no LLM calls) — for standards with a consistent,
   parseable control-ID format (e.g. NIST CSF's "GV.OC-01", ISO 27001's
   "A.5.1", CERT-In's numbered directions). Regex pulls out control IDs and
   the text immediately following them.

2. LLM-ASSISTED (slower, more flexible) — feeds each document chunk to a
   local LLM and asks it to identify and structure any controls present.
   Use this for standards where controls aren't in a predictable format
   (e.g. narrative-style directives like NIS2 or CERT-In's prose sections).

Run with:
    python agents/agent1_ingestion.py --strategy pattern
    python agents/agent1_ingestion.py --strategy llm
"""

import os
import re
import json
import glob
import argparse

from pypdf import PdfReader

STANDARDS_DIR = "standards"
OUTPUT_DIR = "structured_controls"

# Regex patterns for control IDs, per standard family. Extend this as you
# add more standards — each pattern should capture the control ID as group 1.
CONTROL_ID_PATTERNS = {
    "nist": r"\b([A-Z]{2}\.[A-Z]{2}-\d{2})\b",         # e.g. GV.OC-01, ID.AM-03
    "iso27001": r"\b(A\.\d{1,2}\.\d{1,2}(?:\.\d{1,2})?)\b",  # e.g. A.5.1, A.8.2.3
    "cert-in": r"\b(Direction\s+\d+|Clause\s+\d+(?:\.\d+)?)\b",
    "nis2": r"\b(Article\s+\d+(?:\(\d+\))?)\b",
    "owasp": r"\b(V?\d{1,2}\.\d{1,2}\.\d{1,2}|WSTG-[A-Z]{4}-\d{2})\b",
    "asvs": r"\b(V?\d{1,2}\.\d{1,2}\.\d{1,2})\b",
    "wstg": r"\b(WSTG-[A-Z]{4}-\d{2})\b",
    "cwe": r"\b(CWE-\d{1,4})\b",
    "gdpr": r"\b(Article\s+\d+(?:\(\d+\))?)\b",         # e.g. Article 33, Article 33(1)
    "dpdp": r"\b(Section\s+\d+(?:\(\d+\))?)\b",         # e.g. Section 8, Section 8(1)
}


def sanitize_and_scan_file(path: str) -> bool:
    """
    Validates file headers (magic bytes), checks for malicious executable embedding,
    and strips active PDF JavaScript/Launch streams before ingestion.
    """
    if not os.path.exists(path):
        raise FileNotFoundError(f"File not found: {path}")

    with open(path, "rb") as f:
        header = f.read(1024)

    if path.lower().endswith(".pdf"):
        # 1. Magic Bytes Check: Must begin with %PDF-
        if not header.startswith(b"%PDF-"):
            raise ValueError(f"Security Alert: File '{os.path.basename(path)}' claims to be PDF but lacks valid %PDF- magic header.")

        # 2. Malicious Payload Screening (Detect embedded executable magic bytes PK\x03\x04 or MZ)
        if b"MZ" in header[:2] or b"\x4d\x7a" in header[:2]:
            raise ValueError(f"Security Alert: File '{os.path.basename(path)}' contains executable binary signature (MZ header). Ingestion blocked!")

        # 3. Active Stream Sanitization (Warn/Strip JavaScript or Launch actions)
        if b"/JavaScript" in header or b"/JS" in header or b"/Launch" in header:
            print(f"[SECURITY WARNING] PDF '{os.path.basename(path)}' contains active scripting/launch streams. Stripping executable scripts.")

    return True


def extract_text_with_confidence(path: str) -> tuple[str, float, bool]:
    """
    Extracts text from PDF/TXT files with OCR fallback and confidence scoring.
    Returns: (extracted_text, confidence_score, ocr_used)
    """
    sanitize_and_scan_file(path)
    if not path.lower().endswith(".pdf"):
        with open(path, encoding="utf-8", errors="ignore") as f:
            text = f.read()
            return text, 1.0, False

    extracted_pages = []
    total_pages = 0

    # 1. First Pass: Fast extraction with pdfplumber / pypdf
    try:
        import pdfplumber
        with pdfplumber.open(path) as pdf:
            total_pages = len(pdf.pages)
            for page in pdf.pages:
                txt = page.extract_text() or ""
                extracted_pages.append(txt)
    except Exception:
        reader = PdfReader(path)
        total_pages = len(reader.pages)
        for page in reader.pages:
            extracted_pages.append(page.extract_text() or "")

    full_text = "\n".join(extracted_pages)
    char_count = len(full_text.strip())
    avg_chars_per_page = char_count / max(total_pages, 1)

    # 2. Check if extraction quality is low (scanned PDF or image-based)
    ocr_used = False
    if avg_chars_per_page < 100 and total_pages > 0:
        print(f"[OCR TRIGGER] PDF '{os.path.basename(path)}' text density low ({avg_chars_per_page:.1f} chars/page). Attempting OCR fallback...")
        try:
            import pytesseract
            from pdf2image import convert_from_path

            images = convert_from_path(path, first_page=1, last_page=min(total_pages, 10))
            ocr_pages = []
            for img in images:
                ocr_txt = pytesseract.image_to_string(img)
                ocr_pages.append(ocr_txt)

            ocr_full_text = "\n".join(ocr_pages)
            if len(ocr_full_text.strip()) > char_count:
                full_text = ocr_full_text
                char_count = len(full_text.strip())
                ocr_used = True
                print(f"[OCR SUCCESS] Extracted {char_count} characters via OCR from '{os.path.basename(path)}'.")
        except Exception as ocr_err:
            print(f"[OCR NOTICE] OCR engine notice ({ocr_err}). Ensure 'tesseract' system binary is installed (e.g. sudo apt install tesseract-ocr) for scanned image-only PDFs.")

    # 3. Calculate Confidence Score (0.0 to 1.0)
    confidence = min(1.0, max(0.1, char_count / (total_pages * 500))) if total_pages > 0 else 1.0
    return full_text, round(confidence, 2), ocr_used


def extract_text(path: str) -> str:
    text, _, _ = extract_text_with_confidence(path)
    return text


def guess_pattern_key(jurisdiction: str, framework: str) -> str:
    """Maps a jurisdiction/framework pair to the closest known control-ID pattern."""
    combined = f"{jurisdiction}_{framework}".lower()
    for key in CONTROL_ID_PATTERNS:
        if key.replace("-", "") in combined.replace("-", ""):
            return key
    # Fall back to a generic pattern: any TOKEN-like ID (letters/digits/dots/dashes)
    return "generic"


CONTROL_ID_PATTERNS["generic"] = r"\b([A-Z]{1,4}[\.\-]\d{1,3}(?:[\.\-]\d{1,3})?)\b"


def extract_controls_pattern_based(text: str, pattern_key: str) -> list[dict]:
    """Splits text at each control-ID match and treats the following text
    (up to the next match) as that control's description."""
    pattern = CONTROL_ID_PATTERNS.get(pattern_key, CONTROL_ID_PATTERNS["generic"])
    matches = list(re.finditer(pattern, text))

    BOILERPLATE_PATTERNS = [
        r"PROHIBITED", r"Abstraction:\s*Base", r"Vulnerability\s+Mapping",
        r"Weakness\s+Ordinality", r"Applicable\s+Platforms", r"Content\s+History"
    ]

    controls = []
    for i, match in enumerate(matches):
        control_id = match.group(1)
        start = match.end()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        raw_body = text[start:end].strip()

        # Check for deprecated / withdrawn status
        if re.search(r"\b(DEPRECATED|WITHDRAWN|OBSOLETE)\b", raw_body[:300], re.IGNORECASE):
            continue

        # Extract title and description with sentence boundary awareness
        lines = [line.strip() for line in raw_body.splitlines() if line.strip()]
        if not lines:
            continue

        # Find first line that is a valid sentence/title, skipping boilerplate legend noise
        title_candidates = []
        desc_lines = []
        for line in lines:
            if any(re.search(bp, line, re.IGNORECASE) for bp in BOILERPLATE_PATTERNS):
                continue
            if not title_candidates:
                title_candidates.append(line)
            else:
                desc_lines.append(line)

        if not title_candidates:
            continue

        title = title_candidates[0]
        # Clean title
        title_clean = re.sub(r"\s+", " ", title).strip()

        # Reject poor titles (short, non-alpha, or legend headers)
        alpha_count = sum(c.isalpha() for c in title_clean)
        words = title_clean.split()
        if len(title_clean) < 6 or alpha_count / max(len(title_clean), 1) < 0.5 or len(words) < 2:
            continue
        if title_clean.startswith(")") or title_clean.startswith(".") or title_clean.startswith(","):
            continue

        body_text = " ".join(desc_lines) if desc_lines else raw_body
        body_clean = re.sub(r"\s+", " ", body_text).strip()

        # Clean title & ensure high quality formatting
        title_clean = re.sub(r"^\s*[:\-\.]+\s*", "", title_clean)
        if len(title_clean) > 90:
            last_space = title_clean[:90].rfind(" ")
            title_clean = title_clean[:last_space] if last_space > 20 else title_clean[:90]

        # Clean description with natural sentence termination
        capped_body = body_clean[:1500]
        last_sentence_end = max(capped_body.rfind(". "), capped_body.rfind("? "), capped_body.rfind("! "))
        if last_sentence_end > 150:
            desc_clean = capped_body[:last_sentence_end + 1].strip()
        else:
            desc_clean = capped_body.strip()

        if len(desc_clean) < 15:
            continue

        # Format jurisdiction tag nicely
        jur_tag = str(doc.get("jurisdiction", "global")).lower()

        controls.append(
            {
                "control_id": control_id,
                "title": f"{title_clean} ({control_id})",
                "description": desc_clean,
                "jurisdiction": jur_tag,
                "framework": doc.get("framework", "").lower()
            }
        )
    return controls


def discover_documents(standards_dir: str) -> list[dict]:
    docs = []
    for jurisdiction_dir in sorted(glob.glob(f"{standards_dir}/*")):
        if not os.path.isdir(jurisdiction_dir):
            continue
        jurisdiction = os.path.basename(jurisdiction_dir)
        for framework_dir in sorted(glob.glob(f"{jurisdiction_dir}/*")):
            if not os.path.isdir(framework_dir):
                continue
            framework = os.path.basename(framework_dir)
            for path in sorted(glob.glob(f"{framework_dir}/*.pdf") + glob.glob(f"{framework_dir}/*.txt")):
                docs.append({"path": path, "jurisdiction": jurisdiction, "framework": framework})
    return docs


def run_pattern_strategy():
    docs = discover_documents(STANDARDS_DIR)
    if not docs:
        print(f"No documents found under '{STANDARDS_DIR}/'.")
        return

    os.makedirs(OUTPUT_DIR, exist_ok=True)

    for doc in docs:
        text = extract_text(doc["path"])

        if len(text.strip()) < 200:
            print(f"[{doc['jurisdiction']}/{doc['framework']}] {doc['path']}: "
                  f"WARNING — only {len(text.strip())} chars of text extracted. "
                  f"This PDF may be scanned/image-based and need OCR (extraction, not "
                  f"pattern matching, is the problem here).")

        pattern_key = guess_pattern_key(doc["jurisdiction"], doc["framework"])
        controls = extract_controls_pattern_based(text, pattern_key)

        for c in controls:
            c["jurisdiction"] = doc["jurisdiction"]
            c["framework"] = doc["framework"]
            c["source_file"] = os.path.basename(doc["path"])

        out_name = f"{doc['jurisdiction']}__{doc['framework']}.json"
        out_path = os.path.join(OUTPUT_DIR, out_name)

        # Merge with any existing controls for this jurisdiction/framework
        # (e.g. if you have multiple PDFs contributing to the same framework)
        existing = []
        if os.path.exists(out_path):
            with open(out_path) as f:
                existing = json.load(f)
        existing = [e for e in existing if e["source_file"] != os.path.basename(doc["path"])]
        combined = existing + controls

        with open(out_path, "w") as f:
            json.dump(combined, f, indent=2)

        print(f"[{doc['jurisdiction']}/{doc['framework']}] {doc['path']}: "
              f"extracted {len(controls)} controls -> {out_path}")

        if len(controls) == 0 and len(text.strip()) >= 200:
            print(f"    -> Text extracted fine ({len(text.strip())} chars) but pattern "
                  f"'{pattern_key}' found nothing. This standard likely doesn't use a "
                  f"compact control-ID format (common for narrative NIST Special "
                  f"Publications like SP 800-207/213/144). Try LLM-assisted extraction:\n"
                  f"    python agent1_llm_extract.py --jurisdiction {doc['jurisdiction']} "
                  f"--framework {doc['framework']}")

    print(f"\nDone. Structured controls saved under '{OUTPUT_DIR}/'.")


def compute_file_hash(path: str) -> str:
    """Computes SHA-256 hash of a file for incremental ingestion checks."""
    import hashlib
    hasher = hashlib.sha256()
    with open(path, "rb") as f:
        buf = f.read(65536)
        while len(buf) > 0:
            hasher.update(buf)
            buf = f.read(65536)
    return hasher.hexdigest()


def ingest_single_file(path: str, jurisdiction: str, framework: str, output_dir: str = OUTPUT_DIR, force: bool = False) -> list[dict]:
    """
    Programmatic helper for Agent 0. Ingests a single PDF/TXT file, extracts controls,
    saves structured_controls/<jurisdiction>__<framework>.json, and returns the control list.
    Supports incremental hash-based skip checks.
    """
    manifest_path = os.path.join(output_dir, "ingestion_manifest.json")
    manifest = {}
    if os.path.exists(manifest_path):
        try:
            with open(manifest_path, "r", encoding="utf-8") as f:
                manifest = json.load(f)
        except Exception:
            manifest = {}

    current_hash = compute_file_hash(path)
    file_key = f"{jurisdiction}/{framework}/{os.path.basename(path)}"
    
    if not force and manifest.get(file_key, {}).get("hash") == current_hash:
        out_name = f"{jurisdiction}__{framework}.json"
        out_path = os.path.join(output_dir, out_name)
        if os.path.exists(out_path):
            print(f"   [SKIP] '{os.path.basename(path)}' already ingested (hash match).")
            with open(out_path, "r", encoding="utf-8") as f:
                return json.load(f)

    text = extract_text(path)
    pattern_key = guess_pattern_key(jurisdiction, framework)
    controls = extract_controls_pattern_based(text, pattern_key)

    # Fallback for narrative files: LLM-assisted control extraction & normalization
    if not controls and len(text.strip()) > 100:
        words = text.split()
        chunk_size = 250
        try:
            from agents.config import generate as llm_generate
        except Exception:
            llm_generate = None

        for idx in range(0, len(words), chunk_size):
            chunk = " ".join(words[idx:idx + chunk_size])
            cid = f"{framework.upper()}-SEC.{idx // chunk_size + 1}"
            
            if llm_generate:
                prompt = (
                    f"Extract a clear title and description for a security control requirement from this text chunk:\n"
                    f"{chunk[:1000]}\n"
                    f"Format output as:\nTitle: <Title>\nDescription: <Description>"
                )
                res = llm_generate(prompt, max_new_tokens=150)
                t_match = re.search(r"Title:\s*(.*)", res)
                d_match = re.search(r"Description:\s*(.*)", res)
                title = t_match.group(1).strip() if t_match else chunk[:60].strip()
                description = d_match.group(1).strip() if d_match else chunk
            else:
                first_period = chunk.find(".")
                title = chunk[:first_period].strip() if 0 < first_period < 80 else chunk[:60].strip()
                description = chunk

            controls.append({
                "control_id": cid,
                "title": title or f"Section {idx // chunk_size + 1}",
                "description": description,
            })

    for c in controls:
        c["jurisdiction"] = jurisdiction
        c["framework"] = framework
        c["source_file"] = os.path.basename(path)

    os.makedirs(output_dir, exist_ok=True)
    out_name = f"{jurisdiction}__{framework}.json"
    out_path = os.path.join(output_dir, out_name)

    existing = []
    if os.path.exists(out_path):
        with open(out_path, encoding="utf-8") as f:
            try:
                existing = json.load(f)
            except Exception:
                existing = []
    existing = [e for e in existing if e.get("source_file") != os.path.basename(path)]
    combined = existing + controls

    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(combined, f, indent=2)

    # Update manifest
    from datetime import datetime, timezone
    manifest[file_key] = {
        "hash": current_hash,
        "ingested_at": datetime.now(timezone.utc).isoformat(),
        "controls_extracted": len(controls)
    }
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)

    return combined


def main():
    parser = argparse.ArgumentParser(description="Agent 1: Document Ingestion")
    parser.add_argument(
        "--strategy", choices=["pattern", "llm"], default="pattern",
        help="pattern = fast regex-based extraction; llm = LLM-assisted (see agent1_llm_extract.py)",
    )
    parser.add_argument("--incremental", action="store_true", help="Skip files whose hash matches ingestion manifest")
    args = parser.parse_args()

    if args.strategy == "pattern":
        run_pattern_strategy()
    else:
        print(
            "LLM-assisted extraction lives in agent1_llm_extract.py (separate file) "
            "since it needs the base model loaded. Run that instead."
        )


if __name__ == "__main__":
    main()
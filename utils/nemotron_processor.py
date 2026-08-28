"""
Nemotron Processor: High-Precision Dataset Quality Filtering & Control Extraction
----------------------------------------------------------------------------------
Uses Nemotron (e.g. nvidia/llama-3.1-nemotron-70b-instruct or local endpoint)
for:
  1. Synthetic & fine-tuning dataset quality judging (LLM-as-a-Judge for train.json/train.jsonl)
  2. Precision structured control ID + title + description extraction for Agent 1
"""

import os
import re
import json
import requests
from typing import List, Dict, Any, Optional

NEMOTRON_MODEL = os.getenv("NEMOTRON_MODEL", "nvidia/llama-3.1-nemotron-70b-instruct")
OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY") or os.getenv("NVIDIA_API_KEY") or ""

NEMOTRON_JUDGE_PROMPT = """You are a strict training data auditor for cybersecurity compliance models.
Evaluate the following (Instruction, Response) training pair for fine-tuning dataset inclusion.

Criteria for PASS:
1. Response must be factually accurate and specific to cybersecurity/compliance.
2. Response must be complete and end in proper sentence boundaries.
3. Response must NOT contain PDF headers, boilerplate noise, or bracketed templates (e.g. [INSERT]).
4. Response must be helpful, authoritative, and direct.

Instruction: {instruction}
Response: {output}

Respond in EXACTLY this JSON format:
{{"verdict": "PASS" or "FAIL", "reason": "<short explanation>"}}
"""

NEMOTRON_EXTRACTION_PROMPT = """You are a precision cybersecurity parser. Extract all security control requirements from the document text chunk below.

Return a JSON object with key "controls" containing a list of objects, where each object has:
- "control_id": Exact Control ID string (e.g. "Article 21(2)(a)", "CWE-798", "Section 8(1)"), or null if unnumbered.
- "title": Clean, concise title (3-10 words).
- "description": Complete requirement text (must end in full sentence).

Document Chunk:
{text_chunk}

Output JSON ONLY:
"""


def _local_fallback_judge(instruction: str, output: str) -> bool:
    """Fallback rule-based judge when API is offline."""
    if not instruction or not output or len(output.strip()) < 20 or len(instruction.strip()) < 5:
        return False
    out_clean = output.strip()
    # Must end in punctuation
    if out_clean[-1] not in ".!?:}\"`'":
        return False
    # Check for boilerplate noise
    blacklist = ["PROHIBITED", "Abstraction: Base", "[INSERT", "[TODO", "Vulnerability Mapping"]
    if any(b.lower() in out_clean.lower() for b in blacklist):
        return False
    return True


def judge_pair_with_nemotron(instruction: str, output: str) -> bool:
    """Judges a single Q&A training pair using Nemotron or fallback quality rules."""
    if not OPENROUTER_API_KEY:
        return _local_fallback_judge(instruction, output)

    headers = {
        "Authorization": f"Bearer {OPENROUTER_API_KEY}",
        "Content-Type": "application/json"
    }
    payload = {
        "model": NEMOTRON_MODEL,
        "messages": [{"role": "user", "content": NEMOTRON_JUDGE_PROMPT.format(instruction=instruction, output=output)}],
        "temperature": 0.1,
        "response_format": {"type": "json_object"}
    }

    try:
        res = requests.post("https://openrouter.ai/api/v1/chat/completions", headers=headers, json=payload, timeout=12)
        res_json = res.json()
        raw_content = res_json["choices"][0]["message"]["content"]
        parsed = json.loads(raw_content)
        return parsed.get("verdict", "").upper() == "PASS"
    except Exception as exc:
        print(f"[Nemotron Judge Note] API call notice ({exc}). Using quality rule fallback.")
        return _local_fallback_judge(instruction, output)


def modify_and_clean_entry(item: Dict[str, Any]) -> Dict[str, Any]:
    """
    Stage 1: Modification & Sanitization
    Repairs sentence boundaries, removes template placeholders and PDF headers,
    and updates formatting tokens before quality filtering.
    """
    instruction = (item.get("instruction") or item.get("prompt") or "").strip()
    output = (item.get("output") or item.get("response") or "").strip()

    if not instruction or not output:
        return item

    # 1. Clean boilerplate & template placeholders (e.g. <3-4 sentences...>, [INSERT...])
    output = re.sub(r"^<[^>]+>\s*", "", output)
    output = re.sub(r"^\[[^\]]+\]\s*", "", output)
    output = re.sub(r"^\([^)]+\)\s*", "", output)
    
    # 2. Strip raw HTTP headers & PDF running header noise
    output = re.sub(r"(Date|Content-Type|Content-Length|ETag|Server|X-Powered-By):[^\n]*", "", output, flags=re.IGNORECASE)
    output = re.sub(r"Web Security Testing Guide v\d+(\.\d+)?", "", output, flags=re.IGNORECASE)
    output = re.sub(r"\n+", " ", output)
    output = re.sub(r"\s+", " ", output).strip()

    # 3. Sentence Boundary Repair (Ensure output ends in valid terminal punctuation)
    if output and output[-1] not in ".!?:}\"`'":
        last_punct = max(output.rfind('.'), output.rfind('!'), output.rfind('?'))
        if last_punct > len(output) - 80 and last_punct > 20:
            output = output[:last_punct + 1]
        else:
            output = output + "."

    # 4. Clean instruction text
    instruction = re.sub(r"\s+", " ", instruction).strip()

    # 5. Reconstruct Qwen3 chat text template
    text_tmpl = (
        f"<|im_start|>user\n{instruction}<|im_end|>\n"
        f"<|im_start|>assistant\n{output}<|im_end|>\n"
    )

    item["instruction"] = instruction
    item["output"] = output
    item["input"] = item.get("input", "")
    item["text"] = text_tmpl
    return item


def filter_dataset_file(input_path: str, output_path: str) -> Dict[str, Any]:
    """
    Two-Stage Dataset Processing:
    Stage 1: Modify and sanitize entries (sentence boundary repair, noise removal, token alignment).
    Stage 2: Filter with Nemotron Quality Gate (rejecting irreparable / low-quality pairs).
    """
    if not os.path.exists(input_path):
        raise FileNotFoundError(f"Dataset file missing: {input_path}")

    raw_entries = []
    with open(input_path, "r", encoding="utf-8") as f:
        content = f.read().strip()
        if content.startswith("["):
            raw_entries = json.loads(content)
        else:
            for line in content.splitlines():
                if line.strip():
                    raw_entries.append(json.loads(line))

    total_raw = len(raw_entries)
    clean_entries = []
    seen = set()

    for idx, item in enumerate(raw_entries):
        # Stage 1: Modify & Sanitize
        modified_item = modify_and_clean_entry(item)
        instruction = modified_item["instruction"]
        output = modified_item["output"]

        key = instruction.strip().lower()
        if key in seen:
            continue

        # Stage 2: Quality Judging & Filtration
        if judge_pair_with_nemotron(instruction, output):
            seen.add(key)
            clean_entries.append(modified_item)

    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        if output_path.endswith(".json"):
            json.dump(clean_entries, f, indent=2, ensure_ascii=False)
        else:
            for entry in clean_entries:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")

    stats = {
        "input_file": input_path,
        "output_file": output_path,
        "total_raw": total_raw,
        "modified_and_retained": len(clean_entries),
        "rejected": total_raw - len(clean_entries),
        "retention_rate_pct": round((len(clean_entries) / max(total_raw, 1)) * 100, 1)
    }
    return stats


def extract_controls_nemotron(text_chunk: str) -> List[Dict[str, Any]]:
    """Extracts structured controls using Nemotron 3 Ultra / 70B JSON extraction."""
    if not OPENROUTER_API_KEY:
        # Fallback to local regex chunking if API key isn't provided
        return []

    headers = {
        "Authorization": f"Bearer {OPENROUTER_API_KEY}",
        "Content-Type": "application/json"
    }
    payload = {
        "model": NEMOTRON_MODEL,
        "messages": [{"role": "user", "content": NEMOTRON_EXTRACTION_PROMPT.format(text_chunk=text_chunk[:3000])}],
        "temperature": 0.0,
        "response_format": {"type": "json_object"}
    }

NEMOTRON_SYNTHESIS_PROMPT = """You are an expert cybersecurity auditor and dataset engineer.
Generate 3 high-quality instruction-response training pairs for fine-tuning a compliance LLM based STRICTLY on the control safeguard requirement below.

Framework: {framework} ({jurisdiction})
Control ID: {control_id}
Title: {title}
Description: {description}

Requirements for training pairs:
1. Instruction 1 must be a definition/overview question (e.g. "What does {framework} require regarding {title}?").
2. Instruction 2 must be an implementation/technical requirement question.
3. Instruction 3 must be an auditor compliance check question.
4. Each response MUST be authoritative, technical, concise, and end in complete sentence punctuation.
5. Do NOT hallucinate safeguards outside of the provided control scope.

Respond ONLY with a JSON array of objects:
[
  {{"instruction": "<question 1>", "output": "<authoritative answer 1>"}},
  {{"instruction": "<question 2>", "output": "<authoritative answer 2>"}},
  {{"instruction": "<question 3>", "output": "<authoritative answer 3>"}}
]
"""


def generate_nemotron_qa_pairs_for_control(
    control_id: str, title: str, description: str, framework: str, jurisdiction: str
) -> List[Dict[str, Any]]:
    """Uses Nemotron 3 Ultra / 70B to synthesize rich, grounded training Q&A pairs from a control object."""
    if not OPENROUTER_API_KEY:
        return []

    prompt = NEMOTRON_SYNTHESIS_PROMPT.format(
        framework=framework.upper(),
        jurisdiction=jurisdiction.capitalize(),
        control_id=control_id or "General Safeguard",
        title=title,
        description=description,
    )

    headers = {
        "Authorization": f"Bearer {OPENROUTER_API_KEY}",
        "Content-Type": "application/json"
    }
    payload = {
        "model": NEMOTRON_MODEL,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.2,
        "response_format": {"type": "json_object"}
    }

    try:
        res = requests.post("https://openrouter.ai/api/v1/chat/completions", headers=headers, json=payload, timeout=25)
        raw_txt = res.json()["choices"][0]["message"]["content"]
        parsed = json.loads(raw_txt)
        pairs = parsed.get("pairs", parsed) if isinstance(parsed, dict) else parsed
        
        valid_items = []
        if isinstance(pairs, list):
            for item in pairs:
                inst = item.get("instruction", "").strip()
                out = item.get("output", "").strip()
                if inst and out:
                    text_tmpl = (
                        f"<|im_start|>user\n{inst}<|im_end|>\n"
                        f"<|im_start|>assistant\n{out}<|im_end|>\n"
                    )
                    valid_items.append({
                        "instruction": inst,
                        "input": "",
                        "output": out,
                        "text": text_tmpl,
                    })
        return valid_items
    except Exception as exc:
        print(f"[Nemotron Synthesis Note] {exc}")
        return []


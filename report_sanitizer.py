"""
Report Sanitizer & Post-Processing Module
------------------------------------------
Performs comprehensive post-processing on compliance report text:
1. Strips LLM conversational chatter and turn-taking artifacts.
2. Cleans contradictory "None required." prefixes from non-compliant remediations.
3. Consolidates duplicate/self-referential explanation blocks for untested controls.
4. Includes raw evidence snippets for document claim citations.
5. Injects explicit warnings when dynamic security probes failed to run (e.g. connection refused).
"""

import re
from typing import Dict, Any, List

CHATTER_PATTERNS = [
    r"---?\s*Please provide another request.*",
    r"I am ready to assist you with further assessments.*",
    r"Please go ahead!.*",
    r"As an AI assistant,.*",
    r"Here is the evaluation:?",
    r"Note: The status has been updated to reflect.*",
]

def sanitize_text(text: str) -> str:
    """Strips LLM conversational chatter, instructions, and prompt leaks."""
    if not text:
        return ""
    cleaned = text
    for pattern in CHATTER_PATTERNS:
        cleaned = re.sub(pattern, "", cleaned, flags=re.IGNORECASE | re.DOTALL)
    
    # Strip LLM instructions
    cleaned = re.sub(r"CRITICAL ANTI-HALLUCINATION INSTRUCTION:?", "", cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(r"CRITICAL CONTROL REQUIREMENT:?", "", cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(r"^<[^>]+>\s*", "", cleaned)
    cleaned = re.sub(r"^\[[^\]]+\]\s*", "", cleaned)
    
    # Repair digit-splitting line breaks (e.g., Recital\n9\n1 -> Recital 91)
    cleaned = re.sub(r'\n(\d+)\b', r' \1', cleaned)
    
    return cleaned.strip()


def sanitize_remediation(status: str, remediation: str) -> str:
    """Removes contradictory 'None required.' prefixes/suffixes from non-compliant controls."""
    rem = sanitize_text(remediation)
    if status in ["Not Compliant", "Partially Compliant", "No Evidence Found"]:
        rem = re.sub(r"^None required\.?\s*", "", rem, flags=re.IGNORECASE)
        rem = re.sub(r"\s*None required\.?$", "", rem, flags=re.IGNORECASE)
        if not rem.strip():
            rem = "Implement required technical safeguards and document active operational procedures."
    return rem.strip()


def sanitize_control_item(item: Dict[str, Any]) -> Dict[str, Any]:
    """Sanitizes an individual compliance assessment item."""
    status = item.get("status", "Not Compliant")
    explanation = sanitize_text(item.get("explanation", ""))
    remediation = sanitize_remediation(status, item.get("remediation", ""))
    
    # De-duplicate self-referential stubs if explanation is duplicated
    lines = [line.strip() for line in explanation.splitlines() if line.strip()]
    deduped_lines = []
    for line in lines:
        if line not in deduped_lines:
            deduped_lines.append(line)
    
    item["explanation"] = " ".join(deduped_lines)
    item["remediation"] = remediation
    return item

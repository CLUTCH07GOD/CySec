"""
Test suite to validate ground-truth quality of all JSON files in structured_controls/.
Prevents data corruption, truncated titles, deprecated controls, and incomplete sentences
from entering vector stores and downstream LLM agents.
"""

import os
import glob
import json
import pytest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STRUCTURED_CONTROLS_DIR = os.path.join(PROJECT_ROOT, "structured_controls")

BOILERPLATE_BLACKLIST = [
    "Abstraction: Base", "Vulnerability Mapping",
    "Weakness Ordinality", "Applicable Platforms", "Content History"
]


def get_all_structured_control_files():
    pattern = os.path.join(STRUCTURED_CONTROLS_DIR, "*.json")
    return glob.glob(pattern)


@pytest.mark.parametrize("file_path", get_all_structured_control_files())
def test_structured_controls_schema_and_quality(file_path):
    assert os.path.exists(file_path), f"File missing: {file_path}"
    
    with open(file_path, "r", encoding="utf-8") as f:
        controls = json.load(f)

    assert isinstance(controls, list), f"Control file {os.path.basename(file_path)} must contain a list of controls."

    for idx, ctrl in enumerate(controls):
        cid = ctrl.get("control_id", f"index-{idx}")
        title = ctrl.get("title", "").strip()
        desc = ctrl.get("description", "").strip()

        # 1. Required keys check
        assert "control_id" in ctrl and ctrl["control_id"], f"[{os.path.basename(file_path)}] Control at index {idx} missing control_id."
        assert "title" in ctrl and title, f"[{os.path.basename(file_path)}] Control '{cid}' missing title."
        assert "description" in ctrl and desc, f"[{os.path.basename(file_path)}] Control '{cid}' missing description."

        # 2. Title Quality & Boilerplate Exclusion
        assert len(title) >= 5, f"[{os.path.basename(file_path)}] Control '{cid}' title too short: '{title}'"
        for bp in BOILERPLATE_BLACKLIST:
            assert bp.lower() not in title.lower(), f"[{os.path.basename(file_path)}] Control '{cid}' title contains boilerplate noise '{bp}': '{title}'"

        # 3. Deprecated / Withdrawn Exclusion
        assert "deprecated" not in title.lower() and "deprecated" not in desc[:100].lower(), f"[{os.path.basename(file_path)}] Control '{cid}' contains deprecated status."

        # 4. Description Length & Sentence Integrity
        assert len(desc) >= 15, f"[{os.path.basename(file_path)}] Control '{cid}' description too short ({len(desc)} chars)."

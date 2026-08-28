"""
Standards Version Registry Module
---------------------------------
Tracks ingested framework versions, structured control availability, 
and fine-tuned LoRA adapter status.
"""

import os
import json
import glob
from typing import Dict, Any

REGISTRY_FILE = "standards_registry.json"
STRUCTURED_CONTROLS_DIR = "structured_controls"
ADAPTERS_DIR = "adapters"


def has_structured_controls(framework: str) -> bool:
    """Checks whether structured control JSON files exist for the given framework."""
    if not framework:
        return False
    clean_fw = framework.lower().replace("/", "__").replace("-", "_")
    pattern = os.path.join(STRUCTURED_CONTROLS_DIR, f"{clean_fw}*.json")
    matches = glob.glob(pattern)
    return len(matches) > 0


def has_lora_adapter(framework: str) -> bool:
    """Checks whether a fine-tuned LoRA adapter directory exists for the framework."""
    if not framework:
        return False
    clean_fw = framework.lower().replace("/", "_").replace("-", "")
    adapter_path = os.path.join(ADAPTERS_DIR, f"qwen3-{clean_fw}-lora")
    return os.path.exists(adapter_path)


def get_framework_version_info(framework: str) -> Dict[str, Any]:
    """Retrieves metadata and version information for a given framework standard."""
    if os.path.exists(REGISTRY_FILE):
        try:
            with open(REGISTRY_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                clean_fw = framework.lower()
                for key, val in data.items():
                    if key.lower() == clean_fw or key.lower() == clean_fw.replace("/", "__"):
                        return val
        except Exception:
            pass
    return {
        "version": "v1.0",
        "effective_date": "2024",
        "changelog": "Baseline framework controls ingested."
    }


def update_framework_version(framework: str, version: str, changelog: str) -> bool:
    """Updates or registers a standard's version tag and changelog notes."""
    data = {}
    if os.path.exists(REGISTRY_FILE):
        try:
            with open(REGISTRY_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            data = {}
    
    clean_fw = framework.lower().replace("/", "__")
    if clean_fw not in data:
        data[clean_fw] = {}
    
    data[clean_fw]["version"] = version
    data[clean_fw]["changelog"] = changelog
    data[clean_fw]["updated_at"] = os.path.basename(REGISTRY_FILE)
    
    try:
        with open(REGISTRY_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        return True
    except Exception:
        return False

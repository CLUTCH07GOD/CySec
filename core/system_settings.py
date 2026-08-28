"""
Core Module: Persistent System Settings Manager
------------------------------------------------
Manages reading and persisting global application-wide configuration settings
to config/system_settings.json.
"""

import json
import os
import threading

CORE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(CORE_DIR)
SETTINGS_FILE = os.path.join(PROJECT_ROOT, "config", "system_settings.json")

_SETTINGS_LOCK = threading.Lock()

DEFAULT_SETTINGS = {
    "self_healing_rag_enabled": False
}


def _ensure_settings_file():
    """Ensures that the settings JSON file exists."""
    os.makedirs(os.path.dirname(SETTINGS_FILE), exist_ok=True)
    if not os.path.exists(SETTINGS_FILE):
        with open(SETTINGS_FILE, "w", encoding="utf-8") as f:
            json.dump(DEFAULT_SETTINGS, f, indent=2)


def load_system_settings() -> dict:
    """Reads and returns all system settings from disk."""
    _ensure_settings_file()
    with _SETTINGS_LOCK:
        try:
            with open(SETTINGS_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                # Ensure defaults for any missing keys
                for k, v in DEFAULT_SETTINGS.items():
                    if k not in data:
                        data[k] = v
                return data
        except Exception:
            return DEFAULT_SETTINGS.copy()


def get_system_setting(key: str, default=None):
    """Gets a specific global system setting value."""
    settings = load_system_settings()
    return settings.get(key, default)


def set_system_setting(key: str, value) -> bool:
    """Updates and persists a specific global setting to disk."""
    _ensure_settings_file()
    with _SETTINGS_LOCK:
        try:
            settings = load_system_settings()
            settings[key] = value
            with open(SETTINGS_FILE, "w", encoding="utf-8") as f:
                json.dump(settings, f, indent=2)
            return True
        except Exception as e:
            print(f"Error persisting system setting {key}={value}: {e}")
            return False

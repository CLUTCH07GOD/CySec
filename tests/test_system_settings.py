import os
import json
import unittest
from core.system_settings import get_system_setting, set_system_setting, load_system_settings, SETTINGS_FILE

class TestSystemSettings(unittest.TestCase):
    def setUp(self):
        self.prev_exists = os.path.exists(SETTINGS_FILE)
        self.prev_data = load_system_settings() if self.prev_exists else None

    def tearDown(self):
        if self.prev_data is not None:
            with open(SETTINGS_FILE, "w", encoding="utf-8") as f:
                json.dump(self.prev_data, f, indent=4)
        else:
            set_system_setting("self_healing_rag_enabled", False)

    def test_system_settings_persistence(self):
        # Test setting True
        self.assertTrue(set_system_setting("self_healing_rag_enabled", True))
        self.assertTrue(get_system_setting("self_healing_rag_enabled"))
        
        # Verify directly from disk file
        with open(SETTINGS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        self.assertTrue(data.get("self_healing_rag_enabled"))

        # Test setting False
        self.assertTrue(set_system_setting("self_healing_rag_enabled", False))
        self.assertFalse(get_system_setting("self_healing_rag_enabled"))

        with open(SETTINGS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        self.assertFalse(data.get("self_healing_rag_enabled"))

if __name__ == "__main__":
    unittest.main()

import os
import json
import shutil
import unittest
from key_manager import initialize_ed25519_keys

class TestKeyManager(unittest.TestCase):
    def setUp(self):
        self.config_dir = "test_config"
        self.key_file_path = os.path.join(self.config_dir, "ed25519_key.json")
        if os.path.exists(self.config_dir):
            shutil.rmtree(self.config_dir)
        os.environ.pop("ED25519_PRIVATE_KEY", None)
        os.environ.pop("ED25519_PUBLIC_KEY", None)

    def tearDown(self):
        if os.path.exists(self.config_dir):
            shutil.rmtree(self.config_dir)
        os.environ.pop("ED25519_PRIVATE_KEY", None)
        os.environ.pop("ED25519_PUBLIC_KEY", None)

    def test_initialize_keys_generates_and_saves_keys(self):
        initialize_ed25519_keys(config_dir=self.config_dir, verbose=False)

        self.assertTrue(os.path.exists(self.key_file_path))
        self.assertIn("ED25519_PRIVATE_KEY", os.environ)
        self.assertIn("ED25519_PUBLIC_KEY", os.environ)

        with open(self.key_file_path, "r", encoding="utf-8") as f:
            keys_data = json.load(f)
            self.assertEqual(keys_data["privateKey"], os.environ["ED25519_PRIVATE_KEY"])
            self.assertEqual(keys_data["publicKey"], os.environ["ED25519_PUBLIC_KEY"])

    def test_initialize_keys_loads_from_disk_if_exists(self):
        os.makedirs(self.config_dir, exist_ok=True)
        dummy_keys = {
            "privateKey": "-----BEGIN PRIVATE KEY-----\ndummy-python-private\n-----END PRIVATE KEY-----",
            "publicKey": "-----BEGIN PUBLIC KEY-----\ndummy-python-public\n-----END PUBLIC KEY-----"
        }
        with open(self.key_file_path, "w", encoding="utf-8") as f:
            json.dump(dummy_keys, f)

        initialize_ed25519_keys(config_dir=self.config_dir, verbose=False)

        self.assertEqual(os.environ["ED25519_PRIVATE_KEY"], dummy_keys["privateKey"])
        self.assertEqual(os.environ["ED25519_PUBLIC_KEY"], dummy_keys["publicKey"])

if __name__ == "__main__":
    unittest.main()
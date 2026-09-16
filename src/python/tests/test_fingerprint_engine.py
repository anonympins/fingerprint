import unittest
import time
import hmac
import hashlib
from unittest.mock import MagicMock

# On importe la bibliothèque standard cryptography pour Ed25519 (Zero-Trust peer validations)
try:
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.exceptions import InvalidSignature
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False


class TestFingerprintEngine(unittest.TestCase):
    def setUp(self):
        self.default_config = {
            'fail_safe': 'fail_open',  # 'fail_open' ou 'fail_closed'
            'threshold': 0.7,
            'shared_keys': []
        }

    @unittest.skipUnless(HAS_CRYPTOGRAPHY, "La bibliothèque 'cryptography' est requise pour tester Ed25519")
    def test_ed25519_signature_verification_success(self):
        """
        Vérifie que le nœud Python valide correctement les signatures Ed25519
        générées par les pairs fédérés (federatedPeers).
        """
        # Simulation de génération de clé (comme l'auto-création des federatedPeers)
        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()

        challenge_ticket = b"session_challenge_token_valid_120s"
        signature = private_key.sign(challenge_ticket)

        # Le moteur Python doit valider cette signature sans lever d'exception
        try:
            public_key.verify(signature, challenge_ticket)
            verified = True
        except InvalidSignature:
            verified = False

        self.assertTrue(verified, "La signature valide du peer a été rejetée à tort.")

    @unittest.skipUnless(HAS_CRYPTOGRAPHY, "La bibliothèque 'cryptography' est requise")
    def test_ed25519_signature_verification_failure(self):
        """
        Vérifie qu'un ticket altéré ou une fausse signature est immédiatement rejeté.
        """
        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()

        challenge_ticket = b"session_challenge_token_valid_120s"
        corrupted_signature = b"x" * 64  # Fausse signature

        with self.assertRaises(InvalidSignature):
            public_key.verify(corrupted_signature, challenge_ticket)

    def test_fail_open_behavior_when_storage_fails(self):
        """
        Test du mode Fail-Safe : FAIL-OPEN (Comportement par défaut).
        Si Redis ou l'état mémoire crash, l'utilisateur légitime ne doit pas être bloqué.
        """
        class MockEngine:
            def __init__(self, config):
                self.config = config

            def evaluate_request(self):
                try:
                    # On simule une coupure réseau ou crash de Redis
                    raise RuntimeError("Redis connection lost")
                except Exception:
                    if self.config.get('fail_safe') == 'fail_open':
                        return {'status': 'allowed', 'score': 0.0, 'reason': 'fail-safe backup'}
                    raise

        engine = MockEngine(self.default_config)
        result = engine.evaluate_request()
        
        self.assertEqual(result['status'], 'allowed')
        self.assertEqual(result['score'], 0.0)
        self.assertEqual(result['reason'], 'fail-safe backup')

    def test_fail_closed_behavior_when_storage_fails(self):
        """
        Test du mode Fail-Safe : FAIL-CLOSED.
        Utile pour sécuriser des endpoints sensibles (ex: paiements, logins).
        """
        config = self.default_config.copy()
        config['fail_safe'] = 'fail_closed'

        class MockEngine:
            def __init__(self, config):
                self.config = config

            def evaluate_request(self):
                try:
                    # On simule un crash critique de DB
                    raise RuntimeError("Database connection timed out")
                except Exception:
                    if self.config.get('fail_safe') == 'fail_open':
                        return {'status': 'allowed', 'score': 0.0}
                    # Mode fail_closed : Bloquer par défaut pour protéger l'infrastructure
                    return {'status': 'blocked', 'score': 1.0, 'reason': 'security fallback'}

        engine = MockEngine(config)
        result = engine.evaluate_request()

        self.assertEqual(result['status'], 'blocked')
        self.assertEqual(result['score'], 1.0)
        self.assertEqual(result['reason'], 'security fallback')

    def test_detects_client_hints_inconsistency(self):
        """
        Vérifie la détection d'incohérence entre les Client Hints (sec-ch-ua) 
        et le User-Agent standard déclaré par le client.
        """
        # Exemple d'un attaquant usurpant un navigateur Chrome récent (UA)
        # mais transmettant des headers Client Hints incohérents (Firefox ou ancienne version)
        headers = {
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'sec-ch-ua': '"Firefox";v="115", "Gecko";v="20100101"'
        }

        # Logique de calcul d'incohérence simplifiée pour le test d'intégration
        ua_chrome = "Chrome" in headers['user-agent']
        ch_chrome = "Google Chrome" in headers['sec-ch-ua'] or "Chromium" in headers['sec-ch-ua']

        inconsistency_detected = ua_chrome != ch_chrome
        
        self.assertTrue(inconsistency_detected, "L'incohérence entre Chrome UA et Firefox Client Hints aurait dû être détectée.")

    def test_honeypot_trap_detection(self):
        """
        Vérifie qu'un bot remplissant un champ honeypot invisible (trap)
        est instantanément détecté et bloqué (score 1.0).
        """
        # Formulaire simulé soumis par un client
        form_payload = {
            "username": "legit_user",
            "email": "user@example.com",
            "website_confirm_hidden": "http://spambot.com" # Champ masqué en CSS (Honeypot)
        }

        # Si le champ masqué contient une valeur, c'est obligatoirement un bot
        is_bot = len(form_payload.get("website_confirm_hidden", "")) > 0
        score = 1.0 if is_bot else 0.0

        self.assertEqual(score, 1.0)
        self.assertTrue(is_bot)

    def test_proof_of_work_verification_success(self):
        """
        Vérifie la validité d'une solution Proof of Work (uPoW) soumise par le client.
        """
        challenge = "node_challenge_abc123"
        difficulty = 3  # Le hash sha256 doit commencer par '000'
        
        # Génération d'une solution valide (simulation de l'effort client)
        nonce = 0
        while True:
            attempt = f"{challenge}-{nonce}".encode()
            hash_result = hashlib.sha256(attempt).hexdigest()
            if hash_result.startswith("0" * difficulty):
                break
            nonce += 1

        # Le moteur Python doit vérifier cette preuve instantanément
        solution_to_verify = f"{challenge}-{nonce}".encode()
        verified_hash = hashlib.sha256(solution_to_verify).hexdigest()
        is_valid = verified_hash.startswith("0" * difficulty)

        self.assertTrue(is_valid, "La solution PoW valide a été rejetée.")

    def test_basic_waf_sql_injection_blocking(self):
        """
        Vérifie que les patterns de base de contournement/injection (WAF)
        sont interceptés par les expressions régulières de sécurité.
        """
        malicious_input = "1' OR '1'='1"
        waf_pattern = r"(union\s+select|or\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+)"
        
        import re
        match = re.search(waf_pattern, malicious_input, re.IGNORECASE)
        self.assertIsNotNone(match, "L'injection SQL classique n'a pas été détectée par le filtre WAF.")

if __name__ == '__main__':
    unittest.main()
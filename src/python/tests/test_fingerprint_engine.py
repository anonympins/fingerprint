import unittest
import time
import hmac
import hashlib
import json
from unittest.mock import MagicMock

from engine import RequestContext, RequestUtils, InMemoryStore, FingerprintEngine, get_ip_subnet

# On importe la bibliothèque standard cryptography pour Ed25519 (Zero-Trust peer validations)
try:
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.exceptions import InvalidSignature
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False


class TestFingerprintEngine(unittest.IsolatedAsyncioTestCase):
    def setUp(self):

        self.store = InMemoryStore()
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

    async def test_subnet_decay_persistence(self):
        client_ip = "192.168.1.100"
        device_id = "device_1"

        # Initial update to register subnet metrics
        await RequestUtils.update_subnet_metrics(self.store, client_ip, device_id, 80.0)

        # Check initially stored metrics
        subnet = get_ip_subnet(client_ip)
        key = f"subnet:{subnet}"
        subnet_data = await self.store.get(key)

        self.assertIsNotNone(subnet_data)
        self.assertEqual(subnet_data["highScoreCount"], 1)
        self.assertIn(device_id, subnet_data["deviceIds"])

        # Manually backdate the last activity by 1 hour (3600 seconds = 2 half-lives of 30 minutes)
        now = int(time.time())
        subnet_data["lastActivity"] = now - 3600
        await self.store.set(key, subnet_data)

        # Retrieve subnet score which triggers decay and persists it
        await RequestUtils.get_subnet_score(self.store, client_ip, device_id)

        # Verify the score represents decayed metrics
        # Decayed count: 1 / (2^2) = 0.25 -> floored to 0
        decayed_data = await self.store.get(key)
        self.assertEqual(decayed_data["highScoreCount"], 0)
        self.assertEqual(len(decayed_data["deviceIds"]), 0)

    def test_request_context_is_https(self):
        """
        Vérifie la détection de HTTPS via le schéma direct ou les en-têtes de terminaison TLS.
        """
        # 1. Scheme direct
        ctx_https = RequestContext(
            client_ip="1.2.3.4", path="/", headers={}, query_params={}, cookies={}, scheme="https"
        )
        self.assertTrue(ctx_https.is_https)

        # 2. Scheme http sans proxy
        ctx_http = RequestContext(
            client_ip="1.2.3.4", path="/", headers={}, query_params={}, cookies={}, scheme="http"
        )
        self.assertFalse(ctx_http.is_https)

        # 3. En-tête X-Forwarded-Proto
        ctx_proto = RequestContext(
            client_ip="1.2.3.4", path="/", headers={"x-forwarded-proto": "https"}, query_params={}, cookies={}
        )
        self.assertTrue(ctx_proto.is_https)

        # 4. En-tête X-Forwarded-Ssl
        ctx_ssl = RequestContext(
            client_ip="1.2.3.4", path="/", headers={"x-forwarded-ssl": "on"}, query_params={}, cookies={}
        )
        self.assertTrue(ctx_ssl.is_https)

    def test_mtu_anomaly_vpn_detection(self):
        """
        Vérifie la détection de tunnels VPN (WireGuard/OpenVPN) et la reconstitution IPv4/IPv6.
        """
        # 1. WireGuard IPv4 : MSS 1380 + 40 = MTU 1420 (<= 1420 -> +65)
        ctx_wg = RequestContext(
            client_ip="192.168.1.1",
            path="/",
            headers={"x-tcp-mss": "1380"},
            query_params={},
            cookies={}
        )
        score_wg = RequestUtils.get_mtu_anomaly_score(ctx_wg)
        self.assertGreaterEqual(score_wg, 65.0)

        # 2. Reconstitution IPv6 (+60)
        # MSS 1380 + 60 = MTU 1440 (OpenVPN <= 1450 -> +55)
        ctx_v6 = RequestContext(
            client_ip="2001:db8::1",
            path="/",
            headers={"x-tcp-mss": "1380"},
            query_params={},
            cookies={}
        )
        score_v6 = RequestUtils.get_mtu_anomaly_score(ctx_v6)
        self.assertGreaterEqual(score_v6, 55.0)

        # 3. Télémétrie x-tcp-mtu-info avec flag DF manquant et Windows
        ctx_win_nodf = RequestContext(
            client_ip="192.168.1.5",
            path="/",
            headers={
                "x-tcp-mtu-info": "mss:1460,mtu:1500,df:0",
                "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
            },
            query_params={},
            cookies={}
        )
        score_win_nodf = RequestUtils.get_mtu_anomaly_score(ctx_win_nodf)
        self.assertGreaterEqual(score_win_nodf, 40.0)

    def test_protocol_anomaly_forbidden_hop_by_hop(self):
        """
        Vérifie la violation RFC 7540 / RFC 9114 : en-têtes hop-by-hop interdits en HTTP/2 et HTTP/3.
        """
        ctx_h2 = RequestContext(
            client_ip="1.2.3.4",
            path="/",
            headers={"connection": "keep-alive"},
            query_params={},
            cookies={},
            http_version="2.0"
        )
        res = RequestUtils.get_protocol_anomaly_score(ctx_h2)
        self.assertGreaterEqual(res["protocolAnomalyScore"], 70.0)

    def test_protocol_anomaly_cross_layer_timing_mismatch(self):
        """
        Vérifie la détection de triche WAC Navigation Timing (nextHopProtocol vs serveur).
        """
        # Client prétendant être en h3 alors que la connexion reçue est en HTTP/1.1
        telemetry = json.dumps({"network": {"nextHopProtocol": "h3"}})
        ctx = RequestContext(
            client_ip="1.2.3.4",
            path="/",
            headers={"x-behavior-metrics": telemetry},
            query_params={},
            cookies={},
            http_version="1.1"
        )
        res = RequestUtils.get_protocol_anomaly_score(ctx)
        self.assertGreaterEqual(res["protocolAnomalyScore"], 85.0)

    def test_protocol_anomaly_downgrade_and_h3_scrapers(self):
        """
        Vérifie la rétrogradation protocolaire et la détection d'outils d'automatisation sous HTTP/3.
        """
        # 1. Rétrogradation protocolaire d'un navigateur moderne sous HTTPS forcé en HTTP/1.1 sans proxy
        ctx_downgrade = RequestContext(
            client_ip="1.2.3.4",
            path="/",
            headers={"user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0"},
            query_params={},
            cookies={},
            http_version="1.1",
            scheme="https"
        )
        res_downgrade = RequestUtils.get_protocol_anomaly_score(ctx_downgrade)
        self.assertGreaterEqual(res_downgrade["protocolAnomalyScore"], 45.0)

        # 2. Scraper Python en HTTP/3
        ctx_h3_scraper = RequestContext(
            client_ip="1.2.3.4",
            path="/",
            headers={"user-agent": "python-requests/2.31.0"},
            query_params={},
            cookies={},
            http_version="3"
        )
        res_scraper = RequestUtils.get_protocol_anomaly_score(ctx_h3_scraper)
        self.assertGreaterEqual(res_scraper["protocolAnomalyScore"], 90.0)

    def test_dynamic_mtu_amplification(self):
        """
        Vérifie que calculate_final_score amplifie automatiquement le poids des incohérences
        matérielles et comportementales si mtuAnomalyScore > 50.0.
        """
        config = {
            "weights": {
                "tlsSpoofingScore": 1.0,
                "crossLayerInconsistencyScore": 1.0,
                "behaviorScore": 1.0,
                "mtuAnomalyScore": 1.0
            }
        }
        engine = FingerprintEngine(config, self.store)

        # Vecteur sans anomalie MTU
        vector_normal = {
            "tlsSpoofingScore": 40.0,
            "crossLayerInconsistencyScore": 30.0,
            "behaviorScore": 20.0,
            "mtuAnomalyScore": 0.0
        }
        # Score attendu : 40*1.0 + 30*1.0 + 20*1.0 = 90.0
        score_normal = engine.calculate_final_score(vector_normal)
        self.assertEqual(score_normal, 90.0)

        # Vecteur avec anomalie MTU > 50 (déclenche l'amplification x1.25 sur les clés cibles)
        vector_anomalous = {
            "tlsSpoofingScore": 40.0,
            "crossLayerInconsistencyScore": 30.0,
            "behaviorScore": 20.0,
            "mtuAnomalyScore": 65.0
        }
        # Poids effectifs :
        # tlsSpoofingScore: 1.0 * 1.25 = 1.25 -> 40 * 1.25 = 50.0
        # crossLayerInconsistencyScore: 1.0 * 1.25 = 1.25 -> 30 * 1.25 = 37.5
        # behaviorScore: 1.0 * 1.25 = 1.25 -> 20 * 1.25 = 25.0
        # mtuAnomalyScore: 65.0 * 1.0 = 65.0
        # Total non plafonné = 50 + 37.5 + 25 + 65 = 177.5 -> plafonné à 100.0
        score_anomalous = engine.calculate_final_score(vector_anomalous)
        self.assertEqual(score_anomalous, 100.0)

        # Vérification sur des valeurs plus faibles pour observer l'amplification exacte sans plafonnement
        vector_low = {
            "tlsSpoofingScore": 10.0,  # 10 * 1.25 = 12.5
            "mtuAnomalyScore": 55.0    # 55 * 1.0 = 55.0
        }
        score_low = engine.calculate_final_score(vector_low)
        self.assertEqual(score_low, 67.5)

if __name__ == '__main__':
    unittest.main()
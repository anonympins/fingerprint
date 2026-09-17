import unittest
import sys
import os

# Ajout du chemin d'accès pour importer le module engine
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../src/python')))

from engine import FingerprintEngine, RequestContext, InMemoryStore

class TestFingerprintEngine(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        # Configuration de sécurité type "balanced" pour les tests
        self.config = {
            "thresholds": {"low": 20, "high": 75, "block": 95},
            "weights": {
                "inconsistencyScore": 0.8,
                "headerAnomalyScore": 0.1,
                "clientHintsInconsistencyScore": 0.7,
                "tlsSpoofingScore": 0.8,
                "botScore": 1.0,
                "honeypotScore": 1.0,
                "quicAnomalyScore": 0.8,
                "renderingAnomalyScore": 0.8,
            },
            "honeypot": {
                "fields": ["email_confirm"],
                "trapUrls": ["/wp-admin", "/.env"]
            },
            "similarityThreshold": 0.7
        }
        self.store = InMemoryStore()
        self.engine = FingerprintEngine(self.config, self.store)

    async def test_store_operations(self):
        """Teste le bon fonctionnement asynchrone du InMemoryStore."""
        key = "session_test"
        value = {"user": "alice", "role": "admin"}
        
        # Insertion et vérification de présence
        await self.store.set(key, value, ttl=10)
        self.assertTrue(await self.store.has(key))
        
        # Récupération et comparaison
        stored_val = await self.store.get(key)
        self.assertEqual(stored_val, value)
        
        # Suppression
        await self.store.delete(key)
        self.assertFalse(await self.store.has(key))
        self.assertIsNone(await self.store.get(key))

    async def test_request_context_normalization(self):
        """Vérifie la normalisation en minuscules des en-têtes HTTP."""
        context = RequestContext(
            client_ip="127.0.0.1",
            path="/test",
            headers={"User-Agent": "TestAgent", "X-Custom-Header": "Value"},
            query_params={},
            cookies={}
        )
        # Les clés d'en-têtes doivent être automatiquement converties en minuscules
        self.assertIn("user-agent", context.headers)
        self.assertEqual(context.headers["user-agent"], "TestAgent")
        self.assertIn("x-custom-header", context.headers)
        self.assertEqual(context.headers["x-custom-header"], "Value")

    async def test_legitimate_request_passes(self):
        """Vérifie qu'un navigateur standard et légitime passe sans encombre."""
        context = RequestContext(
            client_ip="192.168.1.100",
            path="/",
            headers={
                "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                "accept-language": "fr-FR,fr;q=0.9,en;q=0.8"
            },
            query_params={},
            cookies={}
        )
        decision = await self.engine.process_request(context)
        
        # Un utilisateur légitime ne doit pas être bloqué ni challengé
        self.assertEqual(decision["action"], "next")
        self.assertIn("newCookieForResponse", decision)

    async def test_honeypot_url_blocks_immediately(self):
        """Vérifie qu'un accès direct à une URL piège (honeypot) bloque instantanément l'IP."""
        context = RequestContext(
            client_ip="203.0.113.5",
            path="/.env",  # Configuré dans les trapUrls
            headers={
                "user-agent": "curl/7.68.0"
            },
            query_params={},
            cookies={}
        )
        decision = await self.engine.process_request(context)
        
        # L'action attendue doit être un blocage direct (code HTTP 403)
        self.assertEqual(decision["action"], "block")
        self.assertEqual(decision["status"], 403)
        self.assertEqual(decision["body"], "Forbidden")

        # Simulation d'une seconde requête légitime depuis la même IP
        # pour vérifier l'effet mémoire du bouclier thermique (Fast-Path Cache)
        context_follow_up = RequestContext(
            client_ip="203.0.113.5",
            path="/index.html",
            headers={"user-agent": "Mozilla/5.0"},
            query_params={},
            cookies={}
        )
        decision_follow_up = await self.engine.process_request(context_follow_up)
        self.assertEqual(decision_follow_up["action"], "block")

if __name__ == "__main__":
    unittest.main()
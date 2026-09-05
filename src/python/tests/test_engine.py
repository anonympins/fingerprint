import sys
import asyncio
from pathlib import Path
import pytest

# Ajoute le dossier parent au sys.path pour pouvoir importer le module engine de manière fiable
sys.path.append(str(Path(__file__).parent.parent))

from engine import (
    imul,
    cyrb53,
    RequestContext,
    InMemoryStore,
    FingerprintBuilder,
    ChallengeUtils,
    RequestUtils,
    FingerprintEngine,
    ASGIFingerprintMiddleware,
    WSGIFingerprintMiddleware,
)

# --- TESTS: UTILS & HASHING ---

def test_imul_precision():
    """Vérifie l'émulation JS Math.imul pour les entiers 32-bits signés."""
    assert imul(0, 0) == 0
    assert imul(1, 1) == 1
    assert imul(-1, 1) == -1
    # Test de dépassement de capacité (overflow)
    assert imul(0x7fffffff, 2) == -2
    assert imul(0xffffffff, 0xffffffff) == 1

def test_cyrb53_determinism():
    """Vérifie que le hachage cyrb53 est bien déterministe."""
    val = "test-string-for-fingerprint"
    assert cyrb53(val) == cyrb53(val)
    assert cyrb53("a") != cyrb53("b")
    assert cyrb53("", seed=42) != cyrb53("", seed=0)
    
    # Test de stabilité avec de légères variations
    h1 = cyrb53("user-agent-1")
    h2 = cyrb53("user-agent-2")
    assert h1 != h2
    
    # Vérifie que la valeur est dans les limites de précision JS (53 bits)
    assert 0 <= h1 < (2**53)

def test_request_context_defaults():
    """Vérifie l'initialisation par défaut du RequestContext."""
    context = RequestContext(client_ip="1.1.1.1", path="/", headers={}, query_params={}, cookies={})
    assert context.http_version == "1.1"


# --- TESTS: STORAGE ---

@pytest.mark.asyncio
async def test_in_memory_store_lifecycle():
    """Vérifie le cycle de vie (get, set, has, delete) de l'InMemoryStore."""
    store = InMemoryStore()
    
    # Test d'insertion et récupération de base
    await store.set("test_key", "value123")
    assert await store.get("test_key") == "value123"
    assert await store.has("test_key") is True

    # Test de suppression
    assert await store.get("non_existent") is None
    assert await store.has("non_existent") is False
    
    await store.delete("test_key")
    assert await store.get("test_key") is None
    assert await store.has("test_key") is False
    # Double suppression sécurisée
    await store.delete("test_key")

@pytest.mark.asyncio
async def test_in_memory_store_ttl():
    """Vérifie que le mécanisme d'expiration TTL fonctionne correctement."""
    store = InMemoryStore()
    
    # On configure une clé avec un TTL d'une seconde
    await store.set("ttl_key", "volatile", ttl=1)
    assert await store.get("ttl_key") == "volatile"
    assert await store.has("ttl_key") is True
    
    # On attend l'expiration
    await asyncio.sleep(1.1)
    assert await store.get("ttl_key") is None
    assert await store.has("ttl_key") is False
    
    # Remplacement d'une clé avec suppression de son TTL
    await store.set("ttl_key_2", "persistent", ttl=1)
    await store.set("ttl_key_2", "persistent_forever")
    await asyncio.sleep(1.1)
    assert await store.get("ttl_key_2") == "persistent_forever"


# --- TESTS: FINGERPRINT BUILDER ---

def test_fingerprint_builder_handling():
    """Vérifie la création et la comparaison d'empreintes digitales."""
    builder = FingerprintBuilder()
    builder.add("ua", "Mozilla/5.0")
    builder.add("gpu", "Nvidia")
    builder.add("empty_field", None)  # Devrait être ignoré silencieusement

    fp_str = str(builder)
    assert "ua:" in fp_str
    assert "gpu:" in fp_str
    assert "empty_field:" not in fp_str
    assert "|" in fp_str  # Séparateur de composants

def test_fingerprint_builder_order_independence():
    """L'ordre d'appel à `add` ne doit pas affecter l'empreinte finale calculée."""
    fp1 = FingerprintBuilder().add("a", "1").add("b", "2")
    fp2 = FingerprintBuilder().add("b", "2").add("a", "1")
    assert str(fp1) == str(fp2)
    assert FingerprintBuilder.compare(str(fp1), str(fp2)) == 1.0

def test_fingerprint_builder_comparison():
    """Vérifie la logique de comparaison de similarité entre empreintes."""
    fp1 = FingerprintBuilder().add("ua", "Mozilla/5.0").add("gpu", "Nvidia").add("hw", "8_16")
    fp2 = FingerprintBuilder().add("ua", "Mozilla/5.0").add("gpu", "Nvidia").add("hw", "8_16")
    fp3 = FingerprintBuilder().add("ua", "Mozilla/5.0").add("gpu", "AMD").add("hw", "4_8")

    assert FingerprintBuilder.compare(str(fp1), str(fp2)) == 1.0  # Identiques
    assert FingerprintBuilder.compare(str(fp1), str(fp3)) < 0.6   # Différents
    assert FingerprintBuilder.compare(str(fp1), "") == 0.0        # Vide
    assert FingerprintBuilder.compare("", str(fp1)) == 0.0        # Vide inverse

def test_fingerprint_builder_volatile_exclusion():
    """Vérifie que les clés volatiles n'impactent pas le calcul de similarité."""
    fp1 = FingerprintBuilder().add("ua", "Mozilla/5.0").add("ch_ua", "OldChrome")
    fp2 = FingerprintBuilder().add("ua", "Mozilla/5.0").add("ch_ua", "NewChrome")
    
    # Bien que ch_ua diffère, ils doivent être vus comme identiques (similarité = 1.0)
    assert FingerprintBuilder.compare(str(fp1), str(fp2)) == 1.0
    
    # Test de clés purement volatiles
    assert FingerprintBuilder.compare("ch_ua:1", "ch_ua:2") == 0.0


# --- TESTS: CHALLENGES (PoW) ---

def test_cpu_pow_target_generation_and_verification():
    """Vérifie le calcul de la cible CPU PoW et sa vérification."""
    # Plus le facteur de suspicion est grand, plus la cible doit être petite (difficile)
    target_easy = ChallengeUtils.calculate_cpu_target(0.1)
    target_hard = ChallengeUtils.calculate_cpu_target(0.9)
    assert int(target_easy, 16) > int(target_hard, 16)
    
    # Cas extrêmes de suspicion
    target_min = ChallengeUtils.calculate_cpu_target(0.0)
    target_max = ChallengeUtils.calculate_cpu_target(1.0)
    assert int(target_min, 16) > int(target_max, 16)
    
    # Comportement avec des valeurs hors bornes ou incorrectes
    target_neg = ChallengeUtils.calculate_cpu_target(-1.0)
    assert len(target_neg) == 64

    # Résolution d'un challenge trivial (cible très haute)
    base_block = b"test-nonce-challenge:"
    target_trivial = "f" * 64
    
    # 0 est normalement une solution valide pour une cible aussi simple
    assert ChallengeUtils.verify_cpu_pow(base_block, target_trivial, "0") is True 
    assert ChallengeUtils.verify_cpu_pow(base_block, "0000000000000000000000000000000000000000000000000000000000000000", "0") is False

def test_cpu_pow_verification_failures():
    """Vérifie la robustesse face à des paramètres erronés ou corrompus pour le PoW CPU."""
    base_block = b"xyz"
    target = "000000ffffffffff" + "f"*48
    
    # Solution invalide (type incompatible ou non numérique)
    assert ChallengeUtils.verify_cpu_pow(base_block, target, "not-an-int") is False
    
    # Erreur interne / target vide
    assert ChallengeUtils.verify_cpu_pow(base_block, "", "123") is False

    # Target non hexadécimale
    assert ChallengeUtils.verify_cpu_pow(base_block, "zzzzzz", "12") is False


def test_memory_pow_verification():
    """Vérifie l'exécution théorique et la validation du PoW mémoire."""
    nonce = "test-nonce"
    client_secret = "test-secret"
    
    # Sur une difficulté très faible de 1 MB, on résout et vérifie
    # (Simule une résolution simplifiée pour valider l'exactitude mathématique)
    assert ChallengeUtils.verify_memory_pow(nonce, "999999", 0, client_secret) is True
    
    # Avec une difficulté réelle de 1 MB
    # Le test ne cherche pas à résoudre un PoW coûteux, mais vérifie qu'une mauvaise solution échoue
    assert ChallengeUtils.verify_memory_pow(nonce, "-999", 1, client_secret) is False
    
    # Erreur de type sur la solution
    assert ChallengeUtils.verify_memory_pow(nonce, "invalid_int", 1, client_secret) is False



# --- TESTS: REQUEST ANALYSIS UTILITIES ---

def test_user_agent_parsing():
    """Vérifie l'extraction de l'OS et du navigateur depuis le User-Agent."""
    chrome_ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    parsed = RequestUtils.parse_user_agent(chrome_ua)
    assert parsed["browser"].startswith("Chrome")
    assert parsed["os"] == "Windows 10"
    assert parsed["device"] == "desktop"

    # Test d'autres agents courants
    firefox_ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/115.0"
    parsed_ff = RequestUtils.parse_user_agent(firefox_ua)
    assert parsed_ff["browser"].startswith("Firefox")
    assert parsed_ff["os"] == "macOS"
    
    safari_ua = "Mozilla/5.0 (iPhone; CPU iPhone OS 16_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5 Mobile/15E148 Safari/604.1"
    parsed_saf = RequestUtils.parse_user_agent(safari_ua)
    assert parsed_saf["browser"].startswith("Safari")
    assert parsed_saf["os"] == "iOS"
    assert parsed_saf["device"] == "mobile"

    edge_ua = "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Mobile Safari/537.36 EdgA/114.0.1823.57"
    parsed_edge = RequestUtils.parse_user_agent(edge_ua)
    assert parsed_edge["browser"].startswith("Edge")
    assert parsed_edge["os"] == "Android"
    assert parsed_edge["device"] == "mobile"

def test_header_anomalies_detection():
    """Vérifie que les anomalies majeures d'en-têtes HTTP sont pénalisées."""
    # Requête saine
    context_clean = RequestContext(
        client_ip="127.0.0.1",
        path="/",
        headers={
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
            "accept-language": "fr-FR",
        },
        query_params={},
        cookies={}
    )
    assert RequestUtils.get_header_anomalies(context_clean) == 0.0

    # Requête suspecte (User-Agent trop court, pas d'accept-language)
    context_suspect = RequestContext(
        client_ip="127.0.0.1", path="/", headers={"user-agent": "curl"}, query_params={}, cookies={}
    )
    assert RequestUtils.get_header_anomalies(context_suspect) > 50.0

def test_header_anomalies_specific_firefox():
    """Vérifie les pénalités spécifiques concernant le header 'TE' pour Firefox Desktop."""
    # Firefox desktop sain DOIT avoir "te: trailers"
    ff_sain = RequestContext(
        client_ip="1.1.1.1", path="/",
        headers={
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0",
            "accept-language": "fr",
            "te": "trailers"
        }, query_params={}, cookies={}
    )
    assert RequestUtils.get_header_anomalies(ff_sain) == 0.0

    # Firefox desktop sans "te: trailers" est suspect (+30.0)
    ff_suspect = RequestContext(
        client_ip="1.1.1.1", path="/",
        headers={
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0",
            "accept-language": "fr",
            "te": ""
        }, query_params={}, cookies={}
    )
    assert RequestUtils.get_header_anomalies(ff_suspect) >= 30.0

def test_client_hints_inconsistency_detection():
    """Vérifie la détection d'incohérence entre les Client Hints et le User-Agent."""
    # Cohérent
    context_ok = RequestContext(
        client_ip="127.0.0.1", path="/",
        headers={
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0",
            "sec-ch-ua": '"Google Chrome";v="120", "Chromium";v="120"'
        }, query_params={}, cookies={}
    )
    assert RequestUtils.get_client_hints_inconsistency(context_ok) == 0.0
    # Pas d'UA ou pas de hints
    assert RequestUtils.get_client_hints_inconsistency(RequestContext("1.1.1.1", "/", {}, {}, {})) == 0.0

def test_honeypot_score():
    """Vérifie le déclenchement immédiat des pièges Honeypot."""
    config = {
        "fields": ["email_confirm"],
        "trapUrls": ["/wp-admin"]
    }
    
    # Accès à une URL interdite
    context_trap = RequestContext(
        client_ip="127.0.0.1", path="/wp-admin/login.php", headers={}, query_params={}, cookies={}
    )
    assert RequestUtils.get_honeypot_score(context_trap, config) == 100.0

    # Remplissage d'un champ invisible caché
    context_field = RequestContext(
        client_ip="127.0.0.1", path="/", headers={}, query_params={}, cookies={},
        body={"email_confirm": "crawler@bot.com"}
    )
    assert RequestUtils.get_honeypot_score(context_field, config) == 100.0

    # Ne doit pas déclencher sur les paramètres commençant par pow_ (CPU challenge)
    context_pow = RequestContext(
        client_ip="127.0.0.1", path="/", headers={}, query_params={}, cookies={},
        body={"pow_nonce": "1234"}
    )
    assert RequestUtils.get_honeypot_score(context_pow, config) == 0.0

def test_bot_score_detection():
    """Vérifie l'identification de bots à partir des headers ou extensions d'analyse."""
    context_bot = RequestContext(
        client_ip="1.1.1.1", path="/",
        headers={"x-device-fingerprint": "bot:true|cvs:123"},
        query_params={}, cookies={}
    )
    assert RequestUtils.get_bot_score(context_bot) == 100.0
    
    context_cdp = RequestContext(
        client_ip="1.1.1.1", path="/",
        headers={"x-device-fingerprint": "cdp:true"},
        query_params={}, cookies={}
    )
    assert RequestUtils.get_bot_score(context_cdp) == 100.0
    
    context_clean = RequestContext("1.1.1.1", "/", {}, {}, {})
    assert RequestUtils.get_bot_score(context_clean) == 0.0


# --- TESTS: ENGINE INTEGRATION ---

@pytest.mark.asyncio
async def test_engine_process_request_lifecycle():
    """Vérifie qu'un humain normal passe sans encombres."""
    config = {
        "thresholds": {"low": 20, "high": 75, "block": 95},
        "weights": {"honeypotScore": 1.0, "headerAnomalyScore": 0.5}
    }
    store = InMemoryStore()
    engine = FingerprintEngine(config, store)
    
    context = RequestContext(
        client_ip="127.0.0.1",
        path="/",
        headers={
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
            "accept-language": "fr-FR"
        },
        query_params={},
        cookies={}
    )
    
    decision = await engine.process_request(context)
    assert decision["action"] == "next"
    
    # Vérifie la persistence de l'identité
    identity = await engine.resolve_identity(context)
    assert identity["device_id"] is not None
    assert len(identity["device_data"]["ips"]) == 1

@pytest.mark.asyncio
async def test_engine_process_request_blocked():
    """Vérifie qu'un bot agressif est immédiatement bloqué."""
    config = {
        "thresholds": {"low": 20, "high": 75, "block": 95},
        "weights": {"honeypotScore": 1.0},
        "honeypot": {"trapUrls": ["/.env"]}
    }
    store = InMemoryStore()
    engine = FingerprintEngine(config, store)
    
    context = RequestContext(
        client_ip="127.0.0.1",
        path="/.env",
        headers={"user-agent": "curl/7.68.0"},
        query_params={},
        cookies={}
    )
    
    decision = await engine.process_request(context)
    assert decision["action"] == "block"
    assert decision["status"] == 403

@pytest.mark.asyncio
async def test_engine_process_request_challenge_generation():
    """Vérifie que l'évaluation génère correctement un challenge PoW si score suspicieux modéré."""
    config = {
        "thresholds": {"low": 10, "high": 60, "block": 90},
        "weights": {"headerAnomalyScore": 1.0},
    }
    store = InMemoryStore()
    engine = FingerprintEngine(config, store)
    
    # Doit déclencher un score de suspicion d'en-tête (pas d'accept-lang, UA court)
    context = RequestContext(
        client_ip="1.2.3.4",
        path="/restricted",
        headers={"user-agent": "curl/7.0"},
        query_params={},
        cookies={}
    )
    
    decision = await engine.process_request(context)
    assert decision["action"] == "challenge"
    assert decision["status"] == 403
    assert "pow_nonce" in decision["body"]

@pytest.mark.asyncio
async def test_engine_process_request_condemned_device():
    """Vérifie qu'un terminal banni par le passé (condemned) est systématiquement bloqué."""
    config = {"thresholds": {"low": 20, "block": 95}}
    store = InMemoryStore()
    engine = FingerprintEngine(config, store)
    
    # Initialisation de l'identité bannie
    device_id = "condemned-uuid"
    await store.set(f"device:{device_id}", {
        "initialDeviceHash": "some-hash",
        "ips": {"1.1.1.1"},
        "condemned": True,
        "lastUpdate": 12345
    })
    
    context = RequestContext(
        client_ip="1.1.1.1", path="/", headers={}, query_params={},
        cookies={"device_id": device_id}
    )
    
    decision = await engine.process_request(context)
    assert decision["action"] == "block"

@pytest.mark.asyncio
async def test_engine_suspicion_score_ja3_spoofing():
    """Vérifie l'évaluation de suspicion lors d'une inadéquation JA3 / User-Agent."""
    config = {
        "thresholds": {"low": 20, "block": 95},
        "weights": {"tlsSpoofingScore": 1.0},
    }
    store = InMemoryStore()
    engine = FingerprintEngine(config, store)

    # UA Firefox mais JA3 associé typiquement à Safari ou Chrome
    context = RequestContext(
        client_ip="1.2.3.4", path="/",
        headers={
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0",
            "x-ja3-hash": "b633f21d532d35967c8753c38536b4d3"  # Empreinte TLS de Safari
        }, query_params={}, cookies={}
    )
    
    score = await engine.get_suspicion_score(context)
    # Devrait renvoyer un score élevé d'usurpation TLS
    assert score > 50.0


# --- TESTS: MIDDLEWARES (ASGI & WSGI MOCKS) ---

@pytest.mark.asyncio
async def test_asgi_middleware_flow():
    """Simule un flux complet de requêtes à travers ASGIFingerprintMiddleware."""
    calls = []
    
    async def mock_app(scope, receive, send):
        calls.append("app_called")
        await send({
            "type": "http.response.start",
            "status": 200,
            "headers": [(b"content-type", b"text/plain")]
        })
        await send({
            "type": "http.response.body",
            "body": b"Hello world"
        })

    config = {
        "thresholds": {"low": 30, "high": 75, "block": 95},
        "weights": {"honeypotScore": 1.0},
        "honeypot": {"trapUrls": ["/.env"]}
    }
    middleware = ASGIFingerprintMiddleware(mock_app, security_config=config)
    
    # --- Scénario 1 : Requête légitime de base ---
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/",
        "headers": [
            (b"user-agent", b"Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0"),
            (b"accept-language", b"fr")
        ],
        "query_string": b""
    }
    
    events_sent = []
    async def mock_send(event):
        events_sent.append(event)
        
    async def mock_receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    await middleware(scope, mock_receive, mock_send)
    
    assert "app_called" in calls
    # Vérifie que le cookie d'identité est bien injecté à la volée dans la réponse
    start_event = next(e for e in events_sent if e["type"] == "http.response.start")
    headers_dict = dict(start_event["headers"])
    assert b"set-cookie" in headers_dict
    assert b"device_id" in headers_dict[b"set-cookie"]

    # --- Scénario 2 : Requête bloquée (Accès Honeypot) ---
    calls.clear()
    events_sent.clear()
    
    scope_malicious = {
        "type": "http",
        "method": "GET",
        "path": "/.env",
        "headers": [(b"user-agent", b"curl/7.82")],
        "query_string": b""
    }
    
    await middleware(scope_malicious, mock_receive, mock_send)
    assert "app_called" not in calls # L'application sous-jacente ne doit pas être contactée
    assert any(e["type"] == "http.response.start" and e["status"] == 403 for e in events_sent)


def test_wsgi_middleware_flow():
    """Simule un flux complet de requêtes à travers WSGIFingerprintMiddleware."""
    app_called = False
    
    def mock_app(environ, start_response):
        nonlocal app_called
        app_called = True
        start_response("200 OK", [("Content-Type", "text/plain")])
        return [b"Flask response"]

    config = {
        "thresholds": {"low": 30, "high": 75, "block": 95},
        "weights": {"honeypotScore": 1.0},
        "honeypot": {"trapUrls": ["/.env"]}
    }
    
    middleware = WSGIFingerprintMiddleware(mock_app, security_config=config)
    
    # Mock start_response WSGI
    response_status = None
    response_headers = []
    
    def start_response(status, headers, exc_info=None):
        nonlocal response_status, response_headers
        response_status = status
        response_headers = headers

    # --- Scénario 1 : Légitime ---
    environ = {
        "REQUEST_METHOD": "GET",
        "PATH_INFO": "/",
        "QUERY_STRING": "",
        "HTTP_USER_AGENT": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
        "HTTP_ACCEPT_LANGUAGE": "fr",
        "SERVER_PROTOCOL": "HTTP/1.1",
        "REMOTE_ADDR": "127.0.0.1"
    }
    
    body = middleware(environ, start_response)
    assert app_called is True
    assert response_status == "200 OK"
    # Vérifie l'injection du cookie
    headers_dict = {k.lower(): v for k, v in response_headers}
    assert "set-cookie" in headers_dict
    assert "device_id" in headers_dict["set-cookie"]
    assert body == [b"Flask response"]

    # --- Scénario 2 : Hostile (Bloqué) ---
    app_called = False
    response_headers.clear()
    environ_malicious = {
        "REQUEST_METHOD": "GET",
        "PATH_INFO": "/.env",
        "QUERY_STRING": "",
        "HTTP_USER_AGENT": "curl/7.82",
        "SERVER_PROTOCOL": "HTTP/1.1",
        "REMOTE_ADDR": "1.2.3.4"
    }
    
    body_malicious = middleware(environ_malicious, start_response)
    assert app_called is False
    assert response_status == "403 Forbidden"
    assert b"Forbidden" in body_malicious[0]
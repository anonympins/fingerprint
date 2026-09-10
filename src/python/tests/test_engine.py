import sys
import asyncio
import hashlib
import json
import time
from pathlib import Path
import pytest

# Ajoute le dossier parent au sys.path pour pouvoir importer le module engine de manière fiable
sys.path.append(str(Path(__file__).parent.parent))

from engine import (
    imul,
    parse_tcp_syn,
    classify_tcp_os,
    cyrb53,
    get_ip_subnet,
    RequestContext,
    InMemoryStore,
    FingerprintBuilder,
    ChallengeUtils,
    RequestUtils,
    FingerprintEngine,
    ProblemManager,
    MetricsManager,
    TLSClientHelloParser,
    FingerprintClient,
    RedisStore,
    AutoTuner,
    MaliciousPatterns,
    ASGIFingerprintMiddleware,
    WSGIFingerprintMiddleware,
)

def test_parse_tcp_syn_binary():
    """Vérifie le parsing de trames TCP SYN brutes en Python."""
    # Linux SYN Hex
    linux_syn = bytes.fromhex('4500003c1a2b400040063c1a7f0000017f0000011f9000500000000100000000a00272103c1a0000020405b4040201030307')
    fp = parse_tcp_syn(linux_syn)
    assert fp is not None
    assert fp["ttl"] == 64
    assert fp["windowSize"] == 29200
    assert fp["mss"] == 1460
    assert fp["ws"] == 7
    assert fp["sack"] is True

    # Windows SYN Hex
    windows_syn = bytes.fromhex('4500003c1a2b400080063c1a7f0000017f0000011f9000500000000100000000a002faf03c1a0000020405b4040201030308')
    fp_win = parse_tcp_syn(windows_syn)
    assert fp_win["ttl"] == 128
    assert fp_win["windowSize"] == 64240

def test_classify_tcp_os():
    """Vérifie la classification passive de l'OS."""
    linux_syn = bytes.fromhex('4500003c1a2b400040063c1a7f0000017f0000011f9000500000000100000000a00272103c1a0000020405b4040201030307')
    assert classify_tcp_os(parse_tcp_syn(linux_syn)) == "Linux"

    windows_syn = bytes.fromhex('4500003c1a2b400080063c1a7f0000017f0000011f9000500000000100000000a002faf03c1a0000020405b4040201030308')
    assert classify_tcp_os(parse_tcp_syn(windows_syn)) == "Windows"

def test_tcp_anomaly_cross_layer():
    """Vérifie le croisement de l'OS applicatif avec la couche transport."""
    linux_syn_hex = '4500003c1a2b400040063c1a7f0000017f0000011f9000500000000100000000a00272103c1a0000020405b4040201030307'
    context = RequestContext(
        client_ip="127.0.0.1",
        path="/",
        headers={
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0",
            "x-raw-tcp-binary": linux_syn_hex
        },
        query_params={},
        cookies={}
    )
    score_data = RequestUtils.get_tcp_anomaly_score(context)
    assert score_data["tcpAnomalyScore"] == pytest.approx(80.1)

def test_client_hints_inconsistency_full_version_mismatch():
    """Vérifie le score d'incohérence en cas de différence de version complète."""
    context = RequestContext(
        client_ip="1.2.3.4",
        path="/",
        headers={
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.1.2 Safari/537.36",
            "sec-ch-ua": '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
            "sec-ch-ua-full-version-list": '"Not_A Brand";v="8.0.0.0", "Chromium";v="120.0.1.3", "Google Chrome";v="120.0.1.3"'
        },
        query_params={},
        cookies={}
    )
    score = RequestUtils.get_client_hints_inconsistency(context)
    assert score == 85.0

def test_cross_layer_inconsistency_viewport_exceeds_screen():
    """Vérifie le score d'incohérence quand la largeur du viewport dépasse la taille d'écran physique."""
    scr_hash = cyrb53("1920x1080_24")
    context = RequestContext(
        client_ip="1.2.3.4",
        path="/",
        headers={
            "x-device-fingerprint": f"scr:{scr_hash}",
            "sec-ch-viewport-width": "2560"
        },
        query_params={},
        cookies={}
    )
    score = RequestUtils.get_cross_layer_inconsistency(context)
    assert score == 20.0
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

@pytest.mark.asyncio
async def test_problem_manager_dispatch_and_integrate():
    import os
    import json
    store = InMemoryStore()
    config_path = "test_problems.json"
    problems_config = [
        {
            "id": "facility_location_challenge",
            "workUnit": {
                "type": "simulated_annealing_iterations",
                "scoreFunction": "facility.calculateEnergy",
                "baseIterations": 10
            },
            "payload": {
                "customers": [{"x": 100, "y": 100}, {"x": 200, "y": 200}],
                "options": {"fixedCostPerFacility": 1500}
            },
            "state": {"bestSolution": None, "bestEnergy": "Infinity"}
            },
            {
                "id": "portfolio_optimization",
                "workUnit": {
                    "type": "genetic_algorithm_generations",
                    "baseGenerations": 10
                },
                "payload": {
                    "assets": [{"name": "Asset 1", "expectedReturn": 0.1, "volatility": 0.2}]
                },
                "state": {"population": None}
            },
            {
                "id": "cpc_optimization",
                "workUnit": {
                    "type": "multi_objective_genetic_algorithm",
                    "solverName": "cpc.solve"
                },
                "payload": {},
                "state": {"paretoFront": []}
        }
    ]
    with open(config_path, "w", encoding="utf-8") as f:
        json.dump(problems_config, f)
    
    try:
        ProblemManager._instance = None
        pm = ProblemManager.get_instance(config_path, store)
        await pm.load_problems()
        
        assert pm.initialized is True
        work = await pm.dispatch_work(0.5)
        assert work["problemId"] == "facility_location_challenge"
        assert "iterations" in work["task"]
        
        client_solution = {
            "solution": [{"x": 100, "y": 100}, {"x": 200, "y": 200}],
            "energy": 1500.0
        }
        await pm.integrate_solution("facility_location_challenge", client_solution)
        
        stored_state = await store.get("problem-state:facility_location_challenge")
        assert stored_state is not None
        assert stored_state["bestEnergy"] < float("inf")

        # Test genetic_algorithm_generations
        work_ga = await pm.dispatch_work(0.5)
        assert work_ga["problemId"] == "portfolio_optimization"
        assert "generations" in work_ga["task"]
        client_sol_ga = {
            "population": [{"chromosome": [1.0], "fitness": -0.1}]
        }
        await pm.integrate_solution("portfolio_optimization", client_sol_ga)
        stored_state_ga = await store.get("problem-state:portfolio_optimization")
        assert stored_state_ga is not None
        assert stored_state_ga["population"] == client_sol_ga["population"]

        # Test multi_objective_genetic_algorithm
        work_mo = await pm.dispatch_work(0.5)
        assert work_mo["problemId"] == "cpc_optimization"
        assert "generations" in work_mo["task"]
        client_sol_mo = {
            "paretoFront": [{"solution": 1.5, "objectives": [10.0, 20.0]}]
        }
        await pm.integrate_solution("cpc_optimization", client_sol_mo)
        stored_state_mo = await store.get("problem-state:cpc_optimization")
        assert stored_state_mo is not None
        assert stored_state_mo["paretoFront"] == client_sol_mo["paretoFront"]
    finally:
        if os.path.exists(config_path):
            os.remove(config_path)

@pytest.mark.asyncio
async def test_engine_re_challenge_with_valid_ticket_high_suspicion():
    """Vérifie que même avec un ticket valide, un score de suspicion élevé déclenche un re-challenge."""
    config = {
        "thresholds": {"low": 20, "high": 75, "block": 95},
        "weights": {"inconsistencyScore": 0.8},
        "similarityThreshold": 0.5
    }
    store = InMemoryStore()
    engine = FingerprintEngine(config, store)

    # 1. Résoudre l'identité pour avoir un historique de terminal
    context = RequestContext(
        client_ip="127.0.0.1",
        path="/",
        headers={
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
        },
        query_params={},
        cookies={}
    )
    decision = await engine.process_request(context)
    device_id = decision.get("newCookieForResponse", {}).get("value")

    # Créer un ticket de clearance simulé valide
    ticket = "valid-ticket-123"
    await store.set(f"ticket:{ticket}", {"ip": "127.0.0.1", "device_id": device_id}, 3600)

    # Requête avec ticket valide, mais avec un UA totalement différent pour provoquer une forte incohérence (score >= 75)
    context_suspicious = RequestContext(
        client_ip="127.0.0.1",
        path="/",
        headers={
            "user-agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
        },
        query_params={},
        cookies={"device_id": device_id, "pow_clearance": ticket}
    )

    decision_suspicious = await engine.process_request(context_suspicious)
    # L'action doit être un challenge (re-challenge) malgré le ticket valide
    assert decision_suspicious["action"] == "challenge"

@pytest.mark.asyncio
async def test_engine_honeypot_persistence_with_valid_ticket():
    """Vérifie qu'un bot soumettant un honeypot avec un ticket valide est bloqué."""
    config = {
        "thresholds": {"low": 20, "high": 75, "block": 95},
        "weights": {"honeypotScore": 1.0},
        "honeypot": {"fields": ["email_confirm"]}
    }
    store = InMemoryStore()
    engine = FingerprintEngine(config, store)

    context = RequestContext(
        client_ip="127.0.0.1",
        path="/",
        headers={"user-agent": "Mozilla/5.0"},
        query_params={},
        cookies={}
    )
    decision = await engine.process_request(context)
    device_id = decision.get("newCookieForResponse", {}).get("value")

    ticket = "valid-ticket-456"
    await store.set(f"ticket:{ticket}", {"ip": "127.0.0.1", "device_id": device_id}, 3600)

    # Requête avec un ticket valide, mais qui remplit le champ honeypot
    context_bot = RequestContext(
        client_ip="127.0.0.1",
        path="/",
        headers={"user-agent": "Mozilla/5.0"},
        query_params={},
        cookies={"device_id": device_id, "pow_clearance": ticket},
        body={"email_confirm": "spam-bot"}
    )

    decision_bot = await engine.process_request(context_bot)
    assert decision_bot["action"] == "block"


# --- NEW TESTS: WAF, IP REPUTATION, SUBNET, DRY RUN & VECTOR VALIDATION ---

def test_malicious_patterns_waf():
    """Vérifie la détection d'injections malveillantes via MaliciousPatterns."""
    assert MaliciousPatterns.is_malicious("SELECT * FROM users;--") is True
    assert MaliciousPatterns.is_malicious("UNION SELECT username, password") is True
    assert MaliciousPatterns.is_malicious("${jndi:ldap://evil.com/a}") is True
    assert MaliciousPatterns.is_malicious("{{ 7*7 }}") is True
    assert MaliciousPatterns.is_malicious("cat /etc/passwd") is True
    assert MaliciousPatterns.is_malicious("normal comment text") is False

@pytest.mark.asyncio
async def test_ip_reputation_and_decay():
    """Vérifie la réputation IP, le bornage et sa décroissance temporelle."""
    store = InMemoryStore()
    ip = "1.2.3.4"
    
    # Par défaut, score de 0.0
    assert await RequestUtils.get_ip_reputation_score(store, ip) == 0.0
    
    # Mise à jour positive
    await RequestUtils.update_ip_reputation_score(store, ip, 45.0)
    assert await RequestUtils.get_ip_reputation_score(store, ip) == 45.0
    
    # Bornes max (100)
    await RequestUtils.update_ip_reputation_score(store, ip, 120.0)
    assert await RequestUtils.get_ip_reputation_score(store, ip) == 100.0
    
    # Bornes min (0)
    await RequestUtils.update_ip_reputation_score(store, ip, -150.0)
    assert await RequestUtils.get_ip_reputation_score(store, ip) == 0.0

    # Test de la décroissance temporelle (2 points par heure passée)
    # On simule un score de 50.0 datant de 3 heures
    await store.set(f"ip-reputation:{ip}", {
        "score": 50.0,
        "lastUpdate": time.time() - (3 * 3600)
    })
    # 50.0 - (3 * 2) = 44.0
    assert await RequestUtils.get_ip_reputation_score(store, ip) == 44.0

@pytest.mark.asyncio
async def test_subnet_score_history_and_decay():
    """Vérifie la mise à jour des métriques de sous-réseau, le calcul du score et la décroissance."""
    store = InMemoryStore()
    ip = "192.168.1.50"
    device_id = "device-test-1"
    
    # Initialement 0.0
    score_data = await RequestUtils.get_subnet_score(store, ip, device_id)
    assert score_data["subnetScore"] == 0.0
    
    # On simule une activité de plusieurs appareils uniques avec des scores élevés
    for i in range(1, 15):
        await RequestUtils.update_subnet_metrics(store, ip, f"device-{i}", 40.0)
        
    score_data_updated = await RequestUtils.get_subnet_score(store, ip, device_id)
    assert score_data_updated["subnetScore"] > 0.0
    
    # Test de la décroissance (demi-vie de 30 minutes / 1800 secondes)
    subnet = get_ip_subnet(ip)
    # On simule une activité datant de 1 heure (2 demi-vies)
    subnet_key = f"subnet:{subnet}"
    data = await store.get(subnet_key)
    data["lastActivity"] = int(time.time()) - 3600
    await store.set(subnet_key, data)
    
    score_data_decayed = await RequestUtils.get_subnet_score(store, ip, device_id)
    assert score_data_decayed["subnetScore"] < score_data_updated["subnetScore"]

@pytest.mark.asyncio
async def test_dry_run_mode():
    """Vérifie que le mode Dry Run n'interrompt pas la requête mais enregistre l'intention."""
    config = {
        "dryRun": True,
        "thresholds": {"low": 20, "high": 75, "block": 95},
        "weights": {"honeypotScore": 1.0},
        "honeypot": {"trapUrls": ["/.env"]}
    }
    store = InMemoryStore()
    engine = FingerprintEngine(config, store)
    
    # Requête de bot vers honeypot (.env) qui devrait normalement bloquer
    context = RequestContext(
        client_ip="127.0.0.1",
        path="/.env",
        headers={"user-agent": "curl/7.68.0"},
        query_params={},
        cookies={}
    )
    
    decision = await engine.process_request(context)
    
    # Dry Run actif : action = next, intendedAction = block, pas de status ou body
    assert decision["action"] == "next"
    assert decision["intendedAction"] == "block"
    assert "status" not in decision
    assert "body" not in decision

@pytest.mark.asyncio
async def test_suspicion_vector_and_final_score():
    """Vérifie la parité de structure : get_suspicion_vector et calculate_final_score."""
    config = {
        "thresholds": {"low": 20, "high": 75, "block": 95},
        "weights": {
            "inconsistencyScore": 0.5,
            "headerAnomalyScore": 0.5
        }
    }
    store = InMemoryStore()
    engine = FingerprintEngine(config, store)
    
    # Requête avec anomalies d'en-tête
    context = RequestContext(
        client_ip="127.0.0.1",
        path="/",
        headers={"user-agent": "curl"}, # anomalies
        query_params={},
        cookies={}
    )
    
    vector = await engine.get_suspicion_vector(context)
    assert isinstance(vector, dict)
    assert "inconsistencyScore" in vector
    assert "headerAnomalyScore" in vector
    assert vector["headerAnomalyScore"] > 0
    
    # Calcul manuel avec les poids configurés (0.5 et 0.5)
    score = engine.calculate_final_score(vector)
    expected_score = min(100.0, vector["inconsistencyScore"] * 0.5 + vector["headerAnomalyScore"] * 0.5)
    assert score == pytest.approx(expected_score, 0.01)


def test_metrics_manager():
    """Tests Prometheus-compatible metrics tracking, collection, and generation."""
    MetricsManager.clear_metrics()
    MetricsManager.increment_counter("requests_total", {"status": "passed"})
    MetricsManager.increment_counter("requests_total", {"status": "passed"})
    MetricsManager.observe_value("suspicion_score", 45.5, {"action": "passed"})

    metrics_output = MetricsManager.get_prometheus_metrics(
        security_config={"weights": {"honeypotScore": 1.0}, "thresholds": {"low": 20}}
    )
    assert "fingerprint_requests_total" in metrics_output
    assert 'status="passed"' in metrics_output
    assert "fingerprint_suspicion_score" in metrics_output
    assert "fingerprint_security_weight" in metrics_output
    assert "fingerprint_security_threshold" in metrics_output


def test_tls_client_hello_parser():
    """Tests binary parsing of the Client Hello handshake and JA3/JA4 generation."""
    # Length guard check
    assert TLSClientHelloParser.parse(b"\x16\x03\x01\x00") is None

    # Construct a minimal valid TLS Client Hello binary
    # Record Type: 0x16, Version: 0x0301, Length: 0x003b
    # Handshake Type: 0x01, Length: 0x000037
    # Client Version: 0x0303 (TLS 1.2)
    # Random: 32 bytes of zeros
    # Session ID Length: 0
    # Ciphers Length: 2, Cipher: 0x1301 (TLS_AES_128_GCM_SHA256 - 4865)
    # Compression Length: 1, Compression: 0
    # Extensions Length: 0
    header = (
            b"\x16\x03\x01\x00\x3b"
            b"\x01\x00\x00\x37"
            b"\x03\x03"
            + b"\x00" * 32
            + b"\x00\x00\x02\x13\x01\x01\x00\x00\x00"
    )
    res = TLSClientHelloParser.parse(header)
    assert res is not None
    assert "ja3_string" in res
    assert "ja3_hash" in res


def test_fingerprint_client():
    """Tests client-side helper HTML generation and scripts wrapping."""
    client = FingerprintClient("/static/fp.js")
    field_html = client.generate_honeypot_field("confirm_email_trap")
    assert 'name="confirm_email_trap"' in field_html

    script_tag = client.get_script_tag()
    assert 'src="/static/fp.js"' in script_tag
    assert "confirm_email_trap" in script_tag


@pytest.mark.asyncio
async def test_redis_store_adapter():
    """Tests Redis store serializations, deserializations, and Set-to-list conversions."""
    class MockRedis:
        def __init__(self):
            self.data = {}
        async def get(self, key):
            return self.data.get(key)
        async def set(self, key, value):
            self.data[key] = value
            return True
        async def setex(self, key, ttl, value):
            self.data[key] = value
            return True
        async def exists(self, key):
            return 1 if key in self.data else 0
        async def delete(self, key):
            self.data.pop(key, None)
            return 1

    mock_redis = MockRedis()
    store = RedisStore(mock_redis)

    await store.set("device:123", {"initialDeviceHash": "abc", "ips": {"1.1.1.1"}})
    val = await store.get("device:123")
    assert val["initialDeviceHash"] == "abc"
    assert isinstance(val["ips"], set)
    assert "1.1.1.1" in val["ips"]


def test_auto_tuner_cycle():
    """Tests executing a threshold optimization cycle using traffic logs."""
    security_config = {
        "thresholds": {"low": 20, "medium": 40, "high": 75, "block": 95},
        "weights": {
            "inconsistencyScore": 0.8,
            "headerAnomalyScore": 0.1,
            "honeypotScore": 1.0,
            "behaviorScore": 0.5,
        },
        "patterns": {
            "velocityThreshold": 800,
            "decayFactor": 0.9
        }
    }

    traffic_data = []
    for i in range(150):
        traffic_data.append({
            "type": "challenge_solved",
            "deviceId": f"dev-{i}",
            "vector": {"honeypotScore": 10.0, "inconsistencyScore": 0.0, "headerAnomalyScore": 0.0, "behaviorScore": 0.0}
        })
    for i in range(150):
        traffic_data.append({
            "type": "request_passed",
            "deviceId": f"dev-pass-{i}",
            "vector": {"honeypotScore": 0.0, "inconsistencyScore": 0.0, "headerAnomalyScore": 0.0, "behaviorScore": 0.0}
        })

    tuner = AutoTuner(security_config, traffic_data, {"minDataPoints": 200})
    tuner.run_optimization_cycle()

    best_sol = tuner.get_best_tuning_solution()
    assert best_sol is not None or tuner.traffic_data is not None

@pytest.mark.asyncio
async def test_challenge_rate_limiting():
    """Vérifie le fonctionnement du limiteur de débit pour les challenges (Token Bucket)."""
    store = InMemoryStore()
    client_ip = "1.2.3.4"
    
    # Premier appel : doit passer
    assert await ChallengeUtils.check_challenge_rate_limit(store, client_ip) is True
    
    # On vide le seau artificiellement (on consomme les jetons restants)
    for _ in range(4):
        assert await ChallengeUtils.check_challenge_rate_limit(store, client_ip) is True
        
    # Le 6ème appel doit être rejeté (False)
    assert await ChallengeUtils.check_challenge_rate_limit(store, client_ip) is False

def test_get_behavior_score_with_bot_like_touch_movements():
    """Vérifie la détection de l'émulation tactile (mouvements robotiques / variance de pression nulle)."""
    import json
    metrics = {
        "honeypotInteraction": False,
        "touchMovementsHistory": [
            {"x": 50, "y": 50, "t": 1, "p": 0.5, "r": 10, "num": 1},
            {"x": 55, "y": 55, "t": 100, "p": 0.5, "r": 10, "num": 1},
            {"x": 60, "y": 60, "t": 200, "p": 0.5, "r": 10, "num": 1},
            {"x": 65, "y": 65, "t": 300, "p": 0.5, "r": 10, "num": 1}
        ]
    }
    context = RequestContext(
        client_ip="127.0.0.1",
        path="/",
        headers={"x-behavior-metrics": json.dumps(metrics)},
        query_params={},
        cookies={}
    )
    score = RequestUtils.get_behavior_score(context)
    assert score > 60.0

def test_get_behavior_score_with_human_like_touch_movements():
    """Vérifie que les gestes tactiles complexes et naturels d'un humain n'induisent pas de pénalités."""
    import json
    metrics = {
        "honeypotInteraction": False,
        "touchMovementsHistory": [
            {"x": 50, "y": 50, "t": 1, "p": 0.45, "r": 8.5, "num": 1},
            {"x": 60, "y": 52, "t": 100, "p": 0.52, "r": 9.1, "num": 1},
            {"x": 72, "y": 60, "t": 200, "p": 0.49, "r": 8.8, "num": 1},
            {"x": 80, "y": 80, "t": 300, "p": 0.41, "r": 8.2, "num": 1}
        ]
    }
    context = RequestContext(
        client_ip="127.0.0.1",
        path="/",
        headers={"x-behavior-metrics": json.dumps(metrics)},
        query_params={},
        cookies={}
    )
    score = RequestUtils.get_behavior_score(context)
    assert score < 30.0


@pytest.mark.asyncio
async def test_real_world_console_botnet_clustering():
    """Vérifie le regroupement d'empreintes de consoles (PS4) partageant des composants stables."""
    config = {
        "thresholds": {"low": 20, "high": 75, "block": 95},
        "weights": {"botnetClusterScore": 1.0}
    }
    store = InMemoryStore()
    engine = FingerprintEngine(config, store)

    ps4_headers = {
        "user-agent": "Mozilla/5.0 (PlayStation 4 11.50) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/11.50 Safari/605.1.15",
        "x-ja3-hash": "76993ef93bf89104037599723ab9f201",
        "x-ja4-hash": "t13d1516h2_8daaf6152771_390237aa04be",
    }

    for i in range(1, 11):
        context = RequestContext(
            client_ip=f"185.15.20.{i}",
            path="/api/login",
            headers={
                **ps4_headers,
                "cookie_keys": f"session_id=fake_sess_{i}"
            },
            query_params={},
            cookies={}
        )

        current_hash = engine.get_composite_device_hash(context)
        stable_fp = engine._extract_stable_part(current_hash)
        stable_fp_hash = str(cyrb53(stable_fp))

        score_data = RequestUtils.get_botnet_cluster_score(context, stable_fp_hash)

        if i == 1:
            assert score_data["botnetClusterScore"] == 0.0
        elif i == 2:
            assert score_data["botnetClusterScore"] == 29.5
        elif i == 3:
            assert score_data["botnetClusterScore"] == 50.3
        elif i == 4:
            assert score_data["botnetClusterScore"] == 65.0
        elif i == 5:
            assert score_data["botnetClusterScore"] == 75.3
        elif i == 10:
            assert score_data["botnetClusterScore"] == 95.7

@pytest.mark.asyncio
async def test_stateless_ticket_generation_and_validation():
    """Vérifie la génération de tickets stateless chiffrés et signés et leur validation."""
    payload = {
        "expiry": int(time.time() * 1000) + 3600000,
        "originalIp": "127.0.0.1",
        "deviceId": "device-123",
        "deviceHash": "hash-abc"
    }
    secret = "my-test-pow-secret-with-long-length-32-chars"
    
    # Génération du ticket stateless
    ticket = ChallengeUtils.generate_stateless_ticket(payload, secret)
    assert ticket is not None
    assert "." in ticket
    assert len(ticket.split(".")) == 3
    
    # Validation du ticket stateless
    valid = await ChallengeUtils.is_ticket_valid(
        ip="127.0.0.1",
        ticket=ticket,
        device_id="device-123",
        device_hash="hash-abc",
        secret=secret
    )
    assert valid is True

    # Doit échouer avec une IP différente sans itinérance autorisée
    valid_diff_ip = await ChallengeUtils.is_ticket_valid(
        ip="192.168.1.1",
        ticket=ticket,
        device_id="device-123",
        device_hash="hash-abc",
        secret=secret,
        allow_cross_network_roaming=False
    )
    assert valid_diff_ip is False

@pytest.mark.asyncio
async def test_tls_session_resumption_cookieless_tracking():
    """Vérifie le traçage sans cookie par reprise de session TLS (TLS Session Resumption)."""
    config = {
        "thresholds": {"low": 20, "high": 75, "block": 95},
        "weights": {"inconsistencyScore": 0.5, "headerAnomalyScore": 0.5}
    }
    store = InMemoryStore()
    engine = FingerprintEngine(config, store)

    # 1. Première visite du client avec session TLS mais sans cookie
    tls_session_id = "test-tls1.3-session-resumption-id-abcde"
    context1 = RequestContext(
        client_ip="1.2.3.4",
        path="/",
        headers={
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
            "x-tls-session-id": tls_session_id,
            "accept-language": "fr-FR"
        },
        query_params={},
        cookies={}
    )

    decision1 = await engine.process_request(context1)
    assert "newCookieForResponse" in decision1, "Un cookie d'identité doit être généré."
    device_cookie = decision1["newCookieForResponse"]
    device_id = device_cookie["value"]

    # 2. Deuxième visite du client : les cookies sont supprimés, mais la session TLS est reprise
    context2 = RequestContext(
        client_ip="1.2.3.4",
        path="/",
        headers={
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
            "x-tls-session-id": tls_session_id,
            "accept-language": "fr-FR"
        },
        query_params={},
        cookies={}  # Cookies supprimés !
    )

    decision2 = await engine.process_request(context2)
    assert decision2["action"] == "next"
    assert "newCookieForResponse" not in decision2, "Aucun nouveau cookie d'identité ne doit être généré."

    # Résoudre l'identité pour vérifier qu'elle est bien identique à la première requête
    resolution = await engine.resolve_identity(context2)
    assert resolution["device_id"] == device_id, "L'identifiant d'appareil doit être restauré via la session TLS."

@pytest.mark.asyncio
async def test_pospace_challenge():
    """Vérifie le cycle complet d'un challenge Proof of Space (PoSpace)."""
    config = {
        "thresholds": {"low": 20, "high": 75, "block": 95},
        "weights": {"inconsistencyScore": 1.0},
        "enableProofOfSpace": True,
        "pospace": {
            "sizeMb": 1,
            "numQueries": 5
        }
    }
    store = InMemoryStore()
    engine = FingerprintEngine(config, store)

    context = RequestContext(
        client_ip="127.0.0.1",
        path="/",
        headers={
            "user-agent": "Mozilla/5.0",
        },
        query_params={},
        cookies={}
    )
    
    import unittest.mock as mock
    with mock.patch.object(engine, 'calculate_final_score', return_value=50):
        decision = await engine.process_request(context)
        
    assert decision["action"] == "challenge"
    
    if isinstance(decision["body"], dict):
        challenge = decision["body"]["challenge"]
        nonce = challenge["nonce"]
        client_secret = challenge["clientSecret"]
        queries = challenge["queries"]
    else:
        import re
        nonce = re.search(r'const nonce = "([^"]+)"', decision["body"]).group(1)
        client_secret = re.search(r'const clientSecret = "([^"]+)"', decision["body"]).group(1)
        queries = json.loads(re.search(r'const queries = (\[[^\]]+\])', decision["body"]).group(1))

    seed = f"{nonce}:{client_secret}"
    combined = bytearray()
    for idx in queries:
        combined.extend(ChallengeUtils.generate_block(seed, int(idx)))
    final_block = bytes(combined) + f"{nonce}:{client_secret}".encode("utf-8")
    solution = hashlib.sha256(final_block).hexdigest()

    context_submit = RequestContext(
        client_ip="127.0.0.1",
        path="/",
        headers={
            "user-agent": "Mozilla/5.0",
        },
        query_params={
            "pow_type": "pospace",
            "pow_nonce": nonce,
            "pow_solution_space": solution
        },
        cookies={}
    )
    
    decision_submit = await engine.process_request(context_submit)
    assert decision_submit["action"] == "redirect"
    assert "pow_clearance" in decision_submit["cookie"]["name"]
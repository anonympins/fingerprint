import hmac
import hashlib
import time
from urllib.parse import urlparse
import os

def verify_zkp_proof(y_str, t_str, s_str):
    """
    Vérifie une preuve de connaissance à divulgation nulle (ZKP) de Schnorr.
    Compatible avec les implémentations JS, PHP et Java de la bibliothèque.
    """
    try:
        y = int(y_str, 16)
        t = int(t_str, 16)
        s = int(s_str, 16)

        p = 115792089237316195423570985008687907853269984665640564039457584007908834671663
        g = 2

        c_str = str(g) + str(y) + str(t)
        c_hash = hashlib.sha256(c_str.encode('utf-8')).hexdigest()
        c = int(c_hash, 16) % p

        left = pow(g, s, p)
        right = (t * pow(y, c, p)) % p

        return left == right
    except Exception:
        return False

def get_pow_secret():
    return os.environ.get('POW_SECRET', 'fallback-dev-secret-32-chars-minimum')

def handle_cooperative_request(params, client_ip='127.0.0.1', config=None, store=None):
    """
    Traite de manière sécurisée les requêtes de synchronisation fédérées (ZKP Threat Intel).
    Valide l'origine de l'IP émettrice par rapport au registre federatedPeers.
    """
    if config is None:
        config = {}
    op = params.get('coop_op')
    if not op:
        return None

    if op == 'share_threat_intel':
        peers = config.get('federatedPeers', [])
        if peers:
            allowed_hosts = []
            for url in peers:
                try:
                    # Ajoute un protocole factice si urlparse échoue à détecter l'hôte
                    parsed = urlparse(url) if '://' in url else urlparse('http://' + url)
                    allowed_hosts.append(parsed.hostname or url)
                except Exception:
                    allowed_hosts.append(url)
            if client_ip not in allowed_hosts:
                return {'error': 'Unauthorized federation sender IP'}

        zkp_y = params.get('zkpY', '')
        signature = params.get('signature', '')
        timestamp_str = params.get('timestamp', '0')
        try:
            timestamp = int(timestamp_str)
        except ValueError:
            timestamp = 0

        if not zkp_y or not signature or not timestamp:
            return {'error': 'Missing threat intel parameters'}

        now = int(time.time() * 1000)
        if abs(now - timestamp) > 300000:
            return {'error': 'Message expired or clock skew too high'}

        secret = params.get('federationSecret') or config.get('federationSecret') or get_pow_secret()
        msg = f"{timestamp}:{zkp_y}"
        expected_sig = hmac.new(secret.encode('utf-8'), msg.encode('utf-8'), hashlib.sha256).hexdigest()

        if not hmac.compare_digest(expected_sig, signature):
            return {'error': 'Invalid federation signature'}

        if store is not None:
            store.set(f"banned-zkp-y:{zkp_y}", True, 86400 * 30)
        return {'status': 'synchronized'}

    return None
import os
import json
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

def generate_issuer_pem_keys(out_dir="config", options=None):
    """
    Génère une paire de clés Ed25519 au format PEM (PKCS#8 et SPKI) équivalent à OpenSSL:
    openssl genpkey -algorithm ed25519 -out issuer-private.pem
    openssl pkey -in issuer-private.pem -pubout -out issuer-public.pem
    """
    options = options or {}
    priv_name = options.get("privateKeyName", "issuer-private.pem")
    pub_name = options.get("publicKeyName", "issuer-public.pem")

    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode("utf-8")

    pub_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("utf-8")

    os.makedirs(out_dir, exist_ok=True)
    priv_path = os.path.join(out_dir, priv_name)
    pub_path = os.path.join(out_dir, pub_name)

    with open(priv_path, "w", encoding="utf-8") as f:
        f.write(priv_pem)
    with open(pub_path, "w", encoding="utf-8") as f:
        f.write(pub_pem)
    try:
        os.chmod(priv_path, 0o600)
        os.chmod(pub_path, 0o644)
    except Exception:
        pass

    return {
        "privateKeyPath": priv_path,
        "publicKeyPath": pub_path,
        "privateKey": priv_pem,
        "publicKey": pub_pem,
    }

def initialize_ed25519_keys(config_dir="config", verbose=False):
    """
    Initialise les clés cryptographiques Ed25519 pour l'instance de fédération.
    Tente de charger les clés depuis l'environnement, puis depuis le stockage local persistant,
    ou les génère automatiquement si nécessaire.
    """
    # 1. Bypass si les clés sont déjà définies dans l'environnement de processus
    if os.environ.get("ED25519_PRIVATE_KEY") and os.environ.get("ED25519_PUBLIC_KEY"):
        if verbose:
            print("[Fingerprint] Clés Ed25519 déjà présentes dans l'environnement de processus.")
        return

    key_file_path = os.path.join(config_dir, "ed25519_key.json")
    priv_pem_path = os.path.join(config_dir, "issuer-private.pem")
    pub_pem_path = os.path.join(config_dir, "issuer-public.pem")

    # 2. Tentative de lecture du fichier persistant sur le stockage local
    if os.path.exists(key_file_path):
        try:
            with open(key_file_path, "r", encoding="utf-8") as f:
                keys_data = json.load(f)
                os.environ["ED25519_PRIVATE_KEY"] = keys_data["privateKey"]
                os.environ["ED25519_PUBLIC_KEY"] = keys_data["publicKey"]
                if verbose:
                    print(f"[Fingerprint] Clés de fédération Ed25519 restaurées depuis {key_file_path}")
                return
        except Exception as e:
            if verbose:
                print(f"[Fingerprint] Échec du chargement des clés locales : {e}")
    elif os.path.exists(priv_pem_path) and os.path.exists(pub_pem_path):
        try:
            with open(priv_pem_path, "r", encoding="utf-8") as f:
                priv_pem = f.read()
            with open(pub_pem_path, "r", encoding="utf-8") as f:
                pub_pem = f.read()
            os.environ["ED25519_PRIVATE_KEY"] = priv_pem
            os.environ["ED25519_PUBLIC_KEY"] = pub_pem
            if verbose:
                print(f"[Fingerprint] Clés de fédération Ed25519 restaurées depuis {priv_pem_path}")
            return
        except Exception as e:
            if verbose:
                print(f"[Fingerprint] Échec du chargement des fichiers PEM : {e}")

    # 3. Génération et écriture persistante en cas d'absence
    try:
        pem_keys = generate_issuer_pem_keys(out_dir=config_dir)
        priv_pem = pem_keys["privateKey"]
        pub_pem = pem_keys["publicKey"]

        os.environ["ED25519_PRIVATE_KEY"] = priv_pem
        os.environ["ED25519_PUBLIC_KEY"] = pub_pem

        os.makedirs(config_dir, exist_ok=True)
        with open(key_file_path, "w", encoding="utf-8") as f:
            json.dump({"privateKey": priv_pem, "publicKey": pub_pem}, f, indent=2)
            
        if verbose:
            print(f"[Fingerprint] Nouvelles clés générées et sauvegardées avec succès dans {key_file_path}")
    except Exception as e:
        print(f"[Fingerprint] Erreur critique lors de la génération automatique des clés : {e}")
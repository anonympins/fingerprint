import os
import json
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

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

    # 3. Génération et écriture persistante en cas d'absence
    try:
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

        os.environ["ED25519_PRIVATE_KEY"] = priv_pem
        os.environ["ED25519_PUBLIC_KEY"] = pub_pem

        os.makedirs(config_dir, exist_ok=True)
        with open(key_file_path, "w", encoding="utf-8") as f:
            json.dump({"privateKey": priv_pem, "publicKey": pub_pem}, f, indent=2)
            
        if verbose:
            print(f"[Fingerprint] Nouvelles clés générées et sauvegardées avec succès dans {key_file_path}")
    except Exception as e:
        print(f"[Fingerprint] Erreur critique lors de la génération automatique des clés : {e}")
import sys
from pathlib import Path
import pytest

# Ajoute le dossier parent (src/python) au sys.path pour importer de manière fiable les modules
sys.path.append(str(Path(__file__).parent.parent))

from security_profiles import SecurityProfiles

def test_create_default_profile():
    """Vérifie que l'appel par défaut sans arguments retourne le profil 'balanced'."""
    profile = SecurityProfiles.create_security_profile()
    assert profile["summary"] == "Balanced Profile (Default)"
    assert profile["thresholds"]["low"] == 20
    assert profile["wasm"] is True

def test_create_specific_profiles():
    """Vérifie la création correcte de différents profils enregistrés."""
    strict_profile = SecurityProfiles.create_security_profile("strict")
    assert strict_profile["summary"] == "Strict Profile"
    assert strict_profile["thresholds"]["low"] == 10

    api_profile = SecurityProfiles.create_security_profile("api")
    assert api_profile["summary"] == "API Profile"
    assert api_profile["thresholds"]["low"] == 25

def test_fallback_to_balanced_on_invalid_profile():
    """Vérifie que l'utilisation d'un nom de profil invalide renvoie le profil par défaut."""
    profile = SecurityProfiles.create_security_profile("unknown_profile")
    assert profile["summary"] == "Balanced Profile (Default)"
    assert profile["thresholds"]["low"] == 20

def test_create_profile_with_deep_overrides():
    """Vérifie que les surcharges (overrides) fusionnent correctement de manière récursive."""
    overrides = {
        "thresholds": {
            "low": 15,
            "block": 99
        },
        "weights": {
            "historyScore": 0.95
        },
        "wasm": False
    }
    
    profile = SecurityProfiles.create_security_profile("balanced", overrides)
    
    # Valeurs surchargées attendues
    assert profile["thresholds"]["low"] == 15
    assert profile["thresholds"]["block"] == 99
    assert profile["weights"]["historyScore"] == 0.95
    assert profile["wasm"] is False
    
    # Les valeurs non surchargées doivent être conservées intactes (fusion récursive)
    assert profile["thresholds"]["high"] == 75
    assert profile["weights"]["rotationScore"] == 0.5

def test_deep_copy_safety():
    """Garantit que la modification du profil retourné n'altère pas les profils d'origine."""
    profile = SecurityProfiles.create_security_profile("balanced")
    profile["thresholds"]["low"] = 999
    
    assert SecurityProfiles.PROFILES["balanced"]["thresholds"]["low"] == 20
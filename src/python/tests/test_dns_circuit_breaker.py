import pytest
import time
import sys
from pathlib import Path

# Ajoute le dossier parent au sys.path pour pouvoir importer le module engine
sys.path.append(str(Path(__file__).parent.parent))

from engine import (
    dns_circuit_breaker,
    record_dns_success,
    record_dns_failure,
    can_attempt_dns,
)

@pytest.fixture(autouse=True)
def reset_circuit_breaker():
    """
    Réinitialise l'état global du circuit breaker avant chaque test
    pour éviter les interférences.
    """
    dns_circuit_breaker["state"] = "CLOSED"
    dns_circuit_breaker["failureCount"] = 0
    dns_circuit_breaker["lastStateChange"] = 0.0
    dns_circuit_breaker["threshold"] = 5
    dns_circuit_breaker["cooldown"] = 1.0  # Cooldown court (1s) pour accélérer le test unitaire

def test_initial_state_is_closed():
    """Vérifie que l'état initial autorise les requêtes DNS."""
    assert can_attempt_dns() is True
    assert dns_circuit_breaker["state"] == "CLOSED"

def test_failure_threshold_trips_breaker():
    """Vérifie que le circuit s'ouvre après 5 échecs consécutifs."""
    # En dessous du seuil (4 échecs)
    for _ in range(4):
        record_dns_failure()
        assert can_attempt_dns() is True
        assert dns_circuit_breaker["state"] == "CLOSED"

    # Le 5ème échec doit ouvrir le circuit (trip)
    record_dns_failure()
    assert can_attempt_dns() is False
    assert dns_circuit_breaker["state"] == "OPEN"

def test_cooldown_transitions_to_half_open():
    """Vérifie le passage en HALF-OPEN après expiration du cooldown."""
    # Déclenche l'ouverture
    for _ in range(5):
        record_dns_failure()
    
    assert can_attempt_dns() is False
    
    # Simule l'attente du cooldown (1 seconde + marge)
    time.sleep(1.1)
    
    # can_attempt_dns() doit basculer l'état en HALF-OPEN et renvoyer True
    assert can_attempt_dns() is True
    assert dns_circuit_breaker["state"] == "HALF-OPEN"

def test_success_on_half_open_resets_breaker():
    """Vérifie qu'un succès en mode HALF-OPEN referme le circuit."""
    # Déclenche l'ouverture
    for _ in range(5):
        record_dns_failure()
        
    time.sleep(1.1)
    assert can_attempt_dns() is True  # Transition vers HALF-OPEN
    
    # Enregistrement d'un succès
    record_dns_success()
    assert dns_circuit_breaker["state"] == "CLOSED"
    assert dns_circuit_breaker["failureCount"] == 0
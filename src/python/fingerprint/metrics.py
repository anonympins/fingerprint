import json
from typing import Dict, Any, Optional

# Stockage global des compteurs et des observations (gauges)
_counters: Dict[str, float] = {}
_observations: Dict[str, float] = {}
_last_best_solution: Optional[Dict[str, Any]] = None

def increment_counter(name: str, labels: Optional[Dict[str, str]] = None) -> None:
    full_name = name if name.startswith("fingerprint_") else f"fingerprint_{name}"
    key = _build_key(full_name, labels)
    _counters[key] = _counters.get(key, 0.0) + 1.0

def observe_value(name: str, value: float, labels: Optional[Dict[str, str]] = None) -> None:
    full_name = name if name.startswith("fingerprint_") else f"fingerprint_{name}"
    key = _build_key(full_name, labels)
    _observations[key] = value

def set_last_best_solution(solution: Optional[Dict[str, Any]]) -> None:
    global _last_best_solution
    _last_best_solution = solution

def get_metric(name: str, security_config: Optional[Dict[str, Any]] = None) -> Dict[str, float]:
    """
    Helper pour récupérer les valeurs d'une métrique spécifique sous forme de dict (labels -> valeur).
    """
    result: Dict[str, float] = {}
    query_name = name if name.startswith("fingerprint_") else f"fingerprint_{name}"
    config = security_config or {}

    if query_name == "fingerprint_security_weight":
        weights = config.get("weights", {})
        for indicator, weight in weights.items():
            if isinstance(weight, (int, float)):
                result[indicator] = float(weight)
    elif query_name == "fingerprint_security_threshold":
        thresholds = config.get("thresholds", {})
        for level, threshold in thresholds.items():
            if isinstance(threshold, (int, float)):
                result[level] = float(threshold)
    elif query_name == "fingerprint_autotuning_false_positive_rate":
        if _last_best_solution and "objectives" in _last_best_solution:
            objectives = _last_best_solution["objectives"]
            if isinstance(objectives, list) and len(objectives) > 0:
                result["fpr"] = float(objectives[0])
    elif query_name == "fingerprint_autotuning_false_negative_rate":
        if _last_best_solution and "objectives" in _last_best_solution:
            objectives = _last_best_solution["objectives"]
            if isinstance(objectives, list) and len(objectives) > 1:
                result["fnr"] = float(objectives[1])
    else:
        # Recherche dans les compteurs actifs
        for key, value in _counters.items():
            if key.startswith(query_name):
                label_key = _extract_labels_key(key, query_name)
                result[label_key] = value
        # Recherche dans les observations actives
        for key, value in _observations.items():
            if key.startswith(query_name):
                label_key = _extract_labels_key(key, query_name)
                result[label_key] = value

    return result

def _build_key(name: str, labels: Optional[Dict[str, str]]) -> str:
    if not labels:
        return f"{name}{{}}"
    return f"{name}{{{','.join(f'{k}=\"{v}\"' for k, v in sorted(labels.items()))}}}"

def _extract_labels_key(key: str, query_name: str) -> str:
    return key[len(query_name):].strip("{}") or "value"
import copy
from typing import Any, Dict, Optional, Callable

class SecurityProfiles:
    """
    Définit les profils de sécurité prédéfinis pour la bibliothèque Fingerprint en Python.
    Ces profils contiennent les poids des scores de suspicion, les seuils de déclenchement 
    et la stratégie de contournement de la liste blanche (filter_whitelist).
    """

    PROFILES: Dict[str, Dict[str, Any]] = {
        # ==========================================
        # BALANCED PROFILE (Default)
        # ==========================================
        "balanced": {
            "summary": "Balanced Profile (Default)",
            "description": (
                "A general-purpose configuration suitable for most websites, offering a good mix of "
                "security and user experience. It's sensitive enough to catch common bots without "
                "being overly aggressive towards legitimate users."
            ),
            "weights": {
                "historyScore": 0.3,
                "rotationScore": 0.5,
                "headerAnomalyScore": 0.1,
                "requestPatternScore": 0.6,
                "inconsistencyScore": 0.8,
                "behaviorScore": 0.7,
                "honeypotScore": 1.0,
                "crossLayerInconsistencyScore": 0.4,
                "timeInconsistencyScore": 0.9,
                "tlsSpoofingScore": 0.8,
                "botScore": 1.0,
                "cookieDroppingScore": 0.9,
                "threatIntelScore": 0.4,
                "clientHintsInconsistencyScore": 0.7,
                "clickVarianceScore": 0.6,
                "subnetScore": 0.5,
                "botnetClusterScore": 0.6,
                "tcpAnomalyScore": 0.8,
                "quicAnomalyScore": 0.8,
                "renderingAnomalyScore": 0.8,
                "ipReputationScore": 0.5,
            },
            "thresholds": {"low": 20, "medium": 45, "high": 75, "block": 95},
            "patterns": {
                "velocityThreshold": 800,
                "burstThreshold": 1500,
                "scrapeThreshold": 1000,
                "historySize": 10,
                "minSamples": 5,
                "regularityThreshold": 50,
                "benfordThreshold": 0.15,
                "patternWeight": 80,
                "decayFactor": 0.9,
                "inactivityReset": 5000,
            },
            "wasm": True,
            "filter_whitelist": 85.0,  # Stratégie d'inspection modérée pour les IP/chemins en liste blanche
            "use_asymmetric_tickets": True,
        },

        # ==========================================
        # STRICT PROFILE
        # ==========================================
        "strict": {
            "summary": "Strict Profile",
            "description": (
                "An aggressive configuration for sensitive applications (e.g., financial services, "
                "admin panels). It uses lower suspicion thresholds and higher penalties for anomalies, "
                "prioritizing security over user convenience. All new devices are challenged by default."
            ),
            "weights": {
                "historyScore": 0.4,
                "rotationScore": 0.6,
                "headerAnomalyScore": 0.2,
                "requestPatternScore": 0.8,
                "inconsistencyScore": 1.0,
                "behaviorScore": 0.8,
                "honeypotScore": 1.0,
                "crossLayerInconsistencyScore": 0.6,
                "timeInconsistencyScore": 1.0,
                "tlsSpoofingScore": 1.0,
                "botScore": 1.0,
                "cookieDroppingScore": 1.0,
                "threatIntelScore": 0.7,
                "clientHintsInconsistencyScore": 0.9,
                "clickVarianceScore": 0.7,
                "subnetScore": 0.7,
                "botnetClusterScore": 0.8,
                "tcpAnomalyScore": 1.0,
                "quicAnomalyScore": 1.0,
                "renderingAnomalyScore": 1.0,
            },
            "thresholds": {"low": 10, "medium": 35, "high": 65, "block": 90},
            "patterns": {
                "velocityThreshold": 1000,
                "burstThreshold": 1800,
                "scrapeThreshold": 1200,
                "historySize": 15,
                "minSamples": 4,
                "regularityThreshold": 40,
                "benfordThreshold": 0.12,
                "patternWeight": 90,
                "decayFactor": 0.85,
                "inactivityReset": 4000,
            },
            "challenge_new_devices": True,
            "wasm": True,
            "filter_whitelist": True,  # Tout comportement d'attaque certain bypass immédiatement la liste blanche
            "use_asymmetric_tickets": True,
        },

        # ==========================================
        # API PROFILE
        # ==========================================
        "api": {
            "summary": "API Profile",
            "description": (
                "Optimized for protecting API endpoints. This profile is highly sensitive to request patterns "
                "(velocity, bursts) and less reliant on browser-specific behavioral metrics. It's designed to "
                "quickly identify and throttle scrapers and automated clients."
            ),
            "weights": {
                "historyScore": 0.5,
                "rotationScore": 0.5,
                "headerAnomalyScore": 0.3,
                "requestPatternScore": 1.0,
                "inconsistencyScore": 0.7,
                "behaviorScore": 0.2,
                "honeypotScore": 1.0,
                "crossLayerInconsistencyScore": 0.5,
                "timeInconsistencyScore": 0.8,
                "tlsSpoofingScore": 0.7,
                "botScore": 0.5,
                "cookieDroppingScore": 0.8,
                "threatIntelScore": 0.5,
                "clientHintsInconsistencyScore": 0.6,
                "clickVarianceScore": 0.3,
                "subnetScore": 0.8,
                "botnetClusterScore": 0.7,
                "tcpAnomalyScore": 0.8,
                "quicAnomalyScore": 0.8,
            },
            "thresholds": {"low": 25, "medium": 50, "high": 80, "block": 95},
            "patterns": {
                "velocityThreshold": 200,
                "burstThreshold": 500,
                "scrapeThreshold": 400,
                "historySize": 20,
                "minSamples": 8,
                "regularityThreshold": 20,
                "benfordThreshold": 0.18,
                "patternWeight": 85,
                "decayFactor": 0.9,
                "inactivityReset": 10000,
            },
            "is_api_request": lambda req_path, accept_hdr: req_path.startswith("/api/") or "application/json" in (accept_hdr or ""),
            "wasm": True,
            "filter_whitelist": 75.0,  # Seuil bas pour parer au vol de clés/tokens API légitimes
            "use_asymmetric_tickets": True,
        },

        # ==========================================
        # BLOG PROFILE
        # ==========================================
        "blog": {
            "summary": "Blog Profile",
            "description": (
                "Tuned for blogs and content-heavy websites. This profile focuses on detecting content scraping "
                "and comment spam by placing a high weight on request patterns and honeypot traps, while being "
                "more lenient on behavioral metrics typical of readers."
            ),
            "weights": {
                "historyScore": 0.2,
                "rotationScore": 0.3,
                "headerAnomalyScore": 0.1,
                "requestPatternScore": 0.8,
                "inconsistencyScore": 0.7,
                "behaviorScore": 0.5,
                "honeypotScore": 1.0,
                "crossLayerInconsistencyScore": 0.4,
                "timeInconsistencyScore": 0.8,
                "tlsSpoofingScore": 0.6,
                "botScore": 0.8,
                "cookieDroppingScore": 0.7,
                "threatIntelScore": 0.3,
                "clientHintsInconsistencyScore": 0.5,
                "clickVarianceScore": 0.5,
                "subnetScore": 0.4,
                "ipReputationScore": 0.3,
                "botnetClusterScore": 0.5,
                "tcpAnomalyScore": 0.5,
                "quicAnomalyScore": 0.5,
                "renderingAnomalyScore": 0.5,
            },
            "thresholds": {"low": 25, "medium": 55, "high": 80, "block": 95},
            "patterns": {
                "velocityThreshold": 1000,
                "burstThreshold": 2000,
                "scrapeThreshold": 800,
                "historySize": 12,
                "minSamples": 5,
                "regularityThreshold": 60,
                "benfordThreshold": 0.16,
                "patternWeight": 85,
                "decayFactor": 0.92,
                "inactivityReset": 10000,
            },
            "wasm": True,
            "filter_whitelist": 90.0,  # Très tolérant, n'inspecte que si le score est presque au blocage
            "use_asymmetric_tickets": True,
        }
    }

    @classmethod
    def create_security_profile(cls, profile_name: str = "balanced", overrides: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        base_profile = cls.PROFILES.get(profile_name, cls.PROFILES["balanced"])
        if overrides is None:
            return copy.deepcopy(base_profile)
        return cls.deep_merge(base_profile, overrides)

    @classmethod
    def deep_merge(cls, target: Dict[str, Any], source: Dict[str, Any]) -> Dict[str, Any]:
        output = copy.deepcopy(target)
        for key, value in source.items():
            if isinstance(value, dict) and isinstance(output.get(key), dict):
                output[key] = cls.deep_merge(output[key], value)
            else:
                output[key] = copy.deepcopy(value)
        return output
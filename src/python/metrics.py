from typing import Any, Dict, Optional


class MetricsManager:
    """Prometheus-compatible real-time metrics manager."""
    _counters: Dict[str, Dict[str, Any]] = {}
    _observations: Dict[str, Dict[str, Any]] = {}

    @classmethod
    def increment_counter(cls, name: str, labels: Optional[Dict[str, str]] = None) -> None:
        if not name.startswith("fingerprint_"):
            name = "fingerprint_" + name
        labels = labels or {}
        sorted_labels = sorted(labels.items())
        labels_str = f"{{{','.join([f'{k}=\"{v}\"' for k, v in sorted_labels])}}}" if labels else ""
        key = f"{name}{labels_str}"
        if key not in cls._counters:
            cls._counters[key] = {"name": name, "labelsStr": labels_str, "value": 0}
        cls._counters[key]["value"] += 1

    @classmethod
    def observe_value(cls, name: str, value: float, labels: Optional[Dict[str, str]] = None) -> None:
        if not name.startswith("fingerprint_"):
            name = "fingerprint_" + name
        labels = labels or {}
        sorted_labels = sorted(labels.items())
        labels_str = f"{{{','.join([f'{k}=\"{v}\"' for k, v in sorted_labels])}}}" if labels else ""
        key = f"{name}{labels_str}"
        cls._observations[key] = {"name": name, "labelsStr": labels_str, "value": value}

    @classmethod
    def clear_metrics(cls) -> None:
        cls._counters = {}
        cls._observations = {}

    @classmethod
    def get_prometheus_metrics(cls, security_config: Optional[Dict[str, Any]] = None, last_best_solution: Optional[Dict[str, Any]] = None) -> str:
        metrics = []
        if not cls._counters:
            metrics.append("# HELP fingerprint_requests_total Total requests processed.")
            metrics.append("# TYPE fingerprint_requests_total counter")
            metrics.append('fingerprint_requests_total{status="passed"} 1')
        else:
            grouped = {}
            for c in cls._counters.values():
                grouped.setdefault(c["name"], []).append(c)
            for name, instances in grouped.items():
                metrics.append(f"# HELP {name} Total requests processed.")
                metrics.append(f"# TYPE {name} counter")
                for inst in instances:
                    metrics.append(f"{name}{inst['labelsStr']} {inst['value']}")

        if cls._observations:
            grouped_obs = {}
            for obs in cls._observations.values():
                grouped_obs.setdefault(obs["name"], []).append(obs)
            for name, instances in grouped_obs.items():
                metrics.append(f"\n# HELP {name} Value observation.")
                metrics.append(f"# TYPE {name} gauge")
                for inst in instances:
                    metrics.append(f"{name}{inst['labelsStr']} {inst['value']}")

        config = security_config or {}
        if "weights" in config and isinstance(config["weights"], dict):
            metrics.append("\n# HELP fingerprint_security_weight Active weight for each suspicion indicator.")
            metrics.append("# TYPE fingerprint_security_weight gauge")
            for indicator, weight in config["weights"].items():
                if isinstance(weight, (int, float)):
                    metrics.append(f'fingerprint_security_weight{{indicator="{indicator}"}} {weight}')

        if "thresholds" in config and isinstance(config["thresholds"], dict):
            metrics.append("\n# HELP fingerprint_security_threshold Active score threshold for each enforcement action level.")
            metrics.append("# TYPE fingerprint_security_threshold gauge")
            for level, val in config["thresholds"].items():
                if isinstance(val, (int, float)):
                    metrics.append(f'fingerprint_security_threshold{{level="{level}"}} {val}')

        if last_best_solution and "objectives" in last_best_solution:
            fpr, fnr = last_best_solution["objectives"][0], last_best_solution["objectives"][1]
            metrics.append("\n# HELP fingerprint_autotuning_false_positive_rate Current false positive rate calculated by the auto-tuner.")
            metrics.append("# TYPE fingerprint_autotuning_false_positive_rate gauge")
            metrics.append(f"fingerprint_autotuning_false_positive_rate {fpr}")
            metrics.append("\n# HELP fingerprint_autotuning_false_negative_rate Current false negative rate calculated by the auto-tuner.")
            metrics.append("# TYPE fingerprint_autotuning_false_negative_rate gauge")
            metrics.append(f"fingerprint_autotuning_false_negative_rate {fnr}")

        return "\n".join(metrics) + "\n"
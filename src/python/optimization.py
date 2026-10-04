import copy
import json
import logging
import math
import random
import time
from typing import Any, Callable, Dict, List, Optional


def sanitize_traffic_data(traffic_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Sanitizes traffic data to protect the auto-tuner from poisoning attacks."""
    if not traffic_data:
        return []
    
    raw_logs = list(traffic_data)
    suspicious_logs = []
    passed_logs = []
    device_counts = {}
    ip_counts = {}
    subnet_counts = {}
    hw_cluster_counts = {}
    hw_cluster_cache = {}

    total_count = len(traffic_data)
    max_logs_per_device = max(3, total_count // 50) # 2%
    max_logs_per_ip = max(3, total_count // 50)      # 2%
    max_logs_per_subnet = max(5, total_count // 20)  # 5%
    max_logs_per_hw_cluster = max(3, total_count // 50) # 2%

    def get_vector_distance(v1: Dict[str, float], v2: Dict[str, float]) -> float:
        if not v1 or not v2:
            return float('inf')
        all_keys = set(v1.keys()).union(v2.keys())
        sum_sq = sum((v1.get(k, 0.0) - v2.get(k, 0.0)) ** 2 for k in all_keys)
        return math.sqrt(sum_sq)

    # Cohort compression (Anti-Sybil / Anti-Poisoning)
    clustered_logs = []
    for log in raw_logs:
        matched_cluster = None
        log_vector = log.get("vector") or {}
        log_type = log.get("type") or ""
        for cluster in clustered_logs:
            if log_type == cluster.get("type", "") and get_vector_distance(log_vector, cluster.get("vector", {})) < 5.0:
                matched_cluster = cluster
                break
        if matched_cluster is not None:
            matched_cluster["instancesCount"] = matched_cluster.get("instancesCount", 1) + 1
            matched_cluster["weight"] = 1.0 + math.log(matched_cluster["instancesCount"])
        else:
            log_copy = dict(log)
            log_copy["instancesCount"] = 1
            log_copy["weight"] = 1.0
            clustered_logs.append(log_copy)

    def get_hardware_cluster(log_entry: Dict[str, Any]) -> str:
        fp = log_entry.get("deviceHash") or log_entry.get("fingerprint") or log_entry.get("deviceFingerprint") or ""
        if fp and isinstance(fp, str):
            if fp in hw_cluster_cache:
                return hw_cluster_cache[fp]
            parts = fp.split("|")
            hw_components = [p for p in parts if len(p.split(":", 1)) == 2 and p.split(":", 1)[0] in ("gpu", "cvs", "hw")]
            result = "|".join(sorted(hw_components)) if hw_components else (log_entry.get("deviceId") or "anonymous-cluster")
            hw_cluster_cache[fp] = result
            return result
        return log_entry.get("deviceId") or "anonymous-cluster"

    for log in clustered_logs:
        dev_id = log.get("deviceId") or "anonymous"
        ip = log.get("clientIp") or log.get("ip") or "unknown"
        subnet = ip if ip == "unknown" else ".".join(ip.split(".")[:3]) + "/24"
        hw_cluster = get_hardware_cluster(log)

        current_device_count = device_counts.get(dev_id, 0)
        current_ip_count = ip_counts.get(ip, 0)
        current_subnet_count = subnet_counts.get(subnet, 0)
        current_hw_cluster_count = hw_cluster_counts.get(hw_cluster, 0)

        if (current_device_count < max_logs_per_device and
            (ip == "unknown" or current_ip_count < max_logs_per_ip) and
            (subnet == "unknown" or current_subnet_count < max_logs_per_subnet) and
            current_hw_cluster_count < max_logs_per_hw_cluster):
            device_counts[dev_id] = current_device_count + 1
            if ip != "unknown": ip_counts[ip] = current_ip_count + 1
            subnet_counts[subnet] = current_subnet_count + 1
            hw_cluster_counts[hw_cluster] = current_hw_cluster_count + 1
            (passed_logs if log.get("type") == "request_passed" else suspicious_logs).append(log)

    max_passed = max(200, len(suspicious_logs) * 9)
    return suspicious_logs + passed_logs[:max_passed]


class Individual:
    def __init__(
        self,
        thresholds: Optional[Dict[str, float]] = None,
        weights: Optional[Dict[str, float]] = None,
        patterns: Optional[Dict[str, float]] = None,
        pow_config: Optional[Dict[str, Any]] = None,
    ):
        self.thresholds = thresholds or {}
        self.weights = weights or {}
        self.objectives = [0.0, 0.0]
        self.patterns = patterns or {}
        self.pow_config = pow_config or {}
        self.rank = 0
        self.domination_count = 0
        self.dominated_solutions = []
        self.crowding_distance = 0.0


class Optimization:
    @staticmethod
    def benford_test(numbers: List[float]) -> float:
        leading_digits = []
        for n in numbers:
            s = str(n).lstrip("0.")
            if s:
                leading_digits.append(s[0])
        leading_digits = [d for d in leading_digits if "1" <= d <= "9"]
        if len(leading_digits) < 10:
            return 0.0
        counts = {str(i): 0 for i in range(1, 10)}
        valid_count = 0

        for n in numbers:
            try:
                val = abs(float(n))
            except (ValueError, TypeError):
                continue
            if val == 0.0:
                continue
            log = math.log10(val)
            factor = 10 ** math.floor(log)
            digit = math.floor(val / factor)
            if 1 <= digit <= 9:
                counts[str(digit)] += 1
                valid_count += 1

        if valid_count < 10:
            return 0.0
        benford = {1: 30.1, 2: 17.6, 3: 12.5, 4: 9.7, 5: 7.9, 6: 6.7, 7: 5.8, 8: 5.1, 9: 4.6}
        deviation = 0.0
        for i in range(1, 10):
            obs = (counts[str(i)] / valid_count) * 100.0
            exp = benford[i]
            deviation += (obs - exp) ** 2
        return math.sqrt(deviation) / 50.0

    @staticmethod
    def pareto_dominates(obj_a: List[float], obj_b: List[float]) -> bool:
        better = False
        for a, b in zip(obj_a, obj_b):
            if a > b:
                return False
            if a < b:
                better = True
        return better

    @staticmethod
    def calculate_crowding_distance(front: List[Dict[str, Any]]) -> None:
        if not front:
            return
        n = len(front)
        num_obj = len(front[0]["objectives"])
        for p in front:
            p["crowdingDistance"] = 0.0

        for i in range(num_obj):
            front.sort(key=lambda x: x["objectives"][i])
            front[0]["crowdingDistance"] = float("inf")
            front[-1]["crowdingDistance"] = float("inf")
            min_val = front[0]["objectives"][i]
            max_val = front[-1]["objectives"][i]
            if max_val == min_val:
                continue
            for j in range(1, n - 1):
                front[j]["crowdingDistance"] += (front[j+1]["objectives"][i] - front[j-1]["objectives"][i]) / (max_val - min_val)

    @staticmethod
    def non_dominated_sort(population: List[Dict[str, Any]]) -> List[List[Dict[str, Any]]]:
        fronts = [[]]
        n = len(population)
        for i in range(n):
            p1 = population[i]
            p1["dominationCount"] = 0
            p1["dominatedSolutions"] = []
            for j in range(n):
                if i == j:
                    continue
                p2 = population[j]
                if Optimization.pareto_dominates(p1["objectives"], p2["objectives"]):
                    p1["dominatedSolutions"].append(j)
                elif Optimization.pareto_dominates(p2["objectives"], p1["objectives"]):
                    p1["dominationCount"] += 1
            if p1["dominationCount"] == 0:
                p1["rank"] = 0
                fronts[0].append(p1)

        i = 0
        while len(fronts[i]) > 0:
            next_front = []
            for p1 in fronts[i]:
                for p2_idx in p1["dominatedSolutions"]:
                    p2 = population[p2_idx]
                    p2["dominationCount"] -= 1
                    if p2["dominationCount"] == 0:
                        p2["rank"] = i + 1
                        next_front.append(p2)
            i += 1
            if next_front:
                fronts.append(next_front)
            else:
                break
        return [f for f in fronts if f]

    @staticmethod
    def genetic_algorithm_multi_objective(
        create_individual: Callable[[], Any],
        fitness_function: Callable[[Any], List[float]],
        crossover: Callable[[Any, Any], Any],
        mutate: Callable[[Any], Any],
        options: Optional[Dict[str, Any]] = None
    ) -> List[Dict[str, Any]]:
        options = options or {}
        generations = options.get("generations", 50)
        population_size = options.get("populationSize", 50)
        mutation_rate = options.get("mutationRate", 0.1)

        population = []
        for _ in range(population_size):
            ind = create_individual()
            population.append({
                "individual": ind,
                "objectives": fitness_function(ind)
            })

        for _ in range(generations):
            offspring = []
            for _ in range(population_size):
                p1 = random.choice(population)
                p2 = random.choice(population)
                child_ind = crossover(p1["individual"], p2["individual"])
                if random.random() < mutation_rate:
                    child_ind = mutate(child_ind)
                offspring.append({
                    "individual": child_ind,
                    "objectives": fitness_function(child_ind)
                })

            combined = population + offspring
            fronts = Optimization.non_dominated_sort(combined)

            new_pop = []
            for front in fronts:
                if len(new_pop) + len(front) <= population_size:
                    new_pop.extend(front)
                else:
                    Optimization.calculate_crowding_distance(front)
                    front.sort(key=lambda x: x.get("crowdingDistance", 0.0), reverse=True)
                    remaining = population_size - len(new_pop)
                    new_pop.extend(front[:remaining])
                    break
            population = new_pop

        final_fronts = Optimization.non_dominated_sort(population)
        best_front = final_fronts[0] if final_fronts else []

        unique_solutions = []
        seen = set()
        for p in best_front:
            key = json.dumps(p["objectives"])
            if key not in seen:
                seen.add(key)
                unique_solutions.append({
                    "solution": p["individual"],
                    "objectives": p["objectives"]
                })
        return unique_solutions


class OptimizationOperators:
    @staticmethod
    def create_tournament_selection(options: Optional[Dict[str, Any]] = None) -> Callable[[List[Dict[str, Any]]], Dict[str, Any]]:
        options = options or {}
        tournament_size = options.get("size", 5)

        def tournament_selection(population: List[Dict[str, Any]]) -> Dict[str, Any]:
            best = None
            pop_len = len(population)
            for _ in range(tournament_size):
                individual = population[random.randint(0, pop_len - 1)]
                ind_fit = individual.get("fitness", sum(individual.get("objectives", [])) if "objectives" in individual else float("inf"))
                if best is None or ind_fit < best.get("fitness", sum(best.get("objectives", [])) if "objectives" in best else float("inf")):
                    best = individual
            return best if best is not None else population[random.randint(0, pop_len - 1)]

        return tournament_selection

    @staticmethod
    def create_full_security_config_evaluator(traffic_data: List[Dict[str, Any]]) -> Callable[[Dict[str, Any]], List[float]]:
        def evaluator(config: Dict[str, Any]) -> List[float]:
            false_positives, false_negatives = 0.0, 0.0
            total_humans, total_bots = 0.0, 0.0

            def calculate_score(log: Dict[str, Any]) -> float:
                score = 0.0
                for k, w in config.get("weights", {}).items():
                    score += log.get("vector", {}).get(k, 0) * w
                return score

            confidence_weights = {
                "request_passed": 0.7,
                "challenge_issued": 1.0,
                "request_blocked": 1.0,
                "challenge_solved": 1.5,
                "trap_triggered": 2.0,
            }

            for log in traffic_data:
                confidence = confidence_weights.get(log.get("type", ""), 1.0)
                is_likely_bot = log.get("type") in ("challenge_issued", "request_blocked", "trap_triggered")
                is_likely_human = log.get("type") in ("request_passed", "challenge_solved")

                if is_likely_bot:
                    total_bots += confidence
                    score = calculate_score(log)
                    if score < config.get("thresholds", {}).get("low", 20):
                        false_negatives += confidence
                elif is_likely_human:
                    total_humans += confidence
                    score = calculate_score(log)
                    if score >= config.get("thresholds", {}).get("low", 20):
                        false_positives += confidence

            fpr = false_positives / total_humans if total_humans > 0 else 0.0
            fnr = false_negatives / total_bots if total_bots > 0 else 0.0
            return [fpr, fnr]
        return evaluator

    @staticmethod
    def solve_full_security_tuning(traffic_data: List[Dict[str, Any]], options: Optional[Dict[str, Any]] = None, current_config: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        fitness_fn = OptimizationOperators.create_full_security_config_evaluator(traffic_data)

        def create_individual() -> Dict[str, Any]:
            if current_config:
                ind = {
                    "thresholds": {},
                    "weights": copy.deepcopy(current_config.get("weights", {})),
                    "patterns": {},
                    "pow": {},
                }
                for section in ("thresholds", "patterns"):
                    if section in current_config:
                        for k, v in current_config[section].items():
                            if isinstance(v, (int, float)):
                                ind[section][k] = v * (1.0 + random.uniform(-0.25, 0.25))
                            else:
                                ind[section][k] = v
                cpu_cfg = current_config.get("cpu", {})
                base_ttl = current_config.get("challengeTtl", 300)
                ind["pow"] = {
                    "challengeTtl": max(60, min(900, int(base_ttl * (1.0 + random.uniform(-0.2, 0.2))))),
                    "minDifficultyBits": max(4, min(16, int(cpu_cfg.get("minDifficultyBits", 8) + random.choice([-1, 0, 1])))),
                    "maxDifficultyBits": max(16, min(28, int(cpu_cfg.get("maxDifficultyBits", 22) + random.choice([-1, 0, 1])))),
                }
                if "low" in ind["thresholds"] and "medium" in ind["thresholds"] and "high" in ind["thresholds"]:
                    ind["thresholds"]["low"] = max(10.0, min(35.0, ind["thresholds"]["low"]))
                    ind["thresholds"]["medium"] = max(ind["thresholds"]["low"] + 5.0, min(70.0, ind["thresholds"]["medium"]))
                    ind["thresholds"]["high"] = max(ind["thresholds"]["medium"] + 5.0, min(90.0, ind["thresholds"]["high"]))
                return ind
            return {
                "thresholds": {"low": 15 + random.random() * 20, "medium": 40 + random.random() * 25, "high": 70 + random.random() * 20},
                "weights": {},
                "patterns": {
                    "velocityThreshold": 100 + random.random() * 400, "burstThreshold": 300 + random.random() * 700,
                    "scrapeThreshold": 500 + random.random() * 1000, "regularityThreshold": 50 + random.random() * 200,
                    "decayFactor": 0.85 + random.random() * 0.14, "inactivityReset": 15000 + random.random() * 45000
                },
                "pow": {
                    "challengeTtl": random.randint(180, 420),
                    "minDifficultyBits": random.randint(6, 12),
                    "maxDifficultyBits": random.randint(18, 24),
                },
            }

        def crossover(c1: Dict[str, Any], c2: Dict[str, Any]) -> Dict[str, Any]:
            child = copy.deepcopy(c1)
            for section in ("thresholds", "patterns", "pow"):
                if section in child and section in c2:
                    for k in child[section]:
                        if k in c2[section] and isinstance(child[section][k], (int, float)):
                            child[section][k] = (c1[section][k] + c2[section][k]) / 2.0
            return child

        def mutate(c: Dict[str, Any]) -> Dict[str, Any]:
            new_config = copy.deepcopy(c)
            # Les poids restent invariants pour préserver la baseline multi-couches
            sections = [
                {"name": "thresholds", "weight": 0.45},
                {"name": "pow", "weight": 0.35},
                {"name": "patterns", "weight": 0.20},
            ]
            rand = random.random()
            cumulative = 0.0
            section_to_mutate = "thresholds"
            for section in sections:
                cumulative += section["weight"]
                if rand < cumulative:
                    section_to_mutate = section["name"]
                    break
            keys = list(new_config.get(section_to_mutate, {}).keys())
            if not keys:
                return new_config
            key_to_mutate = random.choice(keys)
            mutation_amount = (random.random() - 0.5) * 0.4
            if section_to_mutate == "pow":
                if key_to_mutate == "challengeTtl":
                    new_config["pow"][key_to_mutate] = max(60, min(900, int(new_config["pow"][key_to_mutate] * (1.0 + mutation_amount))))
                elif key_to_mutate in ("minDifficultyBits", "maxDifficultyBits"):
                    new_config["pow"][key_to_mutate] = max(4, min(28, int(new_config["pow"][key_to_mutate] + random.choice([-1, 1]))))
            else:
                new_config[section_to_mutate][key_to_mutate] *= (1.0 + mutation_amount)
            return new_config

        return Optimization.genetic_algorithm_multi_objective(create_individual, fitness_fn, crossover, mutate, options)

    @staticmethod
    def evaluate_facility_location(facilities: List[Dict[str, float]], payload: Dict[str, Any]) -> float:
        customers = payload.get("customers", [])
        fixed_cost = payload.get("options", {}).get("fixedCostPerFacility", 0.0)
        total_connection_cost = sum(
            math.sqrt(min((c["x"] - f["x"])**2 + (c["y"] - f["y"])**2 for f in facilities))
            for c in customers
        ) if facilities else 0.0
        return total_connection_cost + len(facilities) * fixed_cost

    @staticmethod
    def solve_facility_location(customers: List[Dict[str, float]], num_facilities: int, bounds: Dict[str, float], options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        options = options or {}
        cooling_rate = options.get("coolingRate", 0.999)
        max_iterations = options.get("maxIterations", 5000)
        temperature = options.get("initialTemperature", 100000.0)

        current_solution = [{
            "x": bounds["minX"] + random.random() * (bounds["maxX"] - bounds["minX"]),
            "y": bounds["minY"] + random.random() * (bounds["maxY"] - bounds["minY"])
        } for _ in range(num_facilities)]
        current_energy = OptimizationOperators.evaluate_facility_location(current_solution, {"customers": customers, "options": options})
        best_solution, best_energy = current_solution, current_energy

        for _ in range(max_iterations):
            new_sol = copy.deepcopy(current_solution)
            idx = random.randint(0, num_facilities - 1)
            new_sol[idx]["x"] = max(bounds["minX"], min(bounds["maxX"], new_sol[idx]["x"] + (random.random() - 0.5) * (bounds["maxX"] - bounds["minX"]) * 0.1))
            new_sol[idx]["y"] = max(bounds["minY"], min(bounds["maxY"], new_sol[idx]["y"] + (random.random() - 0.5) * (bounds["maxY"] - bounds["minY"]) * 0.1))
            new_energy = OptimizationOperators.evaluate_facility_location(new_sol, {"customers": customers, "options": options})
            delta = new_energy - current_energy
            if delta < 0 or (temperature > 0 and random.random() < math.exp(-delta / max(1e-9, temperature))):
                current_solution, current_energy = new_sol, new_energy
                if current_energy < best_energy:
                    best_solution, best_energy = current_solution, current_energy
            temperature *= cooling_rate

        return {"solution": best_solution, "energy": best_energy}


class AutoTuner:
    _last_best_solution: Optional[Dict[str, Any]] = None

    def __init__(self, security_config: Dict[str, Any], store, options: Optional[Dict[str, Any]] = None):
        self.security_config = security_config
        self.store = store
        self.traffic_data = store
        options = options or {}
        self.min_data_points = options.get("min_data_points") or options.get("minDataPoints") or 200
        self.max_data_points = options.get("max_data_points") or options.get("maxDataPoints") or 10000
        self.max_age_ms = options.get("max_age_ms") or options.get("maxAgeMs")
        self.validation_tolerance = options.get("validation_tolerance") or options.get("validationTolerance") or 0.15
        self.interval_minutes = options.get("interval", 30)
        self.save_path = options.get("save_path")
        self.clear_after_tuning = options.get("clear_after_tuning", False)
        self.on_cleanup = options.get("on_cleanup")
        self.last_best_solution = None

    @staticmethod
    def get_best_tuning_solution() -> Optional[Dict[str, Any]]:
        return AutoTuner._last_best_solution

    @staticmethod
    def reset_best_tuning_solution() -> None:
        AutoTuner._last_best_solution = None

    def run_optimization_cycle(self) -> Any:
        if isinstance(self.store, list):
            return self._run_optimization_cycle_sync()
        return self._run_optimization_cycle_async()

    async def _run_optimization_cycle_async(self) -> None:
        raw_logs = await self.store.get("traffic_logs") or []
        if not raw_logs:
            return
        self._prune_logs(raw_logs)
        await self.store.set("traffic_logs", raw_logs)
        self._optimize_on_logs(raw_logs)
        if self.clear_after_tuning:
            await self.store.delete("traffic_logs")

    def _run_optimization_cycle_sync(self) -> None:
        raw_logs = self.store
        if not raw_logs:
            return
        self._prune_logs(raw_logs)
        self._optimize_on_logs(raw_logs)
        if self.clear_after_tuning and isinstance(self.store, list):
            self.store.clear()

    def _optimize_on_logs(self, raw_logs: List[Dict[str, Any]]) -> None:
        sanitized_data = sanitize_traffic_data(raw_logs)
        high_confidence_logs = sum(log.get("instancesCount", 1) for log in sanitized_data if log.get("type") in ("challenge_solved", "trap_triggered"))
        total_sanitized_instances = sum(log.get("instancesCount", 1) for log in sanitized_data)
        high_confidence_ratio = high_confidence_logs / total_sanitized_instances if total_sanitized_instances else 0.0

        if total_sanitized_instances < self.min_data_points or (high_confidence_ratio < 0.05 and high_confidence_logs < 10):
            return

        pareto_front = self.solve_full_security_tuning(sanitized_data)
        if not pareto_front: return
        filtered_front = [
            ind for ind in pareto_front
            if self.is_valid_security_config(ind.thresholds, ind.weights) and self.is_valid_pow_config(ind.pow_config)
        ] or pareto_front
        best_solution = min(filtered_front, key=lambda ind: math.sqrt(ind.objectives[0]**2 + ind.objectives[1]**2))
        traffic_confidence = min(1.5, max(0.3, high_confidence_ratio * 4.0))

        temp_thresholds = dict(self.security_config.get("thresholds", {}))
        temp_patterns = dict(self.security_config.get("patterns", {}))
        temp_pow = {
            "challengeTtl": self.security_config.get("challengeTtl", 300),
            "minDifficultyBits": self.security_config.get("cpu", {}).get("minDifficultyBits", 8),
            "maxDifficultyBits": self.security_config.get("cpu", {}).get("maxDifficultyBits", 22),
        }
        self.apply_inertial_update(temp_thresholds, best_solution.thresholds, "thresholds", traffic_confidence)
        self.apply_inertial_update(temp_patterns, best_solution.patterns, "patterns", traffic_confidence)
        self.apply_inertial_update(temp_pow, best_solution.pow_config, "pow", traffic_confidence)

        current_weights = self.security_config.get("weights", {})
        current_obj = self.evaluate_fitness(self.security_config.get("thresholds", {}), current_weights, sanitized_data, temp_pow)
        proposed_obj = self.evaluate_fitness(temp_thresholds, current_weights, sanitized_data, temp_pow)
        if proposed_obj[0] > current_obj[0] + self.validation_tolerance or proposed_obj[1] > current_obj[1] + self.validation_tolerance:
            return

        self.security_config.setdefault("thresholds", {})
        self.security_config.setdefault("patterns", {})
        self.security_config.setdefault("cpu", {})
        self.apply_inertial_update(self.security_config["thresholds"], best_solution.thresholds, "thresholds", traffic_confidence)
        self.apply_inertial_update(self.security_config["patterns"], best_solution.patterns, "patterns", traffic_confidence)
        self.apply_inertial_update(temp_pow, best_solution.pow_config, "pow", traffic_confidence)
        self.security_config["challengeTtl"] = temp_pow["challengeTtl"]
        self.security_config["cpu"]["minDifficultyBits"] = temp_pow["minDifficultyBits"]
        self.security_config["cpu"]["maxDifficultyBits"] = temp_pow["maxDifficultyBits"]

        self.last_best_solution = {
            "thresholds": self.security_config["thresholds"],
            "weights": self.security_config.get("weights", {}),
            "patterns": self.security_config.get("patterns", {}),
            "challengeTtl": self.security_config["challengeTtl"],
            "cpu": self.security_config["cpu"],
            "pow": temp_pow,
            "objectives": best_solution.objectives,
        }
        AutoTuner._last_best_solution = self.last_best_solution
        if self.save_path:
            try:
                with open(self.save_path, 'w', encoding='utf-8') as f:
                    json.dump(self.last_best_solution, f, indent=2)
            except Exception as e:
                logging.error(f"[AutoTuning] Failed to save optimized config: {e}")

    def _prune_logs(self, logs: List[Dict[str, Any]]) -> None:
        now = int(time.time() * 1000)
        removed = []
        if hasattr(self, "max_age_ms") and self.max_age_ms and self.max_age_ms > 0:
            threshold = now - self.max_age_ms
            i = 0
            while i < len(logs):
                log_ts = logs[i].get("timestamp") or logs[i].get("requestTimestamp") or now
                if log_ts < threshold:
                    removed.append(logs.pop(i))
                else:
                    i += 1
        if self.max_data_points and len(logs) > self.max_data_points:
            overflow_count = len(logs) - self.max_data_points
            removed.extend(logs[:overflow_count])
            del logs[:overflow_count]
        if self.on_cleanup and callable(self.on_cleanup) and removed:
            try:
                self.on_cleanup(removed)
            except Exception as e:
                logging.error(f"[AutoTuning] Error in on_cleanup callback: {e}")

    def is_valid_security_config(self, thresholds: Dict[str, float], weights: Dict[str, float]) -> bool:
        active_weights_sum = sum(weights.get(k, 0.0) for k in [
            "inconsistencyScore", "tlsSpoofingScore", "requestPatternScore", "behaviorScore", "botScore"
        ])
        if active_weights_sum < 1.5:
            return False
        low = thresholds.get("low", 0.0)
        medium = thresholds.get("medium", 0.0)
        high = thresholds.get("high", 0.0)
        block = thresholds.get("block", 0.0)
        return 10 <= low <= 35 and low + 5 <= medium <= 70 and medium + 5 <= high <= 90 and high + 5 <= block <= 99

    def is_valid_pow_config(self, pow_config: Optional[Dict[str, Any]]) -> bool:
        if not pow_config:
            return True
        ttl = pow_config.get("challengeTtl", 300)
        min_b = pow_config.get("minDifficultyBits", 8)
        max_b = pow_config.get("maxDifficultyBits", 22)
        return 60 <= ttl <= 900 and 4 <= min_b <= 16 and min_b <= max_b <= 28

    def apply_inertial_update(self, current: Dict[str, Any], target: Dict[str, Any], type_: str, confidence: float) -> None:
        learning_rate = max(0.02, min(0.40, 0.15 * confidence))
        for key in current.keys():
            if key in target:
                cur_val = float(current[key])
                tar_val = float(target[key])
                updated = cur_val + (tar_val - cur_val) * learning_rate
                if type_ == "weights":
                    pass  # Poids strictement invariants sur trafic hétérogène
                elif type_ == "thresholds":
                    current[key] = int(round(updated))
                elif type_ == "patterns":
                    current[key] = updated
                elif type_ == "pow":
                    if key == "challengeTtl":
                        current[key] = max(60, min(900, int(round(updated))))
                    elif key in ("minDifficultyBits", "maxDifficultyBits"):
                        current[key] = max(4, min(28, int(round(updated))))
        if type_ == "thresholds":
            low = max(10, min(35, int(current.get("low", 20))))
            medium = max(low + 8, min(65, int(current.get("medium", 45))))
            high = max(medium + 8, min(85, int(current.get("high", 75))))
            block = max(high + 8, min(98, int(current.get("block", 95))))
            current.update({"low": low, "medium": medium, "high": high, "block": block})
        elif type_ == "pow":
            if current.get("minDifficultyBits", 8) > current.get("maxDifficultyBits", 22):
                current["minDifficultyBits"] = max(4, current.get("maxDifficultyBits", 22) - 2)

    def evaluate_fitness(self, thresholds: Dict[str, Any], weights: Dict[str, Any], traffic_data: List[Dict[str, Any]], pow_config: Optional[Dict[str, Any]] = None) -> List[float]:
        threat_profiles = {
            "account_takeover": {"importance": 10.0, "ux_ratio": 0.1, "indicators": ["requestPatternScore", "behaviorScore", "timeInconsistencyScore", "clickVarianceScore"]},
            "active_exploitation": {"importance": 8.0, "ux_ratio": 0.2, "indicators": ["honeypotScore", "headerAnomalyScore"]},
            "mass_scraping": {"importance": 3.0, "ux_ratio": 0.8, "indicators": ["requestPatternScore", "renderingAnomalyScore", "clientHintsInconsistencyScore", "virtualizationScore"]},
            "distributed_botnets": {"importance": 6.0, "ux_ratio": 0.5, "indicators": ["subnetScore", "botnetClusterScore", "ipReputationScore", "tlsSpoofingScore"]},
            "basic_automation": {"importance": 5.0, "ux_ratio": 0.4, "indicators": ["botScore", "tlsSpoofingScore", "tcpAnomalyScore", "virtualizationScore"]}
        }
        threat_stats = {name: {"fp": 0.0, "fn": 0.0, "totalHumans": 0.0, "totalBots": 0.0} for name in threat_profiles}
        low_threshold = float(thresholds.get("low", 20.0))
        max_human_score, min_bot_score = 0.0, 100.0

        for log in traffic_data:
            vector = log.get("vector", {})
            score = sum(float(vector.get(k, 0.0)) * float(weights.get(k, 0.0)) for k in weights)
            is_bot = log.get("type") in ("request_blocked", "trap_triggered")
            is_human = log.get("type") in ("request_passed", "challenge_solved")

            if is_bot:
                min_bot_score = min(min_bot_score, score)
            elif is_human:
                max_human_score = max(max_human_score, score)

            for name, profile in threat_profiles.items():
                threat_score = sum(float(vector.get(ind, 0.0)) * float(weights.get(ind, 0.0)) for ind in profile["indicators"])
                if is_bot:
                    threat_stats[name]["totalBots"] += 1.0
                    if threat_score < low_threshold:
                        threat_stats[name]["fn"] += 1.0
                elif is_human:
                    threat_stats[name]["totalHumans"] += 1.0
                    if threat_score >= low_threshold:
                        threat_stats[name]["fp"] += 1.0

        total_importance = sum(p["importance"] for p in threat_profiles.values())
        weighted_fpr, weighted_fnr = 0.0, 0.0
        for name, profile in threat_profiles.items():
            stats = threat_stats[name]
            fpr = stats["fp"] / stats["totalHumans"] if stats["totalHumans"] > 0 else 0.0
            fnr = stats["fn"] / stats["totalBots"] if stats["totalBots"] > 0 else 0.0
            weight = profile["importance"] / total_importance
            weighted_fpr += fpr * weight * profile["ux_ratio"]
            weighted_fnr += fnr * weight * (1.0 - profile["ux_ratio"])

        margin_penalty = max(0.0, max_human_score - min_bot_score) / 100.0
        pow_penalty = 0.0
        if pow_config:
            min_bits = pow_config.get("minDifficultyBits", 8)
            max_bits = pow_config.get("maxDifficultyBits", 22)
            ttl = pow_config.get("challengeTtl", 300)
            if min_bits > 14:
                pow_penalty += (min_bits - 14) * 0.015
            if ttl < 90:
                pow_penalty += 0.02
            if max_bits < min_bits:
                pow_penalty += 0.1
        return [weighted_fpr + pow_penalty, weighted_fnr + margin_penalty]

    def solve_full_security_tuning(self, traffic_data: List[Dict[str, Any]]) -> List[Individual]:
        population = [self.random_individual() for _ in range(50)]
        for ind in population:
            ind.objectives = self.evaluate_fitness(ind.thresholds, ind.weights, traffic_data)

        for _ in range(50):
            offspring = []
            for _ in range(50):
                child = self.crossover(random.choice(population), random.choice(population))
                if random.random() < 0.1:
                    self.mutate(child)
                child.objectives = self.evaluate_fitness(child.thresholds, child.weights, traffic_data, child.pow_config)
                offspring.append(child)

            combined = population + offspring
            fronts = self.non_dominated_sort(combined)
            new_pop = []
            for front in fronts:
                if len(new_pop) + len(front) <= 50:
                    new_pop.extend(front)
                else:
                    break
            population = new_pop or combined[:50]

        return self.non_dominated_sort(population)[0]

    def random_individual(self) -> Individual:
        ind = Individual()
        low = random.randint(10, 35)
        medium = low + 10 + random.randint(0, 25)
        high = medium + 10 + random.randint(0, 20)
        block = high + 8 + random.randint(0, 10)
        ind.thresholds = {"low": low, "medium": medium, "high": high, "block": block}
        # Maintien strict de l'invariance des poids
        ind.weights = copy.deepcopy(self.security_config.get("weights", {}))
        ind.patterns = {k: v * (0.5 + random.random()) if isinstance(v, (int, float)) else v for k, v in self.security_config.get("patterns", {}).items()}
        cpu_cfg = self.security_config.get("cpu", {})
        base_ttl = self.security_config.get("challengeTtl", 300)
        base_min = cpu_cfg.get("minDifficultyBits", 8)
        base_max = cpu_cfg.get("maxDifficultyBits", 22)
        ind.pow_config = {
            "challengeTtl": max(60, min(900, int(base_ttl + random.randint(-60, 60)))),
            "minDifficultyBits": max(4, min(16, int(base_min + random.randint(-2, 2)))),
            "maxDifficultyBits": max(16, min(28, int(base_max + random.randint(-2, 2)))),
        }
        return ind

    def crossover(self, p1: Individual, p2: Individual) -> Individual:
        child = Individual()
        child.thresholds = {k: int(round((p1.thresholds[k] + p2.thresholds[k]) / 2.0)) for k in p1.thresholds}
        child.weights = copy.deepcopy(self.security_config.get("weights", {}))
        child.patterns = copy.deepcopy(p1.patterns)
        child.pow_config = {
            k: int(round((p1.pow_config.get(k, 0) + p2.pow_config.get(k, 0)) / 2.0))
            for k in p1.pow_config
        }
        return child

    def mutate(self, ind: Individual) -> None:
        target = random.choice(["thresholds", "pow_config"])
        if target == "thresholds" and ind.thresholds:
            k = random.choice(list(ind.thresholds.keys()))
            ind.thresholds[k] = max(10, ind.thresholds[k] + random.choice([2, -2]))
        elif target == "pow_config" and ind.pow_config:
            k = random.choice(list(ind.pow_config.keys()))
            if k == "challengeTtl":
                ind.pow_config[k] = max(60, min(900, ind.pow_config[k] + random.choice([30, -30])))
            elif k in ("minDifficultyBits", "maxDifficultyBits"):
                ind.pow_config[k] = max(4, min(28, ind.pow_config[k] + random.choice([1, -1])))
                if ind.pow_config.get("minDifficultyBits", 8) > ind.pow_config.get("maxDifficultyBits", 22):
                    ind.pow_config["minDifficultyBits"] = ind.pow_config["maxDifficultyBits"] - 2

    def non_dominated_sort(self, population: List[Individual]) -> List[List[Individual]]:
        fronts = [[]]
        for p1 in population:
            p1.domination_count = 0
            p1.dominated_solutions = []
            for p2 in population:
                if p1 is p2:
                    continue
                if Optimization.pareto_dominates(p1.objectives, p2.objectives):
                    p1.dominated_solutions.append(p2)
                elif Optimization.pareto_dominates(p2.objectives, p1.objectives):
                    p1.domination_count += 1
            if p1.domination_count == 0:
                fronts[0].append(p1)
        return fronts
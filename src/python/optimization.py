import copy
import json
import logging
import math
import random
import time
from typing import Any, Callable, Dict, List, Optional


class Individual:
    def __init__(self, thresholds: Optional[Dict[str, float]] = None, weights: Optional[Dict[str, float]] = None, patterns: Optional[Dict[str, float]] = None):
        self.thresholds = thresholds or {}
        self.weights = weights or {}
        self.objectives = [0.0, 0.0]
        self.patterns = patterns or {}
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

    def _run_optimization_cycle_sync(self) -> None:
        raw_logs = self.store
        if not raw_logs:
            return

        self._prune_logs(raw_logs)
        from engine import sanitize_traffic_data
        sanitized_data = sanitize_traffic_data(raw_logs)

        high_confidence_logs = sum(
            log.get("instancesCount", 1) for log in sanitized_data 
            if log.get("type") in ("challenge_solved", "trap_triggered")
        )
        total_sanitized_instances = sum(log.get("instancesCount", 1) for log in sanitized_data)
        high_confidence_ratio = (
            high_confidence_logs / total_sanitized_instances if total_sanitized_instances else 0.0
        )

        if total_sanitized_instances < self.min_data_points or (high_confidence_ratio < 0.05 and high_confidence_logs < 10):
            return

        pareto_front = self.solve_full_security_tuning(sanitized_data)
        if not pareto_front:
            return

        filtered_front = [
            ind for ind in pareto_front 
            if self.is_valid_security_config(ind.thresholds, ind.weights)
        ] or pareto_front

        best_solution = min(filtered_front, key=lambda ind: math.sqrt(ind.objectives[0]**2 + ind.objectives[1]**2))
        traffic_confidence = min(1.5, max(0.3, high_confidence_ratio * 4.0))

        temp_thresholds = dict(self.security_config.get("thresholds", {}))
        temp_weights = dict(self.security_config.get("weights", {}))
        temp_patterns = dict(self.security_config.get("patterns", {}))

        self.apply_inertial_update(temp_thresholds, best_solution.thresholds, "thresholds", traffic_confidence)
        self.apply_inertial_update(temp_weights, best_solution.weights, "weights", traffic_confidence)
        self.apply_inertial_update(temp_patterns, best_solution.patterns, "patterns", traffic_confidence)

        current_obj = self.evaluate_fitness(self.security_config.get("thresholds", {}), self.security_config.get("weights", {}), sanitized_data)
        proposed_obj = self.evaluate_fitness(temp_thresholds, temp_weights, sanitized_data)

        if (proposed_obj[0] > current_obj[0] + self.validation_tolerance or 
            proposed_obj[1] > current_obj[1] + self.validation_tolerance):
            return

        self.apply_inertial_update(self.security_config["thresholds"], best_solution.thresholds, "thresholds", traffic_confidence)
        self.apply_inertial_update(self.security_config["weights"], best_solution.weights, "weights", traffic_confidence)
        self.security_config.setdefault("patterns", {})
        self.apply_inertial_update(self.security_config["patterns"], best_solution.patterns, "patterns", traffic_confidence)

        self.last_best_solution = {
            "thresholds": self.security_config["thresholds"],
            "weights": self.security_config["weights"],
            "patterns": self.security_config["patterns"],
            "objectives": best_solution.objectives
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

    def apply_inertial_update(self, current: Dict[str, Any], target: Dict[str, float], type_: str, confidence: float) -> None:
        learning_rate = max(0.02, min(0.40, 0.15 * confidence))
        for key in current.keys():
            if key in target:
                cur_val = float(current[key])
                tar_val = float(target[key])
                updated = cur_val + (tar_val - cur_val) * learning_rate
                if type_ == "weights":
                    current[key] = max(0.05, min(1.8, updated))
                elif type_ == "thresholds":
                    current[key] = int(round(updated))
                elif type_ == "patterns":
                    current[key] = updated
        if type_ == "thresholds":
            low = max(10, min(35, int(current.get("low", 20))))
            medium = max(low + 8, min(65, int(current.get("medium", 45))))
            high = max(medium + 8, min(85, int(current.get("high", 75))))
            block = max(high + 8, min(98, int(current.get("block", 95))))
            current.update({"low": low, "medium": medium, "high": high, "block": block})

    def evaluate_fitness(self, thresholds: Dict[str, Any], weights: Dict[str, Any], traffic_data: List[Dict[str, Any]]) -> List[float]:
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
        return [weighted_fpr, weighted_fnr + margin_penalty]

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
                child.objectives = self.evaluate_fitness(child.thresholds, child.weights, traffic_data)
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
        ind.weights = {k: float(v) for k, v in self.security_config.get("weights", {}).items()}
        ind.patterns = {k: v * (0.5 + random.random()) if isinstance(v, (int, float)) else v for k, v in self.security_config.get("patterns", {}).items()}
        return ind

    def crossover(self, p1: Individual, p2: Individual) -> Individual:
        child = Individual()
        child.thresholds = {k: int(round((p1.thresholds[k] + p2.thresholds[k]) / 2.0)) for k in p1.thresholds}
        child.weights = copy.deepcopy(p1.weights)
        child.patterns = copy.deepcopy(p1.patterns)
        return child

    def mutate(self, ind: Individual) -> None:
        if random.random() < 0.5:
            k = random.choice(list(ind.thresholds.keys()))
            ind.thresholds[k] = max(10, ind.thresholds[k] + random.choice([2, -2]))

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
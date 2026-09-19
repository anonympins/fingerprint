import json
import os
import math
import time
import random
import asyncio
from typing import Dict, List, Any, Optional
from upow_model_task import UpowModelTask, TensorFlowModelTask
# --- FunctionRegistry ---
FunctionRegistry = {}

def facility_calculate_energy(facilities, payload):
    customers = payload.get("customers", [])
    fixed_cost = payload.get("options", {}).get("fixedCostPerFacility", 0.0)
    total_connection_cost = 0.0
    for customer in customers:
        min_dist_sq = float("inf")
        for facility in facilities:
            dx = customer["x"] - facility["x"]
            dy = customer["y"] - facility["y"]
            d_sq = dx * dx + dy * dy
            if d_sq < min_dist_sq:
                min_dist_sq = d_sq
        total_connection_cost += math.sqrt(min_dist_sq)
    return total_connection_cost + len(facilities) * fixed_cost

def tsp_calculate_energy(path, payload):
    cities = payload.get("cities") or payload.get("points") or []
    if path and isinstance(path[0], (int, float)) and not isinstance(path[0], dict):
        distance = 0.0
        for i in range(len(path)):
            p1 = cities[path[i]]
            p2 = cities[path[(i + 1) % len(path)]]
            distance += math.sqrt((p1["x"] - p2["x"])**2 + (p1["y"] - p2["y"])**2)
        return distance
    distance = 0.0
    num_pts = len(path)
    for i in range(num_pts):
        p1 = path[i]
        p2 = path[(i + 1) % num_pts]
        distance += math.sqrt((p1["x"] - p2["x"])**2 + (p1["y"] - p2["y"])**2)
    return distance

def portfolio_calculate_metrics(weights, payload):
    assets = payload.get("assets", [])
    max_volatility = payload.get("maxVolatility")
    expected_return = 0.0
    portfolio_volatility = 0.0
    for i, weight in enumerate(weights):
        if i < len(assets):
            expected_return += weight * assets[i].get("expectedReturn", 0.0)
            portfolio_volatility += weight * assets[i].get("volatility", 0.0)
    penalty = 0.0
    if max_volatility is not None and portfolio_volatility > max_volatility:
        penalty = (portfolio_volatility - max_volatility) * 50.0
    return -expected_return + penalty

FunctionRegistry['facility.calculateEnergy'] = facility_calculate_energy
FunctionRegistry['tsp.calculateEnergy'] = tsp_calculate_energy
FunctionRegistry['portfolio.calculateMetrics'] = portfolio_calculate_metrics

# --- ProblemInitializers ---
async def generate_random_points(params):
    count = params.get("count", 0)
    bounds = params.get("bounds", {"x": 1000, "y": 1000})
    points = []
    for _ in range(count):
        points.append({
            "x": random.random() * bounds.get("x", 1000),
            "y": random.random() * bounds.get("y", 1000)
        })
        if len(points) % 5000 == 0:
            await asyncio.sleep(0)
    return points

async def generate_random_assets(params):
    count = params.get("count", 0)
    assets = []
    for i in range(count):
        assets.append({
            "name": f"Asset {i + 1}",
            "expectedReturn": random.random() * 0.2,
            "volatility": 0.1 + random.random() * 0.3
        })
        if len(assets) % 5000 == 0:
            await asyncio.sleep(0)
    return assets

ProblemInitializers = {
    'generate:randomPoints': generate_random_points,
    'generate:randomAssets': generate_random_assets
}

class ProblemManager:
    _instance = None

    def __new__(cls, config_path: str, store: Any):
        if cls._instance is None:
            cls._instance = super(ProblemManager, cls).__new__(cls)
            cls._instance.config_path = config_path or ""
            cls._instance.store = store
            cls._instance.problems = []
            cls._instance.model_tasks = {}
            cls._instance.current_problem_index = 0
            cls._instance.initialized = False
        elif config_path and cls._instance.config_path != config_path:
            cls._instance.config_path = config_path
            cls._instance.initialized = False
        return cls._instance

    @classmethod
    def get_instance(cls, config_path: Optional[str] = None, store: Optional[Any] = None) -> "ProblemManager":
        if cls._instance is None:
            if config_path is None:
                default_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../config/problems.config.json"))
                config_path = default_path if os.path.exists(default_path) else ""
            if not config_path or store is None:
                raise RuntimeError("ProblemManager must be initialized with config_path and store.")
            cls._instance = cls(config_path, store)
        elif config_path and cls._instance.config_path != config_path:
            cls._instance.config_path = config_path
            cls._instance.initialized = False
        return cls._instance

    def register_model_task(self, task: UpowModelTask) -> None:
        self.model_tasks[task.get_problem_id()] = task

    async def load_problems(self) -> None:
        if self.initialized:
            return
        self.problems.clear()

        if not os.path.exists(self.config_path):
            print(f"[ProblemManager] Problem config file not found: {self.config_path}")
            return

        try:
            with open(self.config_path, 'r', encoding='utf-8') as f:
                problems_from_file = json.load(f)

            for problem in problems_from_file:
                problem_id = problem["id"]
                store_key = f"problem-state:{problem_id}"
                stored_state = await self.store.get(store_key)

                if stored_state is None:
                    stored_state = problem.get("state", {})
                    await self.store.set(store_key, stored_state)

                problem["state"] = stored_state

                # Resolve scoreFunction from registry
                work_unit = problem.get("workUnit", {})
                score_func_name = work_unit.get("scoreFunction")
                if score_func_name:
                    work_unit["scoreFunction"] = FunctionRegistry.get(score_func_name)

                # Dynamic initialization of payload
                payload = problem.get("payload", {})
                if isinstance(payload, dict):
                    for key, value in list(payload.items()):
                        if isinstance(value, dict) and "$init" in value:
                            init_type = value["$init"]
                            initializer = ProblemInitializers.get(init_type)
                            if initializer:
                                payload[key] = await initializer(value.get("params", {}))

                self.problems.append(problem)

            self.initialized = True
        except Exception as e:
            print(f"[ProblemManager] Error loading problem config JSON: {str(e)}")

    async def dispatch_work(self, suspicion_factor: float) -> Optional[Dict[str, Any]]:
        if not self.problems and not self.model_tasks:
            return None

        if self.current_problem_index >= len(self.problems):
            self.current_problem_index = 0

        if not self.problems:
            return None

        problem = self.problems[self.current_problem_index]
        self.current_problem_index = (self.current_problem_index + 1) % len(self.problems)

        work_unit = problem.get("workUnit", {})
        task_type = work_unit.get("type")
        scaling_factor = work_unit.get("scalingFactor", 1.0)
        payload = problem.get("payload", {})

        task = {"type": task_type}

        if task_type in ["tfjs_learning", "tensorflow_learning"]:
            task["modelPath"] = work_unit.get("modelPath")
            task["payload"] = payload
            
            # Récupère l'état d'un modèle TensorFlow enregistré, sinon extrait l'état statique du fichier
            registered_task = self.model_tasks.get(problem["id"])
            if registered_task:
                task["weights"] = registered_task.get_current_model_state().get("weights", [])
            else:
                task["weights"] = problem.get("state", {}).get("weights", [])

        elif task_type == "simulated_annealing_iterations":
            base_iterations = max(15000, work_unit.get("baseIterations", 15000))
            if scaling_factor:
                task["iterations"] = int(math.floor(base_iterations * math.pow(scaling_factor, suspicion_factor)))
            else:
                task["iterations"] = int(math.floor(base_iterations * (0.5 + suspicion_factor)))
            task["payload"] = payload
            task["initialSolution"] = problem.get("state", {}).get("bestSolution")

        elif task_type == "genetic_algorithm_generations":
            base_generations = max(50, work_unit.get("baseGenerations", 50))
            if scaling_factor:
                task["generations"] = int(math.floor(base_generations * math.pow(scaling_factor, suspicion_factor)))
            else:
                task["generations"] = int(math.floor(base_generations * (0.5 + suspicion_factor)))
            task["payload"] = payload
            task["initialPopulation"] = problem.get("state", {}).get("population")

        elif task_type == "multi_objective_genetic_algorithm":
            base_generations_multi = max(30, work_unit.get("baseGenerations", 30))
            if scaling_factor:
                task["generations"] = int(math.floor(base_generations_multi * math.pow(scaling_factor, suspicion_factor)))
            else:
                task["generations"] = int(math.floor(base_generations_multi * (0.5 + suspicion_factor)))
            task["payload"] = payload
            task["initialFront"] = problem.get("state", {}).get("paretoFront")
            task["solverName"] = work_unit.get("solverName")

        return {
            "problemId": problem["id"],
            "task": task
        }

    async def integrate_solution(self, problem_id: str, solution_data: Dict[str, Any]) -> None:
        if problem_id in self.model_tasks:
            task = self.model_tasks[problem_id]
            task_context = await self.store.get(f"upow-task-ctx:{problem_id}")

            if task_context is None:
                task_context = task.dispatch_task(1.0)
                await self.store.set(f"upow-task-ctx:{problem_id}", task_context)

            if task.verify_solution(task_context, solution_data):
                task.integrate_solution(solution_data)
                await self.store.set(f"problem-state:{problem_id}", task.get_current_model_state())
                print(f"[ProblemManager] TensorFlow solution integrated successfully for {problem_id}")
            else:
                print(f"[ProblemManager] Solution rejected for model {problem_id} due to verification (anti-poisoning) failure.")
        else:
            # Traitement générique par défaut s'il n'y a pas d'implémentation enregistrée
            problem = next((p for p in self.problems if p["id"] == problem_id), None)
            if not problem:
                return
            # Possibilité d'intégrer
            # d'autres types d'optimisations génériques ici

        problem = next((p for p in self.problems if p["id"] == problem_id), None)
        if not problem or not solution_data or not isinstance(solution_data, dict):
            return

        store_key = f"problem-state:{problem['id']}"
        work_unit_type = problem.get("workUnit", {}).get("type")

        try:
            if work_unit_type == "simulated_annealing_iterations":
                if "solution" not in solution_data:
                    print(f"[ProblemManager] 'solution' key missing in solutionData for {problem_id}")
                    return

                sol = solution_data["solution"]
                if isinstance(sol, list) and len(sol) > 500:
                    print(f"[ProblemManager] Solution array too large for {problem_id} verification.")
                    return

                try:
                    serialized = json.dumps(sol)
                    if len(serialized) > 65536:
                        print(f"[ProblemManager] Solution payload size exceeds safe limit for {problem_id}")
                        return
                except Exception:
                    pass

                score_function = problem.get("workUnit", {}).get("scoreFunction")
                if not score_function:
                    print(f"[ProblemManager] No score function defined for {problem_id}. Verification impossible.")
                    return

                recalculated_energy = score_function(sol, problem.get("payload", {}))
                current_best = float(problem.get("state", {}).get("bestEnergy", float("inf")))

                if recalculated_energy < current_best:
                    problem["state"]["bestSolution"] = sol
                    problem["state"]["bestEnergy"] = recalculated_energy
                    problem["state"]["lastUpdate"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                    await self.store.set(store_key, problem["state"])
                    print(f"[ProblemManager] New best solution for {problem_id}: {recalculated_energy}")

            elif work_unit_type == "genetic_algorithm_generations":
                population = solution_data.get("population")
                if not population or not isinstance(population, list):
                    print(f"[ProblemManager] Invalid population for {problem_id}")
                    return

                if len(population) > 150:
                    print(f"[ProblemManager] Population size exceeds safe limit for {problem_id}")
                    return

                for ind in population:
                    if ind and isinstance(ind, dict) and isinstance(ind.get("chromosome"), list):
                        if len(ind["chromosome"]) > 100:
                            print(f"[ProblemManager] Chromosome size too large for {problem_id}")
                            return

                fitness_fn = FunctionRegistry.get("portfolio.calculateMetrics")
                if not fitness_fn:
                    print(f"[ProblemManager] Portfolio metrics calculator not registered.")
                    return

                # Sampling verification
                sample_size = min(5, len(population))
                sample_indices = random.sample(range(len(population)), sample_size)

                total_recalculated_fitness = 0.0
                for idx in sample_indices:
                    individual = population[idx]
                    if not individual or not isinstance(individual, dict) or "chromosome" not in individual:
                        print(f"[ProblemManager] Invalid individual structure in population.")
                        return
                    recalculated = fitness_fn(individual["chromosome"], problem.get("payload", {}))
                    declared = individual.get("fitness")
                    if declared is not None and declared != -1:
                        if abs(declared - recalculated) > 1e-4:
                            print(f"[ProblemManager] Cheat detected for {problem_id}! Declared: {declared}, Recalculated: {recalculated}")
                            return
                    individual["fitness"] = recalculated
                    total_recalculated_fitness += recalculated

                problem["state"]["population"] = population
                problem["state"]["lastUpdate"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                await self.store.set(store_key, problem["state"])
                print(f"[ProblemManager] Population updated for {problem_id}. Average sample fitness: {total_recalculated_fitness / sample_size:.4f}")

            elif work_unit_type == "multi_objective_genetic_algorithm":
                pareto_front = solution_data.get("paretoFront")
                if not isinstance(pareto_front, list):
                    print(f"[ProblemManager] 'paretoFront' missing or invalid for {problem_id}")
                    return
                await self._integrate_pareto_front(problem, pareto_front)

        except Exception as e:
            print(f"[ProblemManager] Error integrating solution for {problem_id}: {str(e)}")

    async def _ensure_initial_solution(self, problem: Dict[str, Any]) -> None:
        if problem.get("state", {}).get("bestSolution") is not None:
            return

        print(f"[ProblemManager] Generating initial solution for problem {problem['id']}...")
        work_unit = problem.get("workUnit", {})
        score_function = work_unit.get("scoreFunction")
        init_source_key = work_unit.get("initialSolutionSource")
        initial_solution_source = problem.get("payload", {}).get(init_source_key) if init_source_key else None

        if score_function and isinstance(initial_solution_source, list):
            initial_solution = initial_solution_source
            score = score_function(initial_solution, problem.get("payload", {}))

            problem["state"]["bestSolution"] = initial_solution
            problem["state"]["bestEnergy"] = score
            problem["state"]["lastUpdate"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

            print(f"[ProblemManager] Initial solution for {problem['id']} generated with score {score:.2f}")
            await self.store.set(f"problem-state:{problem['id']}", problem["state"])

    async def _integrate_pareto_front(self, problem: Dict[str, Any], new_front: List[Dict[str, Any]]) -> bool:
        if not isinstance(new_front, list) or not new_front:
            return False

        current_front = problem.get("state", {}).get("paretoFront", [])
        combined = current_front + new_front

        def pareto_dominates(a, b):
            a_obj = a.get("objectives", [])
            b_obj = b.get("objectives", [])
            a_better = False
            for idx in range(min(len(a_obj), len(b_obj))):
                if a_obj[idx] > b_obj[idx]:
                    return False
                if a_obj[idx] < b_obj[idx]:
                    a_better = True
            return a_better

        next_front = []
        dominated_indices = set()

        for i in range(len(combined)):
            if i in dominated_indices:
                continue
            is_dominated = False
            for j in range(len(combined)):
                if i == j or j in dominated_indices:
                    continue
                if pareto_dominates(combined[j], combined[i]):
                    is_dominated = True
                    break
                if pareto_dominates(combined[i], combined[j]):
                    dominated_indices.add(j)
            if not is_dominated:
                next_front.append(combined[i])

        has_changed = json.dumps(next_front, sort_keys=True) != json.dumps(current_front, sort_keys=True)
        if has_changed:
            print(f"[ProblemManager] New Pareto front for {problem['id']} with {len(next_front)} solutions (previously {len(current_front)})")
            problem["state"]["paretoFront"] = next_front
            problem["state"]["lastUpdate"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            await self.store.set(f"problem-state:{problem['id']}", problem["state"])
            return True
        return False

    async def get_best_solutions(self, problem_id: Optional[str] = None) -> Any:
        problems_to_process = (
            [p for p in self.problems if p["id"] == problem_id]
            if problem_id
            else self.problems
        )

        for p in problems_to_process:
            if p.get("workUnit", {}).get("type") != "multi_objective_genetic_algorithm":
                await self._ensure_initial_solution(p)

        def format_solution(p):
            if not p or "state" not in p:
                return None
            if p.get("workUnit", {}).get("type") == "multi_objective_genetic_algorithm":
                return {
                    "id": p["id"],
                    "solution": p["state"].get("paretoFront"),
                    "score": len(p["state"].get("paretoFront") or []),
                    "lastUpdate": p["state"].get("lastUpdate")
                }
            return {
                "id": p["id"],
                "solution": p["state"].get("bestSolution"),
                "score": p["state"].get("bestEnergy"),
                "lastUpdate": p["state"].get("lastUpdate")
            }

        if problem_id:
            problem = next((p for p in self.problems if p["id"] == problem_id), None)
            return format_solution(problem) if problem else None

        return [format_solution(p) for p in self.problems if p.get("state", {}).get("bestSolution") is not None or p.get("workUnit", {}).get("type") == "multi_objective_genetic_algorithm"]

    async def update_problem_payload(self, problem_id: str, new_payload: Dict[str, Any]) -> bool:
        problem = next((p for p in self.problems if p["id"] == problem_id), None)
        if not problem:
            print(f"[ProblemManager] Update failed: problem ID '{problem_id}' not found.")
            return False

        print(f"[ProblemManager] Updating payload for problem '{problem_id}'.")
        problem["payload"] = new_payload
        problem["state"]["bestSolution"] = None
        problem["state"]["bestEnergy"] = float("inf")

        await self.store.set(f"problem-state:{problem['id']}", problem["state"])
        return True
import abc
from typing import Dict, Any, List

class UpowModelTask(abc.ABC):
    """
    Classe de base abstraite pour définir des tâches uPoW basées sur l'entraînement
    ou l'évaluation de modèles d'apprentissage automatique en Python.
    """
    def __init__(self, problem_id: str, model_path: str, config: Dict[str, Any] = None):
        self.problem_id = problem_id
        self.model_path = model_path
        self.config = {
            "batch_size": 32,
            "learning_rate": 0.01,
            "validation_tolerance": 0.15,
            **(config or {})
        }

    def get_problem_id(self) -> str:
        return self.problem_id

    def get_model_asset_path(self) -> str:
        return self.model_path

    @abc.abstractmethod
    def dispatch_task(self, suspicion_factor: float) -> Dict[str, Any]:
        """Génère la charge utile de travail à envoyer au client."""
        pass

    @abc.abstractmethod
    def verify_solution(self, task_context: Dict[str, Any], solution: Dict[str, Any]) -> bool:
        """Vérifie la validité de la solution (gradients) retournée par le client."""
        pass

    @abc.abstractmethod
    def integrate_solution(self, solution: Dict[str, Any]) -> None:
        """Intègre les gradients validés dans le modèle global (par exemple via FedAvg)."""
        pass

    @abc.abstractmethod
    def get_current_model_state(self) -> Dict[str, Any]:
        """Récupère l'état actuel du modèle."""
        pass


class TensorFlowModelTask(UpowModelTask):
    """
    Implémentation concrète d'une tâche d'entraînement TensorFlow uPoW.
    """
    def __init__(self, model_path: str, config: Dict[str, Any] = None):
        super().__init__("request_classifier_nn", model_path, config)
        # Poids initiaux du modèle (réseau de neurones linéaire simple)
        self.weights = np.array([0.1, -0.2, 0.8, 0.5], dtype=np.float32)

    def dispatch_task(self, suspicion_factor: float) -> Dict[str, Any]:
        # Génération de données d'entraînement factices/anonymisées pour le client
        inputs = [
            [1.0, 0.5, 0.0, 1.2],
            [0.0, 1.0, -0.5, 0.8]
        ]
        return {
            "weights": self.weights.tolist(),
            "inputs": inputs,
            "learningRate": self.config["learning_rate"],
            "batchSize": self.config["batch_size"]
        }

    def verify_solution(self, task_context: Dict[str, Any], solution: Dict[str, Any]) -> bool:
        gradients = solution.get("gradients")
        if not isinstance(gradients, list) or len(gradients) != len(self.weights):
            return False
        # Garde-fou anti-poisoning : s'assurer que les gradients ne contiennent pas de valeurs aberrantes
        max_gradient_norm = 10.0
        return all(isinstance(grad, (int, float)) and not np.isnan(grad) and abs(grad) <= max_gradient_norm for grad in gradients)

    def integrate_solution(self, solution: Dict[str, Any]) -> None:
        gradients = np.array(solution["gradients"], dtype=np.float32)
        self.weights -= self.config["learning_rate"] * gradients

    def get_current_model_state(self) -> Dict[str, Any]:
        return {"weights": self.weights.tolist()}
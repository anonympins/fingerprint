<?php

declare(strict_types=1);

namespace Anonympins\Fingerprint;

use Anonympins\Fingerprint\Store\IStore;

class ProblemManager
{
    private static ?ProblemManager $instance = null;
    private string $configPath;
    private IStore $store;
    private array $problems = [];
    private int $currentProblemIndex = 0;
    private bool $initialized = false;
    
    /**
     * Le constructeur est privé pour forcer l'utilisation du singleton.
     */
    private function __construct(string $configPath, IStore $store)
    {
        $this->configPath = $configPath;
        $this->store = $store;
        $this->loadProblems();
    }

    /**
     * Obtient l'instance singleton du ProblemManager.
     * Doit être initialisé une fois avec `init`.
     */
    public static function getInstance(?string $configPath = null, ?IStore $store = null): self
    {
        if (self::$instance === null) {
            // Si on essaie d'obtenir l'instance sans l'initialiser d'abord, c'est une erreur.
            if ($configPath === null || $store === null) {
                throw new \RuntimeException("ProblemManager must be initialized with configPath and store.");
            }
            self::$instance = new self($configPath, $store);
        }
        return self::$instance;
    }

    public static function isInitialized(): bool
    {
        return self::$instance !== null && self::$instance->initialized;
    }
    /**
     * Charge et parse les problèmes depuis le fichier de configuration.
     */

    private function loadProblems(): void
    {
        if (!file_exists($this->configPath)) {
            error_log("[ProblemManager] Problem config file not found: {$this->configPath}");
            return;
        }
        $data = file_get_contents($this->configPath);
        if ($data === false) {
            error_log("[ProblemManager] Failed to read problem config file: {$this->configPath}");
            return;
        }
        $problemsFromFile = json_decode($data, true);
        if (json_last_error() !== JSON_ERROR_NONE) {
            error_log("[ProblemManager] Failed to parse problem config JSON: " . json_last_error_msg());
            return;
        }

        $loadedProblems = [];
        foreach ($problemsFromFile as $problem) {
            $storeKey = "problem-state:{$problem['id']}";
            $storedState = $this->store->get($storeKey);

            if ($storedState === null) {
                $storedState = $problem['state'] ?? []; // Use initial state from file
                $this->store->set($storeKey, $storedState); // Persist initial state
            }
            $problem['state'] = $storedState;
            $loadedProblems[] = $problem;
        }
        $this->problems = $loadedProblems;
        $this->initialized = true; // Marquer comme initialisé seulement après un chargement réussi
    }

    public function dispatchWork(float $suspicionFactor): ?array
    {
        if (empty($this->problems)) {
            return null;
        }

        $problem = $this->problems[$this->currentProblemIndex];
        $this->currentProblemIndex = ($this->currentProblemIndex + 1) % count($this->problems);

        $task = ['type' => $problem['workUnit']['type']];
        $scalingFactor = $problem['workUnit']['scalingFactor'] ?? null;

        switch ($problem['workUnit']['type']) {
            case 'simulated_annealing_iterations':
                $baseIterations = $problem['workUnit']['baseIterations'] ?? 15000;
                $task['iterations'] = $scalingFactor
                    ? (int)floor($baseIterations * pow($scalingFactor, $suspicionFactor))
                    : (int)floor($baseIterations * (0.5 + $suspicionFactor));
                if (isset($problem['payload'])) {
                    $task['payload'] = $problem['payload'];
                }
                // Ensure payload is always an array to prevent errors when accessing it.
                $task['payload'] = $task['payload'] ?? [];
                $task['initialSolution'] = $problem['state']['bestSolution'] ?? null;
                break;
            case 'multi_objective_genetic_algorithm':
                $baseGenerationsMulti = max(30, $problem['workUnit']['baseGenerations'] ?? 0);
                $task['generations'] = $scalingFactor
                    ? (int)floor($baseGenerationsMulti * pow($scalingFactor, $suspicionFactor))
                    : (int)floor($baseGenerationsMulti * (0.5 + $suspicionFactor));
                if (isset($problem['payload'])) {
                    $task['payload'] = $problem['payload'];
                }
                $task['initialFront'] = $problem['state']['paretoFront'] ?? null;
                $task['solverName'] = $problem['workUnit']['solverName'];
                break;
            default:
                error_log("[ProblemManager] Unknown useful work type: {$problem['workUnit']['type']}");
                return null;
        }

        return ['problemId' => $problem['id'], 'task' => $task];
    }

    /**
     * Intègre la solution d'un client dans l'état du problème.
     *
     * @param string $problemId L'ID du problème.
     * @param array $solutionData La solution renvoyée par le client.
     */
    public function integrateSolution(string $problemId, array $solutionData): void
    {
        $problemIndex = array_search($problemId, array_column($this->problems, 'id'));
        if ($problemIndex === false) {
            return;
        }
        $problem = &$this->problems[$problemIndex]; // Use reference to modify in place

        $stateChanged = false;

        $storeKey = "problem-state:{$problem['id']}";

        // La logique d'intégration dépend du type de problème.
        switch ($problem['workUnit']['type']) {
            case 'simulated_annealing_iterations':
                // Pour le recuit simulé, on vérifie si la nouvelle "énergie" est meilleure.
                if (isset($solutionData['solution']) && isset($solutionData['energy'])) {
                    // Ne jamais faire confiance au score du client. Idéalement, il faudrait le recalculer ici.
                    // Pour cet exemple, nous faisons confiance au score pour la simplicité.
                    $recalculatedEnergy = (float)$solutionData['energy']; 
                    $currentBest = (float)($problem['state']['bestEnergy'] ?? INF);

                    if ($recalculatedEnergy < $currentBest) {
                        $problem['state']['bestSolution'] = $solutionData['solution'];
                        $problem['state']['bestEnergy'] = $recalculatedEnergy;
                        $problem['state']['lastUpdate'] = (new \DateTime())->format(\DateTime::ATOM);
                        $stateChanged = true;
                        error_log("[ProblemManager] New best solution for {$problemId}: {$recalculatedEnergy}"); // @phpstan-ignore-line
                    }
                }
                break;
            case 'multi_objective_genetic_algorithm':
                // Pour les algorithmes génétiques, on intègre le nouveau front de Pareto.
                if (isset($solutionData['paretoFront']) && is_array($solutionData['paretoFront'])) {
                    $stateChanged = $this->_integrateParetoFront($problem, $solutionData['paretoFront']);
                }
                break;
            default:
                error_log("[ProblemManager] Integration not implemented for useful work type: {$problem['workUnit']['type']}");
                break;
        }
        // Sauvegarder l'état mis à jour dans le store.
        if ($stateChanged) {
            $this->store->set($storeKey, $problem['state']);
        }
    }

    /**
     * Intègre un nouveau front de Pareto dans l'état du problème.
     *
     * @param array &$problem Le problème à mettre à jour (passé par référence).
     * @param array $newFront Le nouveau front de Pareto soumis par le client.
     */
    private function _integrateParetoFront(array &$problem, array $newFront): bool
    {
        // Logique de fusion et de tri non-dominé pour mettre à jour le front de Pareto.
        // Pour cet exemple, nous remplaçons simplement le front, mais une vraie implémentation
        // fusionnerait les deux fronts et recalculerait le meilleur.
        // On vérifie si le nouveau front est différent de l'actuel pour éviter des écritures inutiles.
        $currentFront = $problem['state']['paretoFront'] ?? [];
        if (!empty($newFront) && json_encode($newFront) !== json_encode($currentFront)) {
            $problem['state']['paretoFront'] = $newFront;
            $problem['state']['lastUpdate'] = (new \DateTime())->format(\DateTime::ATOM);
            error_log("[ProblemManager] New Pareto front for {$problem['id']} with " . count($newFront) . " solutions."); // @phpstan-ignore-line
            return true;
        }
        return false;
    }

    /**
     * Réinitialise l'instance singleton.
     * @internal Uniquement pour les tests.
     */
    public static function resetInstanceForTests(): void
    {
        self::$instance = null;
    }

    /**
     * Réinitialise l'instance singleton.
     * @internal Uniquement pour les tests.
     */
    public static function __internal_resetInstance(): void {
        self::$instance = null;
    }

    /**
     * @internal For testing purposes only.
     */
    public function getProblems(): array
    {
        return $this->problems;
    }
}
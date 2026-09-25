<?php

declare(strict_types=1);

namespace Anonympins\Fingerprint;

use Anonympins\Fingerprint\Optimization\FunctionRegistry;
use Anonympins\Fingerprint\Optimization\ProblemInitializers;
use Anonympins\Fingerprint\Store\IStore;

class ProblemManager
{
    private static ?ProblemManager $instance = null;
    private string $configPath;
    private IStore $store;
    /** @var array<int, array<string, mixed>> */
    private array $problems = [];
    private int $currentProblemIndex = 0;
    private bool $initialized = false;
    
    /**
     * Private constructor enforces singleton usage.
     */
    private function __construct(string $configPath, IStore $store)
    {
        $this->configPath = $configPath;
        $this->store = $store;
        $this->loadProblems();
    }

    /**
     * Retrieves the ProblemManager singleton instance.
     * Must be initialized with configPath and store.
     */
    public static function getInstance(?string $configPath = null, ?IStore $store = null): self
    {
        if (self::$instance === null) {
            if ($configPath === null) {
                $defaultPath = dirname(__DIR__, 2) . '/config/problems.config.json';
                $configPath = file_exists($defaultPath) ? $defaultPath : null;
            }
            // Error if accessed before initialization
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
     * Loads and parses problem definitions from configuration file.
     */

    private function loadProblems(): void
    {
        if (!file_exists($this->configPath)) {
            self::logError("[ProblemManager] Problem config file not found: {$this->configPath}");
            return;
        }
        $data = file_get_contents($this->configPath);
        if ($data === false) {
            self::logError("[ProblemManager] Failed to read problem config file: {$this->configPath}");
            return;
        }
        $problemsFromFile = json_decode($data, true);
        if (json_last_error() !== JSON_ERROR_NONE) {
            self::logError("[ProblemManager] Failed to parse problem config JSON: " . json_last_error_msg());
            return;
        }

        foreach ($problemsFromFile as $problem) {
            $storeKey = "problem-state:{$problem['id']}";
            $storedState = $this->store->get($storeKey);

            if ($storedState === null) {
                $storedState = $problem['state'] ?? [];
                $this->store->set($storeKey, $storedState); // Persist initial state
            }
            $problem['state'] = $storedState;

            // Dynamic function and data resolution
            if (isset($problem['workUnit']['scoreFunction'])) {
                $problem['workUnit']['scoreFunction'] = FunctionRegistry::get($problem['workUnit']['scoreFunction']);
                if ($problem['workUnit']['scoreFunction'] === null) {
                    // @codeCoverageIgnoreStart
                    self::logError("[ProblemManager] Warning: scoreFunction '{$problem['workUnit']['scoreFunction']}' not found in registry for problem '{$problem['id']}'.");
                    // @codeCoverageIgnoreEnd
                }
            }

            if (isset($problem['payload']) && is_array($problem['payload'])) {
                foreach ($problem['payload'] as $key => &$value) {
                    if (is_array($value) && isset($value['$init'])) {
                        $initializer = ProblemInitializers::get($value['$init']);
                        if ($initializer) {
                            $value = $initializer($value['params'] ?? []);
                        }
                    }
                }
            }
            $this->problems[] = $problem;
        }
        $this->initialized = true; // Mark initialized only after successful load
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
                
            case 'genetic_algorithm_generations':
                $baseGenerations = max(50, $problem['workUnit']['baseGenerations'] ?? 0);
                $task['generations'] = $scalingFactor
                    ? (int)floor($baseGenerations * pow($scalingFactor, $suspicionFactor))
                    : (int)floor($baseGenerations * (0.5 + $suspicionFactor));
                if (isset($problem['payload'])) {
                    $task['payload'] = $problem['payload'];
                }
                $task['payload'] = $task['payload'] ?? [];
                $task['initialPopulation'] = $problem['state']['population'] ?? null;
                break;

            case 'run_multiple_parallel':
                $task['solverName'] = $problem['workUnit']['solverName'] ?? null;
                $task['numCycles'] = $problem['workUnit']['numCycles'] ?? null;
                $task['baseSolverArgs'] = $problem['payload']['baseSolverArgs'] ?? null;
                $task['workerDataGenerator'] = $problem['payload']['workerDataGenerator'] ?? null;
                $task['logProgress'] = $problem['payload']['logProgress'] ?? false;
                $task['concurrency'] = $problem['payload']['concurrency'] ?? null;
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
                self::logError("[ProblemManager] Unknown useful work type: {$problem['workUnit']['type']}");
                return null;
        }

        return ['problemId' => $problem['id'], 'task' => $task];
    }

    /**
     * Integrates client solution into problem state.
     *
     * @param string $problemId Problem identifier.
     * @param array $solutionData Client-submitted solution payload.
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

        // Integration logic depends on problem type
        switch ($problem['workUnit']['type']) {
            case 'simulated_annealing_iterations':
                if (isset($solutionData['solution']) && isset($solutionData['energy'])) {
                    $scoreFunction = $problem['workUnit']['scoreFunction'] ?? null;
                    if (!$scoreFunction) {
                        self::logError("[ProblemManager] No score function defined for {$problemId}.");
                        return;
                    }
                // DoS mitigation: validate solution size and structure
                if (is_array($solutionData['solution']) && count($solutionData['solution']) > 500) {
                    self::logError("[ProblemManager] Solution array too large for {$problemId} verification.");
                    return;
                }
                $serializedSolution = json_encode($solutionData['solution']);
                if ($serializedSolution !== false && strlen($serializedSolution) > 65536) {
                    self::logError("[ProblemManager] Solution payload size exceeds safe limit for {$problemId}.");
                    return;
                }
                    // 1. Never trust client-reported score. Recalculate server-side.
                    $recalculatedEnergy = $scoreFunction($solutionData['solution'], $problem['payload'] ?? []);

                    $currentBest = (float)($problem['state']['bestEnergy'] ?? INF);

                    // 2. Compare verified score
                    if ($recalculatedEnergy < $currentBest) { // @phpstan-ignore-line
                        $problem['state']['bestSolution'] = $solutionData['solution'];
                        $problem['state']['bestEnergy'] = $recalculatedEnergy; // 3. Store verified score
                        $problem['state']['lastUpdate'] = (new \DateTime())->format(\DateTime::ATOM);
                        $stateChanged = true;
                        self::logError("[ProblemManager] New best solution for {$problemId}: {$recalculatedEnergy}"); // @phpstan-ignore-line
                    }
                }
                break;
            case 'genetic_algorithm_generations':
                if (isset($solutionData['population']) && is_array($solutionData['population'])) {
                if (count($solutionData['population']) > 150) {
                    self::logError("[ProblemManager] Population size exceeds safe limit for {$problemId}.");
                    return;
                }
                foreach ($solutionData['population'] as $ind) {
                    if (isset($ind['chromosome']) && is_array($ind['chromosome']) && count($ind['chromosome']) > 100) {
                        self::logError("[ProblemManager] Chromosome size too large for {$problemId}.");
                        return;
                    }
                }

                    // Sample-based verification (parity with JS)
                    $fitnessFunction = FunctionRegistry::get('portfolio.calculateMetrics');
                    if ($fitnessFunction) {
                        $sampleSize = min(5, count($solutionData['population']));
                        $sampleKeys = (array)array_rand($solutionData['population'], $sampleSize);
                        
                        foreach ($sampleKeys as $key) {
                            $individual = $solutionData['population'][$key];
                            if (isset($individual['chromosome'])) {
                                $recalculated = $fitnessFunction($individual['chromosome'], $problem['payload'] ?? []);
                                if (isset($individual['fitness']) && $individual['fitness'] !== -1) {
                                    if (abs($individual['fitness'] - $recalculated) > 1e-4) {
                                        self::logError("[ProblemManager] Cheating detected for {$problemId}! Reported: {$individual['fitness']}, recalculated: {$recalculated}");
                                        return; // Reject inconsistent population
                                    }
                                }
                                $solutionData['population'][$key]['fitness'] = $recalculated;
                            }
                        }
                    }

                    $problem['state']['population'] = $solutionData['population'];
                    $problem['state']['lastUpdate'] = (new \DateTime())->format(\DateTime::ATOM);
                    $stateChanged = true;
                }
                break;
            case 'multi_objective_genetic_algorithm':
                // Merge candidate Pareto front for multi-objective problems
                if (isset($solutionData['paretoFront']) && is_array($solutionData['paretoFront'])) {
                    $stateChanged = $this->_integrateParetoFront($problem, $solutionData['paretoFront']);
                }
                break;
            default:
                self::logError("[ProblemManager] Integration not implemented for useful work type: {$problem['workUnit']['type']}");
                break;
        }
        // Persist updated state to datastore
        if ($stateChanged) {
            $this->store->set($storeKey, $problem['state']);
        }
    }

    /**
     * Integrates a new Pareto front into the problem state.
     *
     * @param array &$problem Target problem passed by reference.
     * @param array $newFront Candidate Pareto front submitted by client.
     */
    private function _integrateParetoFront(array &$problem, array $newFront): bool
    {
        // Verify content differences before updating to prevent redundant writes
        $currentFront = $problem['state']['paretoFront'] ?? [];
        if (!empty($newFront) && json_encode($newFront) !== json_encode($currentFront)) {
            $problem['state']['paretoFront'] = $newFront;
            $problem['state']['lastUpdate'] = (new \DateTime())->format(\DateTime::ATOM);
            self::logError("[ProblemManager] New Pareto front for {$problem['id']} with " . count($newFront) . " solutions."); // @phpstan-ignore-line
            return true;
        }
        return false;
    }

    /**
     * Ensures that the problem has an initial solution. Generates one if missing.
     *
     * @param array &$problem Problem passed by reference.
     */
    private function ensureInitialSolution(array &$problem): void
    {
        if (!empty($problem['state']['bestSolution'])) {
            return;
        }

        $scoreFunction = $problem['workUnit']['scoreFunction'] ?? null;
        $initialSolutionSourceKey = $problem['workUnit']['initialSolutionSource'] ?? '';
        $initialSolution = $problem['payload'][$initialSolutionSourceKey] ?? null;

        if ($scoreFunction && is_array($initialSolution)) {
            $score = $scoreFunction($initialSolution, $problem['payload'] ?? []);
            $problem['state']['bestSolution'] = $initialSolution;
            $problem['state']['bestEnergy'] = $score;
            $problem['state']['lastUpdate'] = (new \DateTime())->format(\DateTime::ATOM);
            $this->store->set("problem-state:{$problem['id']}", $problem['state']);
        }
    }

    /**
     * Formats problem state for external consumers.
     */
    private function formatSolution(array $problem): ?array
    {
        if (!isset($problem['state'])) {
            return null;
        }

        if (($problem['workUnit']['type'] ?? '') === 'multi_objective_genetic_algorithm') {
            return [
                'id' => $problem['id'],
                'solution' => $problem['state']['paretoFront'] ?? [],
                'score' => count($problem['state']['paretoFront'] ?? []),
                'lastUpdate' => $problem['state']['lastUpdate'] ?? null,
            ];
        }

        return [
            'id' => $problem['id'],
            'solution' => $problem['state']['bestSolution'] ?? null,
            'score' => $problem['state']['bestEnergy'] ?? null,
            'lastUpdate' => $problem['state']['lastUpdate'] ?? null,
        ];
    }

    /**
     * Retrieves the best known solution(s) for loaded problems.
     *
     * @param string|null $problemId Optional problem ID filter.
     * @return array|null Associative array or list of solutions.
     */
    public function getBestSolutions(?string $problemId = null): ?array
    {
        $problemsToProcess = [];
        foreach ($this->problems as &$p) {
            if ($problemId === null || $p['id'] === $problemId) {
                if (($p['workUnit']['type'] ?? '') !== 'multi_objective_genetic_algorithm') {
                    $this->ensureInitialSolution($p);
                }
                $problemsToProcess[] = $p;
            }
        }
        unset($p);

        if ($problemId !== null) {
            return !empty($problemsToProcess) ? $this->formatSolution($problemsToProcess[0]) : null;
        }

        $results = [];
        foreach ($this->problems as $p) {
            $formatted = $this->formatSolution($p);
            if ($formatted && $formatted['solution'] !== null) {
                $results[] = $formatted;
            }
        }
        return $results;
    }

    /**
     * Resets singleton instance.
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

    private static function logError(string $message): void
    {
        // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- ProblemManager logging
        error_log($message);
    }
}
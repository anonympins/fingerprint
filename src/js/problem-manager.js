import {promises as fs} from 'node:fs';
import {fileURLToPath} from 'node:url';
import {dirname, join} from 'node:path';
import {Optimization} from './library.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

/**
 * @namespace FunctionRegistry
 * @description Registry to expose library functions in a controlled manner.
 * Allows dynamic invocation from problem configurations.
 * Uses dot notation to access nested functions (e.g. 'tsp.calculateEnergy').
 */
const FunctionRegistry = {};

// --- Scoring functions (solution evaluation) ---
// These functions are adapters to use library utilities
// with the structure expected by the ProblemManager.
FunctionRegistry['cpc.solve'] = Optimization.Operators.solveOptimalCPC; // Register CPC solver

/**
 * Evaluates total cost for the facility location problem.
 * @param {Array<{x: number, y: number}>} facilities - Facilities.
 * @param {object} payload - Payload containing customers and options.
 * @returns {number} Total cost.
 */
FunctionRegistry['facility.calculateEnergy'] = (facilities, payload) => {
    const customers = payload.customers || [];
    const fixedCostPerFacility = payload.options?.fixedCostPerFacility || 0;
    const distanceSq = (p1, p2) => Math.pow(p1.x - p2.x, 2) + Math.pow(p1.y - p2.y, 2);
    let totalConnectionCost = 0;
    for (const customer of customers) {
        let minDistanceToCustomer = Infinity;
        for (const facility of facilities) {
            const d = distanceSq(customer, facility);
            if (d < minDistanceToCustomer) {
                minDistanceToCustomer = d;
            }
        }
        totalConnectionCost += Math.sqrt(minDistanceToCustomer);
    }
    return totalConnectionCost + facilities.length * fixedCostPerFacility;
};

/**
 * Evaluates total distance of a path for the traveling salesperson problem (TSP).
 * @param {Array<{x: number, y: number}>} path - Array of points representing the path.
 * @returns {number} Total path distance.
 */
FunctionRegistry['tsp.calculateEnergy'] = (path, payload) => {
    const cities = payload?.cities || payload?.points || [];
    if (path && typeof path[0] === 'number') {
        return Optimization.Utils.evaluatePathDistance(cities, path);
    }
    // Fallback: Creates an array of indices [0, 1, 2, ...] for evaluatePathDistance.
    const indices = Array.from({ length: path.length }, (_, i) => i);
    return Optimization.Utils.evaluatePathDistance(path, indices);
};

/**
 * Evaluates portfolio metrics (return and volatility).
 * Currently returns negative return to match the minimization objective
 * of the library's genetic algorithm.
 * @param {Array<number>} weights - Asset weights in the portfolio.
 * @param {object} payload - Problem payload, containing assets.
 * @returns {number} Negative return of the portfolio.
 */
FunctionRegistry['portfolio.calculateMetrics'] = (weights, payload) => {
    const { assets, maxVolatility } = payload;
    // Use the library operator to create the fitness function
    // and invoke it immediately.
    const fitnessFunction = Optimization.Operators.createPortfolioAllocator({
        assets,
        maxVolatility,
    });
    // Fitness function returns negative return, which is what we want
    // to store as "energy" or score.
    return fitnessFunction(weights);
};

// --- Solving functions (complete algorithms) ---
// Useful for workers running end-to-end tasks.
FunctionRegistry['tsp.solve'] = Optimization.Operators.solveTSP;
FunctionRegistry['portfolio.solve'] = Optimization.Operators.solvePortfolio;
FunctionRegistry['fraud.solve'] = Optimization.Operators.solveFraudDetection; // Register fraud solver
FunctionRegistry['facility.solve'] = Optimization.Operators.solveFacilityLocation;
FunctionRegistry['security.tune'] = Optimization.Operators.solveFullSecurityTuning;

// --- Utility functions ---
FunctionRegistry['utils.evaluatePathDistance'] = Optimization.Utils.evaluatePathDistance;

const yieldToEventLoop = () => new Promise(resolve => {
    if (typeof setImmediate === 'function') {
        setImmediate(resolve);
    } else {
        setTimeout(resolve, 0);
    }
});

/**
 * @namespace ProblemInitializers
 * @description Functions to dynamically generate problem data.
 */
const ProblemInitializers = {
    /**
     * Generates a set of random points for a TSP problem.
     * @param {object} params - Generation parameters.
     * @param {number} params.count - Number of points to generate.
     * @param {{x: number, y: number}} [params.bounds={x: 1000, y: 1000}] - Spatial bounds.
     * @returns {Promise<Array<{x: number, y: number}>>}
     */
    'generate:randomPoints': async (params) => {
        const { count, bounds = { x: 1000, y: 1000 } } = params || {};
        if (isNaN(count)) return [];
        const points = [];
        const chunkSize = 5000;
        for (let i = 0; i < count; i++) {
            points.push({ x: Math.random() * bounds.x, y: Math.random() * bounds.y });
            if (i > 0 && i % chunkSize === 0) {
                await yieldToEventLoop();
            }
        }
        return points;
    },

    /**
     * Generates a set of random financial assets for a portfolio problem.
     * @param {object} params - Generation parameters.
     * @param {number} params.count - Number of assets to generate.
     * @returns {Promise<Array<{expectedReturn: number, volatility: number}>>}
     */
    'generate:randomAssets': async (params) => {
        const { count } = params || {};
        if (isNaN(count)) return [];
        const assets = [];
        const chunkSize = 5000;
        for (let i = 0; i < count; i++) {
            assets.push({
                expectedReturn: Math.random() * 0.2,
                volatility: 0.1 + Math.random() * 0.3
            });
            if (i > 0 && i % chunkSize === 0) {
                await yieldToEventLoop();
            }
        }
        return assets;
    },

    /**
     * Creates a function that generates arguments for each worker in `runMultipleParallel`.
     * Allows varying parameters (e.g. initial solution) for each cycle.
     * @param {object} params - Configuration parameters.
     * @param {Array<any>} params.baseArgs - Base arguments common to all workers.
     * @param {object} params.variations - Describes how to vary an argument.
     * @returns {function(number): Array<any>} The `workerDataGenerator` function.
     */
    'generate:parallelArgs': (params) => {
        const { baseArgs, variations } = params || {};
        return (cycleIndex) => {
            const cycleArgs = baseArgs ? [...baseArgs] : [];
            // For now, handle initial solution variation for TSP
            if (variations?.initialSolution === 'random') {
                cycleArgs[0] = cycleArgs[0]?.sort(() => Math.random() - 0.5);
            }
            return cycleArgs;
        };
    }
};

class ProblemManager {
    /**
     * @private
     * The constructor is private. Use the asynchronous factory method `create()`.
     * @param {object} options - Initialization options.
     * @param {string} [options.configPath] - Path to the configuration file.
     * @param {object} [options.config] - Problem configuration object.
     * @param {Array<object>} problems - Pre-loaded problems.
     * @param {IStore} store - The datastore for synchronization.
     */
    constructor(options, problems, store) {
        this.configPath = options.configPath;
        this.config = options.config;
        this.problems = problems;
        this.store = store; // The datastore instance
        this.currentProblemIndex = 0;
    }

    /**
     * Asynchronous factory method to create and initialize a ProblemManager instance.
     * @param {object} options - Initialization options.
     * @returns {Promise<ProblemManager>}
     */
    static async create(options, store) {
        const manager = new ProblemManager(options, [], store);
        manager.problems = await manager.loadProblems();
        return manager;
    }

    /**
     * Charge et parse les problèmes depuis le fichier de configuration de manière asynchrone.
     * It now also synchronizes with the datastore.
     * @returns {Promise<Array<object>>}
     */
    async loadProblems() {
        // Guard clause: If no store is configured (e.g., during isolated test imports),
        // do not attempt to load problems to prevent crashes.
        if (!this.store) {
            return [];
        }

        try {
            let problemsFromFile;
            if (this.config) {
                problemsFromFile = this.config;
            } else if (this.configPath) {
                const data = await fs.readFile(this.configPath, 'utf-8');
                problemsFromFile = JSON.parse(data);
            } else {
                throw new Error('Either `config` or `configPath` must be provided to load problems.');
            }

            // For each problem, try to load its state from the datastore.
            // If it doesn't exist, use the state from the file and save it to the store.
            const problems = await Promise.all(problemsFromFile.map(async (problem) => {
                const storeKey = `problem-state:${problem.id}`;
                let storedState = await this.store.get(storeKey);

                if (!storedState) {
                    storedState = problem.state; // Use initial state from file
                    await this.store.set(storeKey, storedState); // Persist initial state
                }
                problem.state = storedState;
                return problem;
            }));
            // Dynamic problem initialization
            for (const problem of problems) {
                // Resolve functions via registry
                    if (problem.workUnit && problem.workUnit.scoreFunction) {
                    problem.workUnit.scoreFunction = FunctionRegistry[problem.workUnit.scoreFunction] || null;
                }
                    if (problem.payload) {
                        for (const key in problem.payload) {
                            const value = problem.payload[key];
                            // Look for an initialization instruction (e.g. { "$init": "generate:randomPoints", ... })
                            if (typeof value === 'object' && value !== null && value.$init) {
                                const initializer = ProblemInitializers[value.$init];
                                // Look for a function instruction (e.g. { "$func": "tsp.calculateEnergy" })
                                // Note: Currently unused, but ready for future extension.
                                if (initializer) {
                                    // Replace instruction object with dynamically generated data.
                                    problem.payload[key] = await initializer(value.params || {});
                                }
                        }
                    }
                }
            }
            return problems;
        } catch (error) {
            console.error(`[ProblemManager] Erreur lors du chargement du fichier de problèmes: ${error.message}`);
            return []; // Retourne un tableau vide en cas d'erreur pour éviter un crash
        }
    }

    /**
     * Selects a problem and generates a work unit.
     * @param {number} suspicionFactor - Suspicion factor to adjust difficulty.
     * @returns {{problemId: string, task: object}|null}
     */
    dispatchWork(suspicionFactor) {
        if (this.problems.length === 0) return null;

        const problem = this.problems[this.currentProblemIndex];
        this.currentProblemIndex = (this.currentProblemIndex + 1) % this.problems.length;

        const task = { type: problem.workUnit.type };
        const { scalingFactor } = problem.workUnit;

        switch (problem.workUnit.type) {
            case 'simulated_annealing_iterations':
                // Ensure a minimum difficulty so the challenge is meaningful
                const baseIterations = Math.max(15000, problem.workUnit.baseIterations || 0);
                task.iterations = scalingFactor
                    ? Math.floor(baseIterations * Math.pow(scalingFactor, suspicionFactor))
                    : Math.floor(baseIterations * (0.5 + suspicionFactor));
                task.payload = problem.payload;
                task.initialSolution = problem.state.bestSolution;
                break;

            case 'genetic_algorithm_generations':
                // Ensure a minimum difficulty so the challenge is meaningful
                const baseGenerations = Math.max(50, problem.workUnit.baseGenerations || 0);
                task.generations = scalingFactor
                    ? Math.floor(baseGenerations * Math.pow(scalingFactor, suspicionFactor))
                    : Math.floor(baseGenerations * (0.5 + suspicionFactor));
                task.payload = problem.payload;
                task.initialPopulation = problem.state.population;
                break;

            case 'run_multiple_parallel':
                task.solverName = problem.workUnit.solverName;
                task.numCycles = problem.workUnit.numCycles;
                // Arguments and generator are in payload for added flexibility
                task.baseSolverArgs = problem.payload.baseSolverArgs;
                task.workerDataGenerator = problem.payload.workerDataGenerator;
                task.logProgress = problem.payload.logProgress || false;
                task.concurrency = problem.payload.concurrency;
                break;
            
            case 'multi_objective_genetic_algorithm':
                // Difficulty applies to the number of generations
                const baseGenerationsMulti = Math.max(30, problem.workUnit.baseGenerations || 0);
                task.generations = scalingFactor
                    ? Math.floor(baseGenerationsMulti * Math.pow(scalingFactor, suspicionFactor))
                    : Math.floor(baseGenerationsMulti * (0.5 + suspicionFactor));
                task.payload = problem.payload;
                // Initial state is current Pareto front, which client can use for elitism
                task.initialFront = problem.state.paretoFront;
                task.solverName = problem.workUnit.solverName; // Name of solver to use (e.g. 'cpc.solve')
                break;

            case 'tfjs_learning':
                task.modelPath = problem.workUnit.modelPath;
                task.payload = problem.payload;
                task.weights = problem.state.weights || [];
                break;
        }

        return { problemId: problem.id, task };
    }

    /**
     * Integrates a client's solution into the problem state.
     * @param {string} problemId - Problem ID.
     * @param {object} solutionData - Solution returned by client.
     */
    async integrateSolution(problemId, solutionData) {
        const problem = this.problems.find(p => p.id === problemId);
        if (!problem) return;
        const storeKey = `problem-state:${problem.id}`;

        if (!solutionData || typeof solutionData !== 'object') {
            console.error(`[ProblemManager] Données de solution invalides ou manquantes pour ${problemId}.`);
            return;
        }

        try {
            switch (problem.workUnit.type) {
                case 'simulated_annealing_iterations':
                    if (!('solution' in solutionData)) {
                        console.error(`[ProblemManager] Propriété 'solution' manquante dans solutionData pour ${problemId}.`);
                        return;
                    }
            // DoS mitigation: validate solution size and structure
            if (Array.isArray(solutionData.solution) && solutionData.solution.length > 500) {
                console.error(`[ProblemManager] Solution array too large for ${problemId} verification.`);
                return;
            }
            try {
                const serializedSolution = JSON.stringify(solutionData.solution);
                if (serializedSolution && serializedSolution.length > 65536) {
                    console.error(`[ProblemManager] Solution payload size exceeds safe limit for ${problemId}.`);
                    return;
                }
            } catch (e) {}
                    // 1. NEVER trust client score. Always recalculate.
                    const scoreFunction = problem.workUnit.scoreFunction;
                    if (!scoreFunction) {
                        console.error(`[ProblemManager] Aucune fonction de score définie pour ${problemId}. Impossible de vérifier la solution.`);
                        return;
                    }
                    const recalculatedEnergy = scoreFunction(solutionData.solution, problem.payload);

                    const currentBest = parseFloat(problem.state.bestEnergy) || Infinity;
                    // 2. Compare recalculated score, not client score.
                    const isBetter = recalculatedEnergy < currentBest;

                    if (isBetter) {
                        problem.state.bestSolution = solutionData.solution;
                        problem.state.bestEnergy = recalculatedEnergy; // 3. Store verified score.
                        problem.state.lastUpdate = new Date().toISOString();
                        console.log(`[ProblemManager] Nouvelle meilleure solution pour ${problemId}: ${recalculatedEnergy.toFixed(2)}`);
                    }
                    break;
                case 'genetic_algorithm_generations':
                    // SAMPLING VERIFICATION to balance security and performance.
                    const fitnessFunction = FunctionRegistry['portfolio.calculateMetrics']; // Or a more generic function
                    if (!solutionData || !Array.isArray(solutionData.population)) {
                        console.error(`[ProblemManager] Propriété 'population' manquante ou invalide dans solutionData pour ${problemId}.`);
                        return;
                    }
                    if (solutionData.population.length === 0) {
                        return; // Graceful return if population is empty (e.g. redirect fallback)
                    }
                    if (!fitnessFunction) {
                        console.error(`[ProblemManager] Impossible de vérifier la population pour ${problemId} (fonction de fitness manquante).`);
                        return;
                    }

            if (solutionData.population.length > 150) {
                console.error(`[ProblemManager] Population size exceeds safe limit for ${problemId}.`);
                return;
            }
            for (const individual of solutionData.population) {
                if (individual && individual.chromosome && Array.isArray(individual.chromosome) && individual.chromosome.length > 100) {
                    console.error(`[ProblemManager] Chromosome size too large for ${problemId}.`);
                    return;
                }
            }
                    // 1. Choose a small random sample of the submitted population.
                    const sampleSize = Math.min(5, solutionData.population.length);
                    const sampleIndices = new Set();
                    while (sampleIndices.size < sampleSize) {
                        sampleIndices.add(Math.floor(Math.random() * solutionData.population.length));
                    }

                    // 2. Recalculate score for this sample.
                    let totalRecalculatedFitness = 0;
                    for (const index of sampleIndices) {
                        const individual = solutionData.population[index];
                        if (!individual || !individual.chromosome) {
                            throw new Error("Structure d'individu ou chromosome invalide dans la population.");
                        }
                        const recalculated = fitnessFunction(individual.chromosome, problem.payload);
                        
                        if (individual.fitness !== undefined && individual.fitness !== -1) {
                            if (Math.abs(individual.fitness - recalculated) > 1e-4) {
                                console.error(`[ProblemManager] Triche détectée pour ${problemId}! Fitness déclaré: ${individual.fitness}, recalculé: ${recalculated}`);
                                return; // Immediately reject entire population
                            }
                        }
                        individual.fitness = recalculated; // Enforce exact recalculated value
                        totalRecalculatedFitness += recalculated;
                    }

                    problem.state.population = solutionData.population; // Accept population
                    console.log(`[ProblemManager] Population mise à jour pour ${problemId}. Fitness moyen de l'échantillon: ${(totalRecalculatedFitness / sampleSize).toFixed(4)}`);
                    break;
                
                case 'multi_objective_genetic_algorithm':
                    if (!Array.isArray(solutionData.paretoFront)) {
                        console.error(`[ProblemManager] Propriété 'paretoFront' manquante ou invalide dans solutionData pour ${problemId}.`);
                        return;
                    }
                    // For multi-objective, merge existing Pareto front with client's.
                    await this._integrateParetoFront(problem, solutionData.paretoFront);
                    break;
                }
            // Persist the updated state to the datastore immediately.
            await this.store.set(storeKey, problem.state);
        } catch (error) {
            console.error(`[ProblemManager] Erreur lors de l'intégration de la solution pour ${problemId}: ${error.message}`);
        }
    }

    /**
     * Ensures a problem has an initial solution. If not, generates one.
     * @param {object} problem - Problem object.
     * @private
     */
    async _ensureInitialSolution(problem) {
        if (problem.state.bestSolution) {
            return; // A solution already exists
        }

        console.log(`[ProblemManager] Génération d'une solution initiale pour le problème ${problem.id}...`);

        // Use score function defined in config
        const scoreFunction = problem.workUnit.scoreFunction;
        // Assume initial solution source is defined in config
        const initialSolutionSource = problem.payload[problem.workUnit.initialSolutionSource];

        if (scoreFunction && initialSolutionSource && Array.isArray(initialSolutionSource)) {
            const initialSolution = initialSolutionSource;
            // Calculate score (energy, fitness, etc.) of this initial solution.
            // Scoring function may require additional arguments from payload.
            const score = scoreFunction(initialSolution, problem.payload);

            problem.state.bestSolution = initialSolution;
            // Score property name depends on problem type
            problem.state.bestEnergy = score; // Could be generalized if needed
            problem.state.lastUpdate = new Date().toISOString();

            console.log(`[ProblemManager] Solution initiale pour ${problem.id} générée avec un score de ${score.toFixed(2)}.`);
            // Save the newly generated initial solution to the store.
            await this.store.set(`problem-state:${problem.id}`, problem.state);
        }
    }

    /**
     * Integrates a new Pareto front into problem state.
     * @param {object} problem - Problem object.
     * @param {Array<object>} newFront - Pareto front returned by client.
     * @private
     */
    async _integrateParetoFront(problem, newFront) {
        if (!Array.isArray(newFront) || newFront.length === 0) return;

        const currentFront = problem.state.paretoFront || []; // eslint-disable-line no-unused-vars
        const combined = [...currentFront, ...newFront];

        // --- Non-dominated sorting logic to find new best front ---
        const paretoDominates = (a, b) => {
            let aIsBetterInOne = false;
            // Assume objectives are to be minimized
            for (let i = 0; i < a.objectives.length; i++) {
                if (a.objectives[i] > b.objectives[i]) return false; // A is worse on at least one objective
                if (a.objectives[i] < b.objectives[i]) aIsBetterInOne = true; // A is strictly better on at least one
            }
            return aIsBetterInOne;
        };

        const nextFront = [];
        const dominatedIndices = new Set();

        for (let i = 0; i < combined.length; i++) {
            if (dominatedIndices.has(i)) continue;
            let isDominated = false;
            for (let j = 0; j < combined.length; j++) {
                if (i === j || dominatedIndices.has(j)) continue;
                if (paretoDominates(combined[j], combined[i])) {
                    isDominated = true;
                    break;
                }
                if (paretoDominates(combined[i], combined[j])) {
                    dominatedIndices.add(j);
                }
            }
            if (!isDominated) {
                nextFront.push(combined[i]);
            }
        }

        // Update if the new front is different in size OR content.
        // Stringifying is a simple way to check for content changes.
        const hasContentChanged = JSON.stringify(nextFront) !== JSON.stringify(problem.state.paretoFront);
        if (hasContentChanged) {
            console.log(`[ProblemManager] Nouveau front de Pareto pour ${problem.id} avec ${nextFront.length} solutions (précédemment ${currentFront.length}).`);
            problem.state.paretoFront = nextFront;
            problem.state.lastUpdate = new Date().toISOString();
            await this.store.set(`problem-state:${problem.id}`, problem.state);
        }
    }

    /**
     * Retrieves currently known best solution for one or more problems.
     * @param {string} [problemId] - Optional problem ID to inspect.
     * If omitted, returns best solutions for all problems.
     * @returns {object|Array<object>|null}
     * - If `problemId` is provided, returns `{ id, solution, score }` or `null` if not found.
     * - If no `problemId` is provided, returns array of these objects.
     */
    async getBestSolutions(problemId) {
        const problemsToProcess = problemId
            ? this.problems.filter(p => p.id === problemId)
            : this.problems;

        // Only generate an initial solution for single-objective problems
        for (const p of problemsToProcess.filter(p => p.workUnit.type !== 'multi_objective_genetic_algorithm')) {
            await this._ensureInitialSolution(p);
        }

        const formatSolution = (p) => {
            // After _ensureInitialSolution, p.state can be assumed to exist.
            if (!p || !p.state) return null;

            // Special case for multi-objective problems
            if (p.workUnit.type === 'multi_objective_genetic_algorithm') {
                return {
                    id: p.id,
                    solution: p.state.paretoFront, // "solution" is the entire front
                    score: p.state.paretoFront?.length || 0, // "score" is number of points on front
                    lastUpdate: p.state.lastUpdate,
                };
            }

            return {
                id: p.id,
                solution: p.state.bestSolution,
                score: p.state.bestEnergy,
                lastUpdate: p.state.lastUpdate,
            };
        };

        if (problemId) {
            const problem = this.problems.find(p => p.id === problemId);
            return problem ? formatSolution(problem) : null; // Initial filtering already done
        }

        // Return overview for all problems
        return this.problems.map(formatSolution).filter(s => s && s.solution);
    }

    /**
     * Updates payload of a specific problem by its ID.
     * @param {string} problemId - ID of problem to update.
     * @param {object} newPayload - New payload object to replace old one.
     * @returns {boolean} - True if update succeeded, false otherwise.
     */
    async updateProblemPayload(problemId, newPayload) {
        const problem = this.problems.find(p => p.id === problemId);
        if (!problem) {
            console.error(`[ProblemManager] Impossible de mettre à jour : problème avec l'ID '${problemId}' non trouvé.`);
            return false;
        }

        console.log(`[ProblemManager] Mise à jour du payload pour le problème '${problemId}'.`);
        problem.payload = newPayload;

        // Invalidate current state because problem has changed
        problem.state.bestSolution = null;
        problem.state.bestEnergy = "Infinity";

        await this.store.set(`problem-state:${problem.id}`, problem.state);
        return true;
    }

}

export { ProblemManager }; // Export the class for testing

/**
 * @type {ProblemManager | null}
 */
let problemManagerInstance = null;
let managerPromise = null;

/**
 * Gets or creates the singleton instance of the ProblemManager.
 * @param {object} [options] - The options for initialization.
 * @param {string} [options.configPath='./problems.config.json'] - The path to the problems configuration file.
 * @param {object} [options.config] - The problem configuration as an object.
 * @param {IStore} [store] - The datastore instance.
 * @returns {Promise<ProblemManager>} The singleton instance.
 */
export function getProblemManager(options = {}, store) {
    const defaultPath = join(__dirname, '..', '..', 'config', 'problems.config.json');
    const { configPath = defaultPath, config } = options;

    const hasConfigChanged = problemManagerInstance && (
        (config && problemManagerInstance.config !== config) ||
        (configPath && problemManagerInstance.configPath !== configPath)
    );
    if (!managerPromise || hasConfigChanged || (problemManagerInstance && problemManagerInstance.store !== store)) {
        managerPromise = ProblemManager.create({ configPath, config }, store).then(manager => {
            problemManagerInstance = manager;
            return manager;
        });
    }
    return managerPromise;
}
export const problemManager = await getProblemManager(); // This now exports the resolved ProblemManager instance

/**
 * @internal
 * For testing purposes only.
 */
export const __internal = {
    resetManager: () => {
        problemManagerInstance = null;
        managerPromise = null;
    }
};
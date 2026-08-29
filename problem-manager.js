import { promises as fs } from 'node:fs';
import { Optimization } from './library.js';

/**
 * @namespace FunctionRegistry
 * @description Registre pour exposer de manière contrôlée les fonctions de la bibliothèque.
 * Permet de les appeler dynamiquement depuis la configuration des problèmes.
 * Utilise la notation par points pour accéder aux fonctions imbriquées (ex: 'tsp.calculateEnergy').
 */
const FunctionRegistry = {};

// --- Fonctions de "Scoring" (évaluation d'une solution) ---
// Ces fonctions sont des adaptateurs pour utiliser les utilitaires de la bibliothèque
// avec la structure attendue par le ProblemManager.
FunctionRegistry['cpc.solve'] = Optimization.Operators.solveOptimalCPC; // NOUVEAU: Enregistrement du solveur CPC

/**
/**
 * Évalue la distance totale d'un chemin pour le problème du voyageur de commerce (TSP).
 * @param {Array<{x: number, y: number}>} path - Un tableau de points représentant le chemin.
 * @returns {number} La distance totale du chemin.
 */
FunctionRegistry['tsp.calculateEnergy'] = (path) => {
    // Crée un tableau d'indices [0, 1, 2, ...] pour la fonction evaluatePathDistance.
    const indices = Array.from({ length: path.length }, (_, i) => i);
    return Optimization.Utils.evaluatePathDistance(path, indices);
};

/**
 * Évalue les métriques d'un portefeuille (rendement et volatilité).
 * Pour l'instant, retourne le rendement négatif pour correspondre à l'objectif de minimisation
 * de l'algorithme génétique de la bibliothèque.
 * @param {Array<number>} weights - Les poids des actifs dans le portefeuille.
 * @param {object} payload - Le payload du problème, contenant les actifs.
 * @returns {number} Le rendement négatif du portefeuille.
 */
FunctionRegistry['portfolio.calculateMetrics'] = (weights, payload) => {
    const { assets, maxVolatility } = payload;
    // On utilise l'opérateur de la bibliothèque pour créer la fonction de fitness
    // et on l'appelle immédiatement.
    const fitnessFunction = Optimization.Operators.createPortfolioAllocator({
        assets,
        maxVolatility,
    });
    // La fonction de fitness retourne le rendement négatif, ce qui est ce que nous voulons
    // stocker comme "énergie" ou score.
    return fitnessFunction(weights);
};

// --- Fonctions de "Résolution" (algorithmes complets) ---
// Utiles pour les workers qui exécutent une tâche de bout en bout.
FunctionRegistry['tsp.solve'] = Optimization.Operators.solveTSP;
FunctionRegistry['portfolio.solve'] = Optimization.Operators.solvePortfolio;
FunctionRegistry['fraud.solve'] = Optimization.Operators.solveFraudDetection; // NOUVEAU: Enregistrement du solveur de fraude
FunctionRegistry['facility.solve'] = Optimization.Operators.solveFacilityLocation;
FunctionRegistry['security.tune'] = Optimization.Operators.solveFullSecurityTuning;

// --- Fonctions "Utilitaires" ---
FunctionRegistry['utils.evaluatePathDistance'] = Optimization.Utils.evaluatePathDistance;


/**
 * @namespace ProblemInitializers
 * @description Fonctions pour générer dynamiquement les données d'un problème.
 */
const ProblemInitializers = {
    /**
     * Génère un ensemble de points aléatoires pour un problème de TSP.
     * @param {object} params - Les paramètres de génération.
     * @param {number} params.count - Le nombre de points à générer.
     * @param {{x: number, y: number}} [params.bounds={x: 1000, y: 1000}] - Les limites spatiales.
     * @returns {Array<{x: number, y: number}>}
     */
    'generate:randomPoints': (params) => {
        const { count, bounds = { x: 1000, y: 1000 } } = params;
        if (isNaN(count)) return [];
        return Array.from({ length: count }, () => ({ x: Math.random() * bounds.x, y: Math.random() * bounds.y }));
    },

    /**
     * Génère un ensemble d'actifs financiers aléatoires pour un problème de portefeuille.
     * @param {object} params - Les paramètres de génération.
     * @param {number} params.count - Le nombre d'actifs à générer.
     * @returns {Array<{expectedReturn: number, volatility: number}>}
     */
    'generate:randomAssets': (params) => {
        const { count } = params;
        if (isNaN(count)) return [];
        return Array.from({ length: count }, () => ({
            expectedReturn: Math.random() * 0.2,
            volatility: 0.1 + Math.random() * 0.3
        }));
    },

    /**
     * Crée une fonction qui génère des arguments pour chaque worker de `runMultipleParallel`.
     * Permet de faire varier les paramètres (ex: solution initiale) pour chaque cycle.
     * @param {object} params - Les paramètres de configuration.
     * @param {Array<any>} params.baseArgs - Les arguments de base, communs à tous les workers.
     * @param {object} params.variations - Décrit comment faire varier un argument.
     * @returns {function(number): Array<any>} La fonction `workerDataGenerator`.
     */
    'generate:parallelArgs': (params) => {
        const { baseArgs, variations } = params;
        return (cycleIndex) => {
            const cycleArgs = [...baseArgs];
            // Pour l'instant, on gère la variation de la solution initiale pour le TSP
            if (variations?.initialSolution === 'random') {
                cycleArgs[0] = cycleArgs[0].sort(() => Math.random() - 0.5);
            }
            return cycleArgs;
        };
    }
};

class ProblemManager {
    /**
     * @private
     * Le constructeur est privé. Utilisez la méthode de fabrique asynchrone `create()`.
     * @param {string} configPath - Le chemin vers le fichier de configuration.
     * @param {Array<object>} problems - Les problèmes pré-chargés.
     * @param {IStore} store - The datastore for synchronization.
     */
    constructor(configPath, problems, store) {
        this.configPath = configPath;
        this.problems = problems;
        this.store = store; // The datastore instance
        this.currentProblemIndex = 0;
    }

    /**
     * Méthode de fabrique asynchrone pour créer et initialiser une instance de ProblemManager.
     * @param {string} configPath - Le chemin vers le fichier de configuration.
     * @returns {Promise<ProblemManager>}
     */
    static async create(configPath, store) {
        const manager = new ProblemManager(configPath, [], store);
        manager.problems = await manager.loadProblems(configPath);
        return manager;
    }

    /**
     * Charge et parse les problèmes depuis le fichier de configuration de manière asynchrone.
     * It now also synchronizes with the datastore.
     * @param {string} configPath - Le chemin vers le fichier de configuration.
     * @returns {Promise<Array<object>>}
     */
    async loadProblems(configPath) {
        // Guard clause: If no store is configured (e.g., during isolated test imports),
        // do not attempt to load problems to prevent crashes.
        if (!this.store) {
            return [];
        }

        try {
            const data = await fs.readFile(configPath, 'utf-8');
            const problemsFromFile = JSON.parse(data);

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
            // Initialisation dynamique des problèmes
            for (const problem of problems) {
                // Résolution des fonctions via le registre
                if (problem.workUnit.scoreFunction) {
                    problem.workUnit.scoreFunction = FunctionRegistry[problem.workUnit.scoreFunction] || null;
                }
                for (const key in problem.payload) {
                    const value = problem.payload[key];
                    // On cherche une instruction d'initialisation (ex: { "$init": "generate:randomPoints", ... })
                    if (typeof value === 'object' && value !== null && value.$init) {
                        const initializer = ProblemInitializers[value.$init];
                        // On cherche une instruction de fonction (ex: { "$func": "tsp.calculateEnergy" })
                        // Note: Actuellement non utilisé, mais prêt pour une future extension.
                        if (initializer) {
                            // On remplace l'objet d'instruction par les données générées.
                            problem.payload[key] = initializer(value.params || {});
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
     * Sélectionne un problème et génère une unité de travail.
     * @param {number} suspicionFactor - Le facteur de suspicion pour ajuster la difficulté.
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
                // Assurer une difficulté minimale pour que le challenge soit significatif
                const baseIterations = Math.max(15000, problem.workUnit.baseIterations || 0);
                task.iterations = scalingFactor
                    ? Math.floor(baseIterations * Math.pow(scalingFactor, suspicionFactor))
                    : Math.floor(baseIterations * (0.5 + suspicionFactor));
                task.payload = problem.payload;
                task.initialSolution = problem.state.bestSolution;
                break;

            case 'genetic_algorithm_generations':
                // Assurer une difficulté minimale pour que le challenge soit significatif
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
                // Les arguments et le générateur sont dans le payload pour plus de flexibilité
                task.baseSolverArgs = problem.payload.baseSolverArgs;
                task.workerDataGenerator = problem.payload.workerDataGenerator;
                task.logProgress = problem.payload.logProgress || false;
                task.concurrency = problem.payload.concurrency;
                break;
            
            case 'multi_objective_genetic_algorithm':
                // La difficulté s'applique au nombre de générations
                const baseGenerationsMulti = Math.max(30, problem.workUnit.baseGenerations || 0);
                task.generations = scalingFactor
                    ? Math.floor(baseGenerationsMulti * Math.pow(scalingFactor, suspicionFactor))
                    : Math.floor(baseGenerationsMulti * (0.5 + suspicionFactor));
                task.payload = problem.payload;
                // L'état initial est le front de Pareto actuel, que le client peut utiliser pour l'élitisme
                task.initialFront = problem.state.paretoFront;
                task.solverName = problem.workUnit.solverName; // Le nom du solveur à utiliser (ex: 'cpc.solve')
                break;
        }

        return { problemId: problem.id, task };
    }

    /**
     * Intègre la solution d'un client dans l'état du problème.
     * @param {string} problemId - L'ID du problème.
     * @param {object} solutionData - La solution renvoyée par le client.
     */
    async integrateSolution(problemId, solutionData) {
        const problem = this.problems.find(p => p.id === problemId);
        if (!problem) return;
        const storeKey = `problem-state:${problem.id}`;
        switch (problem.workUnit.type) {
            case 'simulated_annealing_iterations':
            // 1. Ne JAMAIS faire confiance au score du client. Recalculer systématiquement.
            const scoreFunction = problem.workUnit.scoreFunction;
            if (!scoreFunction) {
                console.error(`[ProblemManager] Aucune fonction de score définie pour ${problemId}. Impossible de vérifier la solution.`);
                return;
            }
            const recalculatedEnergy = scoreFunction(solutionData.solution, problem.payload);

                const currentBest = parseFloat(problem.state.bestEnergy) || Infinity;
            // 2. Comparer le score recalculé, pas celui du client.
            const isBetter = recalculatedEnergy < currentBest;

                if (isBetter) {
                    problem.state.bestSolution = solutionData.solution;
                problem.state.bestEnergy = recalculatedEnergy; // 3. Stocker le score vérifié.
                problem.state.lastUpdate = new Date().toISOString();
                console.log(`[ProblemManager] Nouvelle meilleure solution pour ${problemId}: ${recalculatedEnergy.toFixed(2)}`);
                }
                break;
            case 'genetic_algorithm_generations':
                // VÉRIFICATION PAR ÉCHANTILLONNAGE pour équilibrer sécurité et performance.
                const fitnessFunction = FunctionRegistry['portfolio.calculateMetrics']; // Ou une fonction plus générique
                if (!fitnessFunction || !solutionData.population || solutionData.population.length === 0) {
                    console.error(`[ProblemManager] Impossible de vérifier la population pour ${problemId}.`);
                    return; // Ne rien faire si la vérification est impossible.
                }

                // 1. On choisit un petit échantillon aléatoire de la population soumise.
                const sampleSize = Math.min(5, solutionData.population.length);
                const sampleIndices = new Set();
                while (sampleIndices.size < sampleSize) {
                    sampleIndices.add(Math.floor(Math.random() * solutionData.population.length));
                }

                // 2. On recalcule le score pour cet échantillon.
                let totalRecalculatedFitness = 0;
                for (const index of sampleIndices) {
                    const individual = solutionData.population[index];
                    totalRecalculatedFitness += fitnessFunction(individual.chromosome, problem.payload);
                }

                problem.state.population = solutionData.population; // On accepte la population
                console.log(`[ProblemManager] Population mise à jour pour ${problemId}. Fitness moyen de l'échantillon: ${(totalRecalculatedFitness / sampleSize).toFixed(4)}`);
                break;
            
            case 'multi_objective_genetic_algorithm':
                // Pour le multi-objectifs, on fusionne le front de Pareto existant avec celui du client.
                await this._integrateParetoFront(problem, solutionData.paretoFront);
                break;
        }
        // Persist the updated state to the datastore immediately.
        await this.store.set(storeKey, problem.state);
    }

    /**
     * S'assure qu'un problème a une solution initiale. Si non, en génère une.
     * @param {object} problem - L'objet problème.
     * @private
     */
    async _ensureInitialSolution(problem) {
        if (problem.state.bestSolution) {
            return; // Une solution existe déjà
        }

        console.log(`[ProblemManager] Génération d'une solution initiale pour le problème ${problem.id}...`);

        // On utilise la fonction de score définie dans la config
        const scoreFunction = problem.workUnit.scoreFunction;
        // On suppose que la source de la solution initiale est définie dans la config
        const initialSolutionSource = problem.payload[problem.workUnit.initialSolutionSource];

        if (scoreFunction && initialSolutionSource && Array.isArray(initialSolutionSource)) {
            const initialSolution = initialSolutionSource;
            // On calcule le score (énergie, fitness, etc.) de cette solution initiale.
            // La fonction de scoring peut nécessiter des arguments supplémentaires du payload.
            const score = scoreFunction(initialSolution, problem.payload);

            problem.state.bestSolution = initialSolution;
            // Le nom de la propriété du score dépend du type de problème
            problem.state.bestEnergy = score; // Pourrait être généralisé si besoin
            problem.state.lastUpdate = new Date().toISOString();

            console.log(`[ProblemManager] Solution initiale pour ${problem.id} générée avec un score de ${score.toFixed(2)}.`);
            // Save the newly generated initial solution to the store.
            await this.store.set(`problem-state:${problem.id}`, problem.state);
        }
    }

    /**
     * Intègre un nouveau front de Pareto dans l'état du problème.
     * @param {object} problem - L'objet problème.
     * @param {Array<object>} newFront - Le front de Pareto renvoyé par un client.
     * @private
     */
    async _integrateParetoFront(problem, newFront) {
        if (!Array.isArray(newFront) || newFront.length === 0) return;

        const currentFront = problem.state.paretoFront || []; // eslint-disable-line no-unused-vars
        const combined = [...currentFront, ...newFront];

        // --- Logique de tri non-dominé pour trouver le nouveau meilleur front ---
        const paretoDominates = (a, b) => {
            let aIsBetterInOne = false;
            // On suppose que les objectifs sont à minimiser
            for (let i = 0; i < a.objectives.length; i++) {
                if (a.objectives[i] > b.objectives[i]) return false; // A est pire sur au moins un objectif
                if (a.objectives[i] < b.objectives[i]) aIsBetterInOne = true; // A est strictement meilleur sur au moins un
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
     * Récupère la meilleure solution actuellement connue pour un ou plusieurs problèmes.
     * @param {string} [problemId] - L'ID optionnel du problème à consulter.
     * Si non fourni, retourne les meilleures solutions pour tous les problèmes.
     * @returns {object|Array<object>|null}
     * - Si un `problemId` est fourni, retourne un objet `{ id, solution, score }` ou `null` si non trouvé.
     * - Si aucun `problemId` n'est fourni, retourne un tableau de ces objets.
     */
    async getBestSolutions(problemId) {
        const problemsToProcess = problemId
            ? this.problems.filter(p => p.id === problemId)
            : this.problems;

        // On ne génère une solution initiale que pour les problèmes mono-objectif
        for (const p of problemsToProcess.filter(p => p.workUnit.type !== 'multi_objective_genetic_algorithm')) {
            await this._ensureInitialSolution(p);
        }

        const formatSolution = (p) => {
            // Après _ensureInitialSolution, on peut supposer que p.state existe.
            if (!p || !p.state) return null;

            // Cas spécial pour les problèmes multi-objectifs
            if (p.workUnit.type === 'multi_objective_genetic_algorithm') {
                return {
                    id: p.id,
                    solution: p.state.paretoFront, // La "solution" est l'ensemble du front
                    score: p.state.paretoFront?.length || 0, // Le "score" est le nombre de points sur le front
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
            return problem ? formatSolution(problem) : null; // Le filtrage initial a déjà fait le travail
        }

        // Retourne un aperçu pour tous les problèmes
        return this.problems.map(formatSolution).filter(s => s && s.solution);
    }

    /**
     * Met à jour le payload d'un problème spécifique par son ID.
     * @param {string} problemId - L'ID du problème à mettre à jour.
     * @param {object} newPayload - Le nouvel objet payload qui remplacera l'ancien.
     * @returns {boolean} - True si la mise à jour a réussi, false sinon.
     */
    async updateProblemPayload(problemId, newPayload) {
        const problem = this.problems.find(p => p.id === problemId);
        if (!problem) {
            console.error(`[ProblemManager] Impossible de mettre à jour : problème avec l'ID '${problemId}' non trouvé.`);
            return false;
        }

        console.log(`[ProblemManager] Mise à jour du payload pour le problème '${problemId}'.`);
        problem.payload = newPayload;

        // Invalider l'état actuel car le problème a changé
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
 * @param {string} [configPath] - The path to the problems configuration file. If not provided, uses the existing instance or a default path.
 * @returns {Promise<ProblemManager>} The singleton instance.
 * @param {IStore} [store] - The datastore instance.
 */
export function getProblemManager(configPath = './problems.config.json', store) {
    if (!managerPromise || (problemManagerInstance && (problemManagerInstance.configPath !== configPath || problemManagerInstance.store !== store))) {
        managerPromise = ProblemManager.create(configPath, store).then(manager => {
            problemManagerInstance = manager;
            return manager;
        });
    }
    return managerPromise;
}
export const problemManager = getProblemManager(); // This now exports a Promise

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
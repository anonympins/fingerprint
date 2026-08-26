import { readFileSync, writeFileSync } from 'node:fs';
import { Optimization } from './library.js';

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
    constructor(configPath) {
        this.configPath = configPath;
        this.problems = this.loadProblems();
        this.currentProblemIndex = 0;
    }

    loadProblems() {
        try {
            const data = readFileSync(this.configPath, 'utf-8');
            const problems = JSON.parse(data);
            // Initialisation dynamique des problèmes
            for (const problem of problems) { // eslint-disable-line no-unused-vars
                for (const key in problem.payload) {
                    const value = problem.payload[key];
                    // On cherche une instruction d'initialisation (ex: { "$init": "generate:randomPoints", ... })
                    if (typeof value === 'object' && value !== null && value.$init) {
                        const initializer = ProblemInitializers[value.$init];
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

    saveProblems() {
        // Note: Dans un vrai scénario, utilisez une base de données pour éviter les race conditions.
        try {
            writeFileSync(this.configPath, JSON.stringify(this.problems, null, 2));
        } catch (error) {
            console.error(`[ProblemManager] Erreur lors de la sauvegarde du fichier de problèmes: ${error.message}`);
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
        }

        return { problemId: problem.id, task };
    }

    /**
     * Intègre la solution d'un client dans l'état du problème.
     * @param {string} problemId - L'ID du problème.
     * @param {object} solutionData - La solution renvoyée par le client.
     */
    integrateSolution(problemId, solutionData) {
        const problem = this.problems.find(p => p.id === problemId);
        if (!problem) return;

        switch (problem.workUnit.type) {
            case 'simulated_annealing_iterations':
                if (solutionData.energy < (parseFloat(problem.state.bestEnergy) || Infinity)) {
                    problem.state.bestSolution = solutionData.solution;
                    problem.state.bestEnergy = solutionData.energy;
                    console.log(`[ProblemManager] Nouvelle meilleure solution pour ${problemId}: ${solutionData.energy.toFixed(2)}`);
                }
                break;
            case 'genetic_algorithm_generations':
                problem.state.population = solutionData.population;
                console.log(`[ProblemManager] Population mise à jour pour ${problemId}.`);
                break;
        }
        this.saveProblems();
    }
}

export { ProblemManager }; // Export the class for testing
export const problemManager = new ProblemManager('./problems.config.json');
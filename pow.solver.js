/**
 * @file @/pow.solver.js
 * @description Contient les fonctions côté client pour résoudre les différents types de challenges Proof-of-Work.
 * IMPORTANT: Pour les tâches d'optimisation, ce fichier a besoin d'accéder aux algorithmes de `library.js`.
 * Dans un vrai projet, il faudrait bundler une version client de `library.js` et l'importer ici.
 * Pour cet exemple, nous allons copier/coller les fonctions nécessaires.
 * Fichier compatible à la fois avec l'import de modules ES6 et l'injection directe dans un script HTML.
 */

'use strict';

/**
 * Résout un challenge CPU basé sur une cible (version inline pour compatibilité HTML).
 * @param {string} clientIp - L'adresse IP du client.
 * @param {string} nonce - Le nonce du challenge.
 * @param {bigint} target - La cible à atteindre.
 * @param {string} clientSecret - Le secret client (optionnel).
 * @param {Function} progressCallback - Callback pour les mises à jour de progression.
 * @param {string} [fingerprint=''] - The client's fingerprint, to be included in the hash.
 * @returns {Promise<number>} La solution (un nombre entier).
 */
export async function solveCpuTargetInline(clientIp, nonce, target, clientSecret = null, progressCallback, fingerprint = '') {
    // Le 'target' est déjà un BigInt lorsqu'il est appelé depuis la page de challenge.
    // On s'assure juste qu'il est bien de ce type.
    const cpuTarget = typeof target === 'bigint' ? target : BigInt('0x' + target);
    let cpuSolution = 0;
    const ipPart = clientIp || ''; // Use empty string if IP is null/undefined
    while (true) { // When a clientSecret is used, the IP is omitted from the hash to make it independent of the network.
        const msg = clientSecret ? // The fingerprint is part of the signed message when a secret is used.
            `${nonce}:${cpuSolution}:${clientSecret}:${fingerprint}` :
            `${ipPart}:${nonce}:${cpuSolution}`;
        // --- AJOUT DE LOGS POUR LE DÉBOGAGE ---
        if (cpuSolution === 0) { // Log only the first attempt to avoid flooding the console
            console.log('[FP Solve Debug] Client will hash message:', msg);
        }
        // --- FIN DES LOGS ---
        const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(msg));
        const hashHex = Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
        if (BigInt('0x' + hashHex) < cpuTarget) break;
        cpuSolution++;
        if (cpuSolution % 100000 === 0) {
            await new Promise(r => setTimeout(r, 0));
            if (progressCallback) progressCallback(cpuSolution);
        }
    }
    return cpuSolution;
}

/**
 * Résout un challenge CPU basé sur une cible (version Web Worker).
 * @param {string} message - Le message à hasher (ex: `ip:nonce:solution:secret`).
 * @param {bigint} target - La cible à atteindre.
 * @returns {Promise<number>} La solution (un nombre entier).
 */
export async function solveCpuTarget(message, target) {
    // Vérifie si les Web Workers sont supportés par le navigateur.
    if (typeof(Worker) === "undefined") {
        console.warn("Web Workers not supported. Falling back to main thread calculation (UI may freeze).");
        // Ici, on pourrait remettre l'ancienne implémentation comme solution de secours.
        // Pour la clarté, nous supposons que les workers sont disponibles.
        throw new Error("Web Worker support is required for CPU challenges.");
    }

    return new Promise((resolve, reject) => {
        // Crée un worker à partir du script dédié. Le chemin doit être accessible publiquement.
        // Assurez-vous que `pow.worker.js` est servi par votre serveur statique.
        const worker = new Worker('./pow.worker.js');

        worker.onmessage = (event) => {
            resolve(event.data.solution);
            worker.terminate(); // Nettoie le worker une fois le travail terminé.
        };

        worker.onerror = (error) => {
            reject(error);
            worker.terminate();
        };

        // Envoie les données du challenge au worker pour qu'il commence le calcul.
        worker.postMessage({ message, target });
    });
}

/**
 * Résout un challenge basé sur la mémoire.
 * @param {string} seed - La graine pour l'initialisation de la mémoire.
 * @param {number} difficulty - La difficulté (en Mo).
 * @returns {Promise<number>} La solution (nombre entier).
 */
export async function solveMemory(seed, difficulty) {
    // On définit un seuil pour savoir quand faire une pause, afin de ne pas bloquer le thread UI.
    const YIELD_THRESHOLD = 100000;
    const size = difficulty * 1024 * 1024;
    const buffer = new Uint32Array(size / 4);
    let h = new TextEncoder().encode(seed).reduce((acc, v) => acc + v, 0);

    for (let i = 0; i < buffer.length; i++) {
        buffer[i] = (h = Math.imul(h ^ i, 1597334677));
        if (i % YIELD_THRESHOLD === 0) {
            await new Promise(r => setTimeout(r, 0)); // Respiration pour ne pas geler l'UI
        }
    }

    let solution = 0;
    const iterations = size / 16;
    let addr = buffer.length > 0 ? buffer[0] % buffer.length : 0;
    for (let i = 0; i < iterations; i++) {
        addr = buffer[addr] % buffer.length;
        solution ^= addr;
        if (i % YIELD_THRESHOLD === 0) {
            await new Promise(r => setTimeout(r, 0)); // Respiration pour ne pas geler l'UI
        }
    }
    return solution;
}

/**
 * Résout un challenge de type "Problème du Voyageur de Commerce" (TSP).
 * NOTE: Ceci est une implémentation simple (heuristique du plus proche voisin) et n'est pas garantie
 * de trouver la solution optimale, mais elle est suffisante pour un challenge.
 * @param {Array<{x: number, y: number}>} cities - Les coordonnées des villes.
 * @param {number} targetMaxDistance - La distance maximale acceptable.
 * @returns {Promise<{path: number[], distance: number}>} Le chemin et la distance.
 */
export async function solveTsp(cities, targetMaxDistance) {
    // Utility function to calculate the distance between two cities
    function distance(city1, city2) {
        return Math.sqrt(Math.pow(city1.x - city2.x, 2) + Math.pow(city1.y - city2.y, 2));
    }

    // Utility function to evaluate the total distance of a path
    function evaluatePathDistance(cities, path) {
        let totalDistance = 0;
        for (let i = 0; i < path.length - 1; i++) {
            totalDistance += distance(cities[path[i]], cities[path[i + 1]]);
        }
        totalDistance += distance(cities[path[path.length - 1]], cities[path[0]]); // Return to start
        return totalDistance;
    }

    // Solveur simple du TSP (heuristique du plus proche voisin)
    function solveTspNearestNeighbor(cities) {
        const numCities = cities.length;
        if (numCities === 0) return [];

        let currentPath = [];
        let visited = new Array(numCities).fill(false);

        let currentCityIndex = 0; // Always start with the first city for reproducibility
        currentPath.push(currentCityIndex);
        visited[currentCityIndex] = true;

        for (let i = 1; i < numCities; i++) {
            let nearestCityIndex = -1;
            let minDistance = Infinity;

            for (let j = 0; j < numCities; j++) {
                if (!visited[j]) {
                    const dist = distance(cities[currentCityIndex], cities[j]);
                    if (dist < minDistance) {
                        minDistance = dist;
                        nearestCityIndex = j;
                    }
                }
            }
            currentCityIndex = nearestCityIndex;
            currentPath.push(currentCityIndex);
            visited[currentCityIndex] = true;
        }
        return currentPath;
    }

    // To avoid freezing the browser, yield the thread from time to time
    await new Promise(resolve => setTimeout(resolve, 10));
    const solutionPath = solveTspNearestNeighbor(cities);
    const solutionDistance = evaluatePathDistance(cities, solutionPath);

    return { path: solutionPath, distance: solutionDistance };
}

// --- Fonctions d'optimisation copiées/adaptées de library.js pour le client ---

const ClientOptimizers = {
    simulatedAnnealing(initialSolution, evaluator, neighbor, iterations, temp, cooling) {
        let currentSolution = initialSolution;
        let currentEnergy = evaluator(currentSolution);
        let temperature = temp;

        for (let i = 0; i < iterations; i++) {
            const newSolution = neighbor(currentSolution);
            const newEnergy = evaluator(newSolution);
            if (newEnergy < currentEnergy || Math.random() < Math.exp((currentEnergy - newEnergy) / temperature)) {
                currentSolution = newSolution;
                currentEnergy = newEnergy;
            }
            temperature *= cooling;
        }
        return { solution: currentSolution, energy: currentEnergy };
    },

    geneticAlgorithm(createIndividual, fitness, crossover, mutate, generations, popSize) {
        let population = Array.from({ length: popSize }, () => {
            const chromosome = createIndividual();
            return { chromosome, fitness: fitness(chromosome) };
        });

        for (let gen = 0; gen < generations; gen++) {
            population.sort((a, b) => a.fitness - b.fitness);
            const newPopulation = [population[0]]; // Elitism
            while (newPopulation.length < popSize) {
                const p1 = population[Math.floor(Math.random() * (popSize / 2))];
                const p2 = population[Math.floor(Math.random() * (popSize / 2))];
                let offspring = crossover(p1.chromosome, p2.chromosome);
                if (Math.random() < 0.1) offspring = mutate(offspring);
                newPopulation.push({ chromosome: offspring, fitness: fitness(offspring) });
            }
            population = newPopulation;
        }
        return population;
    }
};

/**
 * Résout une unité de travail utile (Useful Work Unit).
 * @param {object} task - La tâche envoyée par le serveur.
 * @returns {Promise<object>} Le résultat du calcul.
 */
async function solveUsefulWorkTask(task) {
    await new Promise(r => setTimeout(r, 10)); // Yield thread

    switch (task.type) {
        case 'simulated_annealing_iterations': {
            const { cities } = task.payload;
            const distance = (c1, c2) => Math.sqrt(Math.pow(c1.x - c2.x, 2) + Math.pow(c1.y - c2.y, 2));
            const evaluator = (path) => {
                let total = 0;
                for (let i = 0; i < path.length - 1; i++) total += distance(cities[path[i]], cities[path[i + 1]]);
                total += distance(cities[path[path.length - 1]], cities[path[0]]);
                return total;
            };
            const neighbor = (path) => {
                const newPath = [...path];
                const [i, j] = [Math.floor(Math.random() * path.length), Math.floor(Math.random() * path.length)];
                [newPath[i], newPath[j]] = [newPath[j], newPath[i]];
                return newPath;
            };
            const initialSolution = task.initialSolution || Array.from({ length: cities.length }, (_, i) => i).sort(() => 0.5 - Math.random());
            
            return ClientOptimizers.simulatedAnnealing(initialSolution, evaluator, neighbor, task.iterations, task.payload.options.initialTemperature, task.payload.options.coolingRate);
        }

        case 'genetic_algorithm_generations': {
            const { assets, maxVolatility } = task.payload;
            const fitness = (weights) => {
                const total = weights.reduce((s, w) => s + w, 0);
                if (total === 0) return Infinity;
                const normW = weights.map(w => w / total);
                const ret = normW.reduce((s, w, i) => s + w * assets[i].expectedReturn, 0);
                const vol = normW.reduce((s, w, i) => s + w * assets[i].volatility, 0);
                if (vol > maxVolatility) return 1000 + (vol - maxVolatility);
                return -ret;
            };
            const createIndividual = () => Array.from({ length: assets.length }, Math.random);
            const crossover = (p1, p2) => p1.map((w, i) => (w + p2[i]) / 2);
            const mutate = p => { const n = [...p], i = Math.floor(Math.random() * n.length); n[i] += (Math.random() - 0.5) * 0.2; return n.map(v => Math.max(0, v)); };
            
            // Le client doit recréer la population si elle n'est pas fournie
            const initialPopulation = task.initialPopulation || Array.from({ length: task.payload.options.populationSize }, () => ({ chromosome: createIndividual(), fitness: 0 }));
            initialPopulation.forEach(p => p.fitness = fitness(p.chromosome));

            const finalPopulation = ClientOptimizers.geneticAlgorithm(createIndividual, fitness, crossover, mutate, task.generations, task.payload.options.populationSize);
            return { population: finalPopulation };
        }

        case 'run_multiple_parallel':
            // Côté client, on ne peut pas utiliser de vrais workers pour `runMultipleParallel`.
            // On exécute donc une version simplifiée : un seul cycle du solveur demandé.
            // Cela reste un travail coûteux et valide le principe du "Useful Work".
            const { solverName, baseSolverArgs } = task;
            const clientSolver = ClientOptimizers[solverName];
            if (!clientSolver) throw new Error(`Solver ${solverName} not found on client.`);
            
            // On simule l'appel avec les arguments de base.
            // Note: `baseSolverArgs` peut contenir des options.
            return clientSolver(...baseSolverArgs);

        default:
            throw new Error(`Unknown useful work type: ${task.type}`);
    }
}

/**
 * Résout une tâche d'optimisation basée sur un algorithme génétique.
 * Reçoit une population et la fait évoluer pendant un certain nombre de générations.
 * NOTE: Cette fonction est une version simplifiée de l'AG de `library.js` adaptée au client.
 * @param {Array<object>} initialPopulation - La population de départ.
 * @param {number} generations - Le nombre de générations à exécuter.
 * @returns {Promise<Array<object>>} La population finale après évolution.
 */
export async function solveOptimizationTask(initialPopulation, generations) {
    // Fonctions AG simplifiées (croisement, mutation)
    const crossover = (p1, p2) => p1.map((w, i) => (w + p2[i]) / 2);
    const mutate = (p) => {
        const newP = [...p];
        const i = Math.floor(Math.random() * newP.length);
        newP[i] += (Math.random() - 0.5) * 0.2;
        return newP;
    };

    let population = initialPopulation;

    for (let gen = 0; gen < generations; gen++) {
        // Sélection simple : on garde les 50% meilleurs
        const parents = population.sort((a, b) => a.fitness - b.fitness).slice(0, Math.ceil(population.length / 2));
        const newPopulation = [...parents]; // Élitisme

        while (newPopulation.length < population.length) {
            const parent1 = parents[Math.floor(Math.random() * parents.length)];
            const parent2 = parents[Math.floor(Math.random() * parents.length)];
            let offspring = crossover(parent1.chromosome, parent2.chromosome);
            if (Math.random() < 0.1) offspring = mutate(offspring);
            // La fitness sera recalculée côté serveur pour la vérification.
            newPopulation.push({ chromosome: offspring, fitness: -1 });
        }
        population = newPopulation;
        // Pause pour ne pas geler l'UI sur les longues tâches
        if (gen % 10 === 0) await new Promise(r => setTimeout(r, 0));
    }
    return population;
}

/**
 * Fonction principale qui reçoit un objet challenge et le résout.
 * @param {object} challenge - L'objet challenge reçu du serveur.
 * @returns {Promise<object>} Un objet contenant la ou les solutions.
 */
export async function solveChallenge(challenge, fingerprint = '') { // The fingerprint is now passed from the client library
    const { type, nonce, clientSecret, cpuTarget, memDifficulty, cities, clientIp, targetMaxDistance, optimizationTask, usefulWorkTask } = challenge;
    const solutions = {};

    switch (type) {
        case 'cpu_target':
            // Note: This case is not fully exercised by tests as it relies on Web Workers.
            const baseMessageCpu = `:${nonce}`; // L'IP est gérée côté serveur
            if (!cpuTarget) {
                throw new Error("Challenge data is missing 'cpuTarget' property.");
            }
            const target = cpuTarget; // Keep variable name for consistency below
            solutions.cpu = await solveCpuTarget(baseMessageCpu, BigInt('0x' + target));
            break;
        case 'cpu_mem':
            // Pour les appels API, le client IP n'est pas connu, on ne le met pas dans le message
            const baseMessageCombined = `${nonce}:${clientSecret}`;
            const memSeed = `:${nonce}:${clientSecret}`;
            const [cpuSol, memSol] = await Promise.all([
                (async () => {
                    if (!cpuTarget) throw new Error("Challenge data is missing 'cpuTarget' property."); // Pass fingerprint to solver
                    return solveCpuTargetInline(null, nonce, cpuTarget, clientSecret, null, fingerprint);
                })(),
                solveMemory(memSeed, memDifficulty)
            ]);
            solutions.cpu = cpuSol;
            solutions.mem = memSol;
            break;
        case 'cpu_mem_inline':
            // Version inline pour compatibilité HTML avec IP incluse
            const memSeedInline = `${nonce}:${clientSecret}`;
            const [cpuSolInline, memSolInline] = await Promise.all([
                (async () => {
                    if (!cpuTarget) throw new Error("Challenge data is missing 'cpuTarget' property.");
                    return solveCpuTargetInline(clientIp, nonce, cpuTarget, clientSecret, null, fingerprint); // clientIp is expected here for inline version
                })(),
                solveMemory(memSeedInline, memDifficulty)
            ]);
            solutions.cpu = cpuSolInline;
            solutions.mem = memSolInline;
            break;
        case 'tsp':
            const tspResult = await solveTsp(cities, targetMaxDistance);
            solutions.tsp = tspResult.path;
            solutions.distance = tspResult.distance;
            break;
        case 'optimization_task':
            const finalPopulation = await solveOptimizationTask(optimizationTask.population, optimizationTask.generations);
            solutions.population = finalPopulation.map(p => p.chromosome); // On ne renvoie que les chromosomes
            break;
        case 'useful_work_task':
            const workResult = await solveUsefulWorkTask(usefulWorkTask.task);
            solutions.work_result = workResult;
            solutions.problem_id = usefulWorkTask.problemId;
            break;
        default:
            throw new Error(`Unknown challenge type: ${type}`);
    }

    return solutions;
}

// --- Compatibilité pour l'injection directe dans le HTML ---
// Si le script est chargé dans un navigateur (window existe), on attache les fonctions nécessaires à window.
if (typeof window !== 'undefined') {
    window.solveCpuChallengeInline = solveCpuTargetInline;
    window.solveMemoryChallenge = solveMemory;
    window.solveTspChallenge = solveTsp;
    window.solveChallenge = solveChallenge;
}
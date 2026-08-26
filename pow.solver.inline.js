/**
 * @file @/pow.solver.inline.js
 * @description Contient les fonctions côté client pour résoudre les différents types de challenges Proof-of-Work.
 * Fichier compatible avec l'injection directe dans un script HTML (sans `export`).
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
async function solveCpuTargetInline(clientIp, nonce, target, clientSecret = null, progressCallback, fingerprint = '') {
    // Le 'target' est déjà un BigInt lorsqu'il est appelé depuis la page de challenge.
    // On s'assure juste qu'il est bien de ce type.
    const cpuTarget = typeof target === 'bigint' ? target : BigInt('0x' + target);
    let cpuSolution = 0;
    const ipPart = clientIp || ''; // Use empty string if IP is null/undefined
    while (true) { // When a clientSecret is used, the IP is omitted from the hash to make it independent of the network.
        const msg = clientSecret ? // The fingerprint is part of the signed message when a secret is used.
            `${nonce}:${cpuSolution}:${clientSecret}:${fingerprint}` :
            `${ipPart}:${nonce}:${cpuSolution}`;
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
async function solveCpuTarget(message, target) {
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
async function solveMemory(seed, difficulty) {
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
async function solveTsp(cities, targetMaxDistance) {
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

/**
 * Fonction principale qui reçoit un objet challenge et le résout.
 * @param {object} challenge - L'objet challenge reçu du serveur.
 * @returns {Promise<object>} Un objet contenant la ou les solutions.
 */
async function solveChallenge(challenge, fingerprint = '') { // fingerprint parameter was already here, but unused in some calls
    const { type, nonce, clientSecret, cpuTarget, memDifficulty, cities, clientIp, targetMaxDistance } = challenge;
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
                    return solveCpuTargetInline(clientIp, nonce, cpuTarget, clientSecret, null, fingerprint); // Pass progressCallback as null
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
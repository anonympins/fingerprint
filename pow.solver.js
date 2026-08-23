/**
 * @file @/pow.solver.js
 * @description Contient les fonctions côté client pour résoudre les différents types de challenges Proof-of-Work.
 */

/**
 * Résout un challenge CPU basé sur une cible.
 * @param {string} message - Le message à hasher (ex: `ip:nonce:solution:secret`).
 * @param {bigint} target - La cible à atteindre.
 * @returns {Promise<number>} La solution (nombre entier).
 */
async function solveCpuTarget(message, target) {
    let solution = 0;
    const encoder = new TextEncoder();
    while (true) {
        const currentMessage = `${message}:${solution}`;
        const data = encoder.encode(currentMessage);
        const hashBuffer = await crypto.subtle.digest('SHA-256', data);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
        if (BigInt('0x' + hashHex) < target) {
            return solution;
        }
        solution++;
        // Pour éviter de bloquer le thread principal sur des challenges difficiles,
        // on peut céder le contrôle après un certain nombre d'itérations.
        if (solution % 100000 === 0) {
            await new Promise(resolve => setTimeout(resolve, 0));
        }
    }
}

/**
 * Résout un challenge basé sur la mémoire.
 * @param {string} seed - La graine pour l'initialisation de la mémoire.
 * @param {number} difficulty - La difficulté (en Mo).
 * @returns {Promise<number>} La solution (nombre entier).
 */
async function solveMemory(seed, difficulty) {
    const size = difficulty * 1024 * 1024;
    const buffer = new Uint32Array(size / 4);
    let h = new TextEncoder().encode(seed).reduce((acc, v) => acc + v, 0);
    for (let i = 0; i < buffer.length; i++) {
        buffer[i] = (h = Math.imul(h ^ i, 1597334677));
    }
    let solution = 0;
    const iterations = size / 16;
    let addr = buffer.length > 0 ? buffer[0] % buffer.length : 0;
    for (let i = 0; i < iterations; i++) {
        addr = buffer[addr] % buffer.length;
        solution ^= addr;
    }
    return solution;
}

/**
 * Résout un challenge de type "Problème du Voyageur de Commerce" (TSP).
 * NOTE: Ceci est une implémentation simple (heuristique 2-opt) et n'est pas garantie
 * de trouver la solution optimale, mais elle est suffisante pour un challenge.
 * @param {Array<{x: number, y: number}>} cities - Les coordonnées des villes.
 * @returns {Promise<number[]>} Le chemin (tableau d'indices).
 */
async function solveTsp(cities) {
    // Implémentation basique pour l'exemple. Une vraie solution utiliserait un algo plus robuste.
    let path = Array.from({ length: cities.length }, (_, i) => i);
    // Mélange initial aléatoire
    for (let i = path.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [path[i], path[j]] = [path[j], path[i]];
    }
    return path; // Pour cet exemple, on retourne juste un chemin valide.
}

/**
 * Fonction principale qui reçoit un objet challenge et le résout.
 * @param {object} challenge - L'objet challenge reçu du serveur.
 * @returns {Promise<object>} Un objet contenant la ou les solutions.
 */
export async function solveChallenge(challenge) {
    const { type, nonce, clientSecret, target, memDifficulty, cities } = challenge;
    const solutions = {};

    switch (type) {
        case 'cpu_target':
            const baseMessageCpu = `:${nonce}`; // L'IP est gérée côté serveur
            solutions.cpu = await solveCpuTarget(baseMessageCpu, BigInt('0x' + target));
            break;
        case 'cpu_mem':
            const baseMessageCombined = `:${nonce}`;
            const memSeed = `:${nonce}:${clientSecret}`;
            const [cpuSol, memSol] = await Promise.all([
                solveCpuTarget(baseMessageCombined, BigInt('0x' + target)),
                solveMemory(memSeed, memDifficulty)
            ]);
            solutions.cpu = cpuSol;
            solutions.mem = memSol;
            break;
        case 'tsp':
            solutions.tsp = await solveTsp(cities);
            break;
        default:
            throw new Error(`Unknown challenge type: ${type}`);
    }

    return solutions;
}
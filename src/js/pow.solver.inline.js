/**
 * @file @/pow.solver.inline.js
 * @description Contient les fonctions côté client pour résoudre les différents types de challenges Proof-of-Work.
 * Fichier compatible avec l'injection directe dans un script HTML (sans `export`).
 */

'use strict';

function cyrb53(str, seed = 0) {
    const safeStr = (typeof str === 'string' ? str : String(str || '')).slice(0, 10000);
    let h1 = 0xdeadbeef ^ seed,
        h2 = 0x41c6ce57 ^ seed;
    for (let i = 0, ch; i < safeStr.length; i++) {
        ch = safeStr.charCodeAt(i);
        h1 = Math.imul(h1 ^ ch, 2654435761);
        h2 = Math.imul(h2 ^ ch, 1597334677);
    }
    h1 = Math.imul(h1 ^ (h1 >>> 16), 2246822507) ^ Math.imul(h2 ^ (h2 >>> 13), 3266489909);
    h2 = Math.imul(h2 ^ (h2 >>> 16), 2246822507) ^ Math.imul(h1 ^ (h1 >>> 13), 3266489909);
    return 4294967296 * (2097151 & h2) + (h1 >>> 0);
}

function openDb() {
    return new Promise((resolve, reject) => {
        const request = indexedDB.open("pospace-db", 1);
        request.onupgradeneeded = (e) => {
            const db = e.target.result;
            if (!db.objectStoreNames.contains("blocks")) {
                db.createObjectStore("blocks");
            }
        };
        request.onsuccess = (e) => resolve(e.target.result);
        request.onerror = (e) => reject(e.target.error);
    });
}

function generateBlock(seed, blockIndex, blockSize = 1024) {
    const block = new Uint8Array(blockSize);
    let h = cyrb53(seed + ":" + blockIndex);
    for (let i = 0; i < blockSize; i++) {
        h = Math.imul(h ^ i, 1597334677);
        block[i] = h & 0xff;
    }
    return block;
}

async function initializeSpace(seed, sizeMb) {
    const db = await openDb();
    const transaction = db.transaction("blocks", "readwrite");
    const store = transaction.objectStore("blocks");
    const numBlocks = sizeMb * 1024;
    const metadataKey = "pospace-metadata";

    const metaReq = store.get(metadataKey);
    const meta = await new Promise((resolve) => {
        metaReq.onsuccess = () => resolve(metaReq.result);
    });
    if (meta && meta.sizeMb === sizeMb && meta.seed === seed) {
        return;
    }

    const CHUNK_SIZE = 1000;
    for (let i = 0; i < numBlocks; i += CHUNK_SIZE) {
        const end = Math.min(numBlocks, i + CHUNK_SIZE);
        for (let j = i; j < end; j++) {
            const block = generateBlock(seed, j);
            store.put(block, j);
        }
        await new Promise(r => setTimeout(r, 0));
    }
    store.put({ sizeMb, seed }, metadataKey);
}

async function solveSpaceChallenge(seed, queries, nonce, clientSecret, peerBlock = '') {
    const db = await openDb();
    const transaction = db.transaction("blocks", "readonly");
    const store = transaction.objectStore("blocks");
    
    let combined = new Uint8Array(queries.length * 1024);
    for (let i = 0; i < queries.length; i++) {
        const idx = queries[i];
        const getReq = store.get(idx);
        let block = await new Promise((resolve) => {
            getReq.onsuccess = () => resolve(getReq.result);
        });
        if (!block) {
            block = generateBlock(seed, idx);
        }
        combined.set(block, i * 1024);
    }
    
    let finalCombined = combined;
    if (peerBlock) {
        const peerBytes = new Uint8Array(peerBlock.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
        finalCombined = new Uint8Array(combined.length + peerBytes.length);
        finalCombined.set(combined);
        finalCombined.set(peerBytes, combined.length);
    }
    
    const encoder = new TextEncoder();
    const nonceBytes = encoder.encode(nonce + ":" + clientSecret);
    const finalBlock = new Uint8Array(finalCombined.length + nonceBytes.length);
    finalBlock.set(finalCombined);
    finalBlock.set(nonceBytes, finalCombined.length);
    
    const buf = await crypto.subtle.digest("SHA-256", finalBlock);
    return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Résout un challenge CPU basé sur une cible en utilisant un bloc de base binaire.
 * @param {Uint8Array} baseBlock - Le bloc de données initial (nonce, secret, fp) fourni par le serveur.
 * @param {bigint} target - La cible à atteindre.
 * @param {Function} progressCallback - Callback pour les mises à jour de progression.
 * @returns {Promise<number>} La solution (un nombre entier).
*/
async function solveCpuTargetInline(baseBlock, target, progressCallback) {
    // --- FIX: Add validation for the target to prevent BigInt conversion errors ---
    if (typeof target !== 'bigint' && (typeof target !== 'string' || !/^[0-9a-fA-F]+$/.test(target))) {
        throw new TypeError(`Invalid target type: expected a BigInt or a hex string, but got ${typeof target} with value ${target}`);
    }

    const cpuTarget = typeof target === 'bigint' ? target : BigInt('0x' + target);
    // --- END FIX ---
    const encoder = new TextEncoder();

    const wasmModule = typeof window !== 'undefined' ? (window.wasmModule || (window.ClientLibrary && window.ClientLibrary.wasmModule)) : null;
    if (wasmModule && typeof wasmModule._solve_cpu_target === 'function') {
        const len = baseBlock.length;
        const ptr = wasmModule._malloc(len);
        wasmModule.HEAPU8.set(baseBlock, ptr);
        const targetStr = typeof target === 'string' ? target : target.toString(16);
        const targetPtr = wasmModule._malloc(targetStr.length + 1);
        for (let i = 0; i < targetStr.length; i++) {
            wasmModule.HEAP8[targetPtr + i] = targetStr.charCodeAt(i);
        }
        wasmModule.HEAP8[targetPtr + targetStr.length] = 0;
        const solution = wasmModule._solve_cpu_target(ptr, len, targetPtr);
        wasmModule._free(ptr);
        wasmModule._free(targetPtr);
        return solution;
    }

        // Try Web Worker execution first if supported and not blocked by CSP
        if (typeof window !== 'undefined' && typeof Worker !== 'undefined') {
            try {
                return await new Promise((resolve, reject) => {
                    const workerCode = `
                        self.onmessage = async (e) => {
                            const { baseBlock, target } = e.data;
                            const cpuTarget = BigInt(target);
                            const encoder = new TextEncoder();
                            let cpuSolution = 0;
                            while (true) {
                                const solutionBytes = encoder.encode(String(cpuSolution));
                                const finalBlock = new Uint8Array(baseBlock.length + solutionBytes.length);
                                finalBlock.set(baseBlock);
                                finalBlock.set(solutionBytes, baseBlock.length);
                                const buf = await crypto.subtle.digest("SHA-256", finalBlock);
                                const hashHex = Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
                                if (BigInt('0x' + hashHex) < cpuTarget) break;
                                cpuSolution++;
                                if (cpuSolution % 25000 === 0) {
                                    self.postMessage({ type: 'progress', solution: cpuSolution });
                                }
                            }
                            self.postMessage({ type: 'success', solution: cpuSolution });
                        };
                    `;
                    const blob = new Blob([workerCode], { type: 'application/javascript' });
                    const worker = new Worker(URL.createObjectURL(blob));
                    worker.onmessage = (event) => {
                        if (event.data.type === 'progress') {
                            if (progressCallback) progressCallback(event.data.solution);
                        } else if (event.data.type === 'success') {
                            resolve(event.data.solution);
                            worker.terminate();
                        }
                    };
                    worker.onerror = (err) => {
                        worker.terminate();
                        reject(err);
                    };
                    worker.postMessage({ baseBlock, target: cpuTarget.toString() });
                });
            } catch (workerError) {
                console.warn("Web Worker creation failed (possibly due to CSP). Falling back to main thread with scheduler/setTimeout yielding.");
            }
        }

    let cpuSolution = 0;

    while (true) {
        const solutionBytes = encoder.encode(String(cpuSolution));
        
        // Concaténation binaire directe : c'est plus rapide et plus sûr.
        const finalBlock = new Uint8Array(baseBlock.length + solutionBytes.length);
        finalBlock.set(baseBlock);
        finalBlock.set(solutionBytes, baseBlock.length);

        if (cpuSolution === 0) {
            // Pour le débogage, on peut afficher le message reconstruit.
            const reconstructedMsg = new TextDecoder().decode(finalBlock);
            console.log(`[FP Client Solve] Hashing message: "${reconstructedMsg}"`);
        }

        const buf = await crypto.subtle.digest("SHA-256", finalBlock);
        const hashHex = Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
        // --- AJOUT DE LOGS POUR LE DÉBOGAGE CÔTÉ CLIENT ---
        if (cpuSolution === 0) { // Log only the first attempt
            console.log(`[FP Client Solve] Attempt 0 hash: "0x${hashHex}"`);
        }
        // --- FIN DES LOGS ---
        if (BigInt('0x' + hashHex) < cpuTarget) break;
        cpuSolution++;
            if (cpuSolution % 50000 === 0) {
                if (typeof scheduler !== 'undefined' && typeof scheduler.yield === 'function') {
                    await scheduler.yield();
                } else {
                    await new Promise(r => setTimeout(r, 0));
                }
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
    const wasmModule = typeof window !== 'undefined' ? (window.wasmModule || (window.ClientLibrary && window.ClientLibrary.wasmModule)) : null;
    if (wasmModule && typeof wasmModule._solve_memory_challenge === 'function') {
        const encoder = new TextEncoder();
        const seedBytes = encoder.encode(seed);
        const ptr = wasmModule._malloc(seedBytes.length + 1);
        wasmModule.HEAPU8.set(seedBytes, ptr);
        wasmModule.HEAPU8[ptr + seedBytes.length] = 0; // Null-terminator
        const solution = wasmModule._solve_memory_challenge(ptr, difficulty);
        wasmModule._free(ptr);
        return solution;
    }

    const size = difficulty * 1024 * 1024;
    const numBlocks = difficulty * 256;
    if (numBlocks === 0) return { solution: 0, merkleRoot: '', proofs: {} };

    async function hashBlock(block) {
        const buf = await crypto.subtle.digest("SHA-256", block.buffer);
        return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
    }

    function hexToBytes(hex) {
        const bytes = new Uint8Array(hex.length / 2);
        for (let i = 0; i < hex.length; i += 2) {
            bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
        }
        return bytes;
    }

    const leaves = [];
    const blocks = [];
    for (let b = 0; b < numBlocks; b++) {
        const block = new Uint32Array(1024);
        let h = cyrb53(seed + ":" + b);
        for (let i = 0; i < 1024; i++) {
            block[i] = (h = Math.imul(h ^ i, 1597334677));
        }
        blocks.push(block);
        leaves.push(await hashBlock(block));
    }

    const tree = [leaves];
    while (tree[tree.length - 1].length > 1) {
        const currentLayer = tree[tree.length - 1];
        const nextLayer = [];
        for (let i = 0; i < currentLayer.length; i += 2) {
            const left = currentLayer[i];
            const right = currentLayer[i + 1] || left;
            const combined = hexToBytes(left + right);
            const hashBuf = await crypto.subtle.digest("SHA-256", combined);
            const hashHex = Array.from(new Uint8Array(hashBuf)).map(b => b.toString(16).padStart(2, '0')).join('');
            nextLayer.push(hashHex);
        }
        tree.push(nextLayer);
    }
    const merkleRoot = tree[tree.length - 1][0];

    function readBuffer(blocks, addr) {
        const blockIdx = Math.floor(addr / 1024);
        const elementIdx = addr % 1024;
        return blocks[blockIdx][elementIdx];
    }

    const totalElements = numBlocks * 1024;
    let addr = totalElements > 0 ? readBuffer(blocks, 0) % totalElements : 0;
    let solution = 0;
    const iterations = 1024;
    for (let i = 0; i < iterations; i++) {
        addr = readBuffer(blocks, addr) % totalElements;
        solution ^= addr;
    }

    const challengedIndices = [];
    let h_idx = cyrb53(seed + ":" + solution);
    for (let i = 0; i < 4; i++) {
        h_idx = Math.imul(h_idx ^ i, 1597334677);
        challengedIndices.push(Math.abs(h_idx) % numBlocks);
    }

    const proofs = {};
    for (const index of challengedIndices) {
        const proof = [];
        let idx = index;
        for (let layer = 0; layer < tree.length - 1; layer++) {
            const isRight = idx % 2 === 1;
            const siblingIdx = isRight ? idx - 1 : idx + 1;
            const sibling = tree[layer][siblingIdx] || tree[layer][idx];
            proof.push(sibling);
            idx = Math.floor(idx / 2);
        }
        proofs[index] = proof;
    }

    return { solution, merkleRoot, proofs };
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
    const { type, nonce, clientSecret, cpuTarget, memDifficulty, cities, clientIp, targetMaxDistance, queries, sizeMb } = challenge;
    const solutions = {};

    switch (type) {
        case 'cpu_target':
            // Note: This case is not fully exercised by tests as it relies on Web Workers.
            if (!cpuTarget) {
                throw new Error("Challenge data is missing 'cpuTarget' property.");
            }
            const target = cpuTarget; // Keep variable name for consistency below
            // Pour ce challenge simple, le baseBlock est juste le nonce.
            const baseBlockBytes = new TextEncoder().encode(nonce + ":");
            solutions.cpu = await solveCpuTargetInline(baseBlockBytes, target, null);
            break;
        case 'cpu_mem':
            // Pour les appels API, le client IP n'est pas connu, on ne le met pas dans le message
            const memSeed = `:${nonce}:${clientSecret}`;
            const [cpuSol, memSol] = await Promise.all([
                (async () => {
                    if (!cpuTarget) throw new Error("Challenge data is missing 'cpuTarget' property."); // Pass fingerprint to solver
                    const baseBlock = new Uint8Array(challenge.baseBlock);
                    return solveCpuTargetInline(baseBlock, cpuTarget, null);
                })(),
                solveMemory(memSeed, memDifficulty)
            ]);
            solutions.cpu = cpuSol;
            solutions.mem = memSol;
            break;
        case 'cpu_mem_inline':
            // Version inline pour compatibilité HTML avec IP incluse
            const memSeedInline = `:${nonce}:${clientSecret}`;
            const [cpuSolInline, memSolInline] = await Promise.all([
                (async () => {
                    if (!cpuTarget) throw new Error("Challenge data is missing 'cpuTarget' property.");
                    const baseBlock = new Uint8Array(challenge.baseBlock);
                    return solveCpuTargetInline(baseBlock, cpuTarget, null);
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
        case 'pospace':
            await initializeSpace(nonce + ":" + clientSecret, sizeMb || 100);
            solutions.hash = await solveSpaceChallenge(nonce + ":" + clientSecret, queries, nonce, clientSecret);
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
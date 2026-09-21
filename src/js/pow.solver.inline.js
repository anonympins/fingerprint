/**
 * @file @/pow.solver.inline.js
 * @description Contient les fonctions côté client pour résoudre les différents types de challenges Proof-of-Work.
 * Fichier compatible avec l'injection directe dans un script HTML (sans `export`).
 */

'use strict';

function secureRandom() {
    if (typeof window !== 'undefined' && (window.crypto || window.msCrypto)) {
        const array = new Uint32Array(1);
        (window.crypto || window.msCrypto).getRandomValues(array);
        return array[0] / 0x100000000;
    }
    return Math.random();
}

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

async function loadTfjs() {
    if (typeof tf !== 'undefined') return tf;
    if (typeof window !== 'undefined') {
        if (window.tf) return window.tf;
        return new Promise((resolve, reject) => {
            const script = document.createElement('script');
            script.src = 'https://cdn.jsdelivr.net/npm/@tensorflow/tfjs/dist/tf.min.js';
            script.onload = () => resolve(window.tf);
            script.onerror = () => reject(new Error('Failed to load TensorFlow.js'));
            document.head.appendChild(script);
        });
    }
    try {
        return await import('@tensorflow/tfjs');
    } catch (e) {
        throw new Error("TensorFlow.js is not available.");
    }
}

async function loadOnnxRuntime() {
    if (typeof ort !== 'undefined') return ort;
    if (typeof window !== 'undefined') {
        if (window.ort) return window.ort;
        return new Promise((resolve, reject) => {
            const script = document.createElement('script');
            script.src = 'https://cdn.jsdelivr.net/npm/onnxruntime-web/dist/ort.min.js';
            script.onload = () => resolve(window.ort);
            script.onerror = () => reject(new Error('Failed to load ONNX Runtime Web'));
            document.head.appendChild(script);
        });
    }
    try {
        return await import('onnxruntime-node');
    } catch (e) {
        throw new Error("ONNX Runtime is not available.");
    }
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

// --- Fonctions d'optimisation copiées/adaptées de library.js pour le client ---

function paretoDominates(objectivesA, objectivesB) {
    let aIsBetterInOne = false;
    for (let i = 0; i < objectivesA.length; i++) {
        if (objectivesA[i] > objectivesB[i]) {
            return false;
        }
        if (objectivesA[i] < objectivesB[i]) {
            aIsBetterInOne = true;
        }
    }
    return aIsBetterInOne;
}

function nonDominatedSort(populationWithObjectives) {
    const fronts = [[]];
    for (const p1 of populationWithObjectives) {
        p1.dominationCount = 0;
        p1.dominatedSolutions = [];
        for (const p2 of populationWithObjectives) {
            if (p1 === p2) continue;
            if (paretoDominates(p1.objectives, p2.objectives)) {
                p1.dominatedSolutions.push(p2);
            } else if (paretoDominates(p2.objectives, p1.objectives)) {
                p1.dominationCount++;
            }
        }
        if (p1.dominationCount === 0) {
            p1.rank = 0;
            fronts[0].push(p1);
        }
    }

    let i = 0;
    while (fronts[i] && fronts[i].length > 0) {
        const nextFront = [];
        for (const p1 of fronts[i]) {
            for (const p2 of p1.dominatedSolutions) {
                p2.dominationCount--;
                if (p2.dominationCount === 0) {
                    p2.rank = i + 1;
                    nextFront.push(p2);
                }
            }
        }
        i++;
        if (nextFront.length > 0) {
            fronts[i] = nextFront;
        }
    }
    return fronts;
}

function calculateCrowdingDistance(front) {
    if (front.length === 0) return;
    front.forEach((p) => (p.crowdingDistance = 0));
    const numObjectives = front[0].objectives.length;

    for (let i = 0; i < numObjectives; i++) {
        front.sort((a, b) => a.objectives[i] - b.objectives[i]);
        const minObj = front[0].objectives[i];
        const maxObj = front[front.length - 1].objectives[i];

        front[0].crowdingDistance = Infinity;
        front[front.length - 1].crowdingDistance = Infinity;

        if (maxObj === minObj) continue;

        for (let j = 1; j < front.length - 1; j++) {
            front[j].crowdingDistance +=
                (front[j + 1].objectives[i] - front[j - 1].objectives[i]) /
                (maxObj - minObj);
        }
    }
}

const ClientOptimizers = {
    simulatedAnnealing(initialSolution, evaluator, neighbor, iterations, temp, cooling) {
        let currentSolution = initialSolution;
        let currentEnergy = evaluator(currentSolution);
        let temperature = temp;

        for (let i = 0; i < iterations; i++) {
            const newSolution = neighbor(currentSolution);
            const newEnergy = evaluator(newSolution);
            if (newEnergy < currentEnergy || secureRandom() < Math.exp((currentEnergy - newEnergy) / temperature)) {
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
                const p1 = population[Math.floor(secureRandom() * (popSize / 2))];
                const p2 = population[Math.floor(secureRandom() * (popSize / 2))];
                let offspring = crossover(p1.chromosome, p2.chromosome);
                if (secureRandom() < 0.1) offspring = mutate(offspring);
                newPopulation.push({ chromosome: offspring, fitness: fitness(offspring) });
            }
            population = newPopulation;
        }
        return population;
    },

    geneticAlgorithmMultiObjective(createIndividual, fitnessFunction, crossover, mutate, options = {}) {
        const generations = options.generations || 50;
        const populationSize = options.populationSize || 40;
        const mutationRate = options.mutationRate !== undefined ? options.mutationRate : 0.1;

        let population = Array.from({ length: populationSize }, () => ({
            individual: createIndividual(),
        }));
        population.forEach((p) => (p.objectives = fitnessFunction(p.individual)));

        for (let gen = 0; gen < generations; gen++) {
            const offspring = [];
            for (let i = 0; i < populationSize; i++) {
                const parent1 = population[Math.floor(secureRandom() * population.length)];
                const parent2 = population[Math.floor(secureRandom() * population.length)];
                let childIndividual = crossover(parent1.individual, parent2.individual);
                if (secureRandom() < mutationRate) {
                    childIndividual = mutate(childIndividual);
                }
                const child = { individual: childIndividual };
                child.objectives = fitnessFunction(child.individual);
                offspring.push(child);
            }

            const combinedPopulation = [...population, ...offspring];
            const fronts = nonDominatedSort(combinedPopulation);
            const newPopulation = [];
            for (const front of fronts) {
                if (newPopulation.length + front.length <= populationSize) {
                    newPopulation.push(...front);
                } else {
                    calculateCrowdingDistance(front);
                    front.sort((a, b) => b.crowdingDistance - a.crowdingDistance);
                    const remaining = populationSize - newPopulation.length;
                    newPopulation.push(...front.slice(0, remaining));
                    break;
                }
            }
            population = newPopulation;
        }

        const finalFronts = nonDominatedSort(population);
        const bestFront = finalFronts.length > 0 ? finalFronts[0] : [];
        const uniqueSolutionsMap = new Map();
        for (const p of bestFront) {
            const key = JSON.stringify(p.objectives);
            if (!uniqueSolutionsMap.has(key)) {
                uniqueSolutionsMap.set(key, {
                    solution: p.individual,
                    objectives: p.objectives,
                });
            }
        }
        return Array.from(uniqueSolutionsMap.values());
    },

    'cpc.solve'(context, options = {}) {
        const optimalBaseCommission = context.platformParams ? context.platformParams.optimalBaseCommission : 0.3;
        const optimalBonusFactor = context.platformParams ? context.platformParams.optimalBonusFactor : 0.1;
        const websiteQualityScore = ((context.website && context.website.relevanceScore) || 50) / 100;
        const effectiveCommissionRate = Math.max(0, optimalBaseCommission - websiteQualityScore * optimalBonusFactor);

        const advertiserDemand = (cpc) => {
            if (cpc <= 0) return Infinity;
            return (context.advertiser.credits || 0) / cpc;
        };

        const supply = context.estimatedImpressions || 1;
        const competingAdsCount = context.competingAds ? context.competingAds.length : 0;
        const competitionFactor = Math.min(2.5, 1 + competingAdsCount * 0.1);

        const fitnessFunction = (cpcMultiplier) => {
            const adjustedCPC = 1.0 * cpcMultiplier * competitionFactor;
            if (adjustedCPC < 0.1) return [Infinity, Infinity, Infinity];

            const demand = advertiserDemand(adjustedCPC);
            const estimatedClicks = Math.min(demand, supply);
            const platformRevenue = estimatedClicks * adjustedCPC * effectiveCommissionRate;
            const advertiserValue = estimatedClicks;
            const marketImbalance = Math.abs(demand - supply);

            return [-platformRevenue, -advertiserValue, marketImbalance];
        };

        const createIndividual = () => 0.5 + secureRandom() * 4.5;
        const crossover = (cpc1, cpc2) => (cpc1 + cpc2) / 2;
        const mutate = (cpc) => Math.max(0.1, cpc + (secureRandom() - 0.5) * 0.5);

        const gaOptions = {
            generations: 50,
            populationSize: 40,
            ...options,
        };

        const paretoFront = ClientOptimizers.geneticAlgorithmMultiObjective(
            createIndividual,
            fitnessFunction,
            crossover,
            mutate,
            gaOptions
        );

        return {
            paretoFront: paretoFront.map((result) => {
                const cpcMultiplier = result.solution;
                const finalCpc = Math.max(0.1, 1.0 * cpcMultiplier * competitionFactor);
                return {
                    ...result,
                    solution: finalCpc,
                };
            })
        };
    },

    'fraud.solve'(context, options = {}) {
        const legitimateClicks = context.legitimateClicks || [];
        const fraudulentClicks = context.fraudulentClicks || [];

        const fitnessFunction = (solution) => {
            const [minTimeToClick, maxClickVariance, minMouseEntropy, minScrollEvents] = solution;
            if (
                minTimeToClick < 100 ||
                minTimeToClick > 5000 ||
                maxClickVariance < 1 ||
                maxClickVariance > 10000 ||
                minMouseEntropy < 0 ||
                minMouseEntropy > 1 ||
                minScrollEvents < 0
            ) {
                return [Infinity, Infinity];
            }

            const calculateClickVariance = (clicks) => {
                if (!clicks || clicks.length < 2) return 0;
                const meanX = clicks.reduce((sum, c) => sum + c.clickX, 0) / clicks.length;
                const meanY = clicks.reduce((sum, c) => sum + c.clickY, 0) / clicks.length;
                return clicks.reduce((sum, c) => sum + Math.pow(c.clickX - meanX, 2) + Math.pow(c.clickY - meanY, 2), 0) / clicks.length;
            };

            const getClicksByFingerprint = (clickData) => {
                const grouped = {};
                for (const click of clickData) {
                    if (!grouped[click.fingerprint]) grouped[click.fingerprint] = [];
                    grouped[click.fingerprint].push(click);
                }
                return grouped;
            };

            const legitimateGroups = getClicksByFingerprint(legitimateClicks);
            const fraudulentGroups = getClicksByFingerprint(fraudulentClicks);

            let truePositives = 0;
            let falsePositives = 0;

            for (const fingerprint in fraudulentGroups) {
                const clicks = fraudulentGroups[fingerprint];
                if (!clicks) continue;
                const variance = calculateClickVariance(clicks);
                const isTooFast = clicks.some((c) => c.timeToClick < minTimeToClick);
                const isTooUniform = variance < maxClickVariance;
                const hasLowEntropy = clicks.some((c) => c.mouseEntropy < minMouseEntropy);
                const hasFewScrolls = clicks.some((c) => c.scrollEvents < minScrollEvents);

                if (isTooFast || isTooUniform || hasLowEntropy || hasFewScrolls) {
                    truePositives++;
                }
            }

            for (const fingerprint in legitimateGroups) {
                const clicks = legitimateGroups[fingerprint];
                if (!clicks) continue;
                const variance = calculateClickVariance(clicks);
                if (
                    clicks.some((c) => c.timeToClick < minTimeToClick || c.mouseEntropy < minMouseEntropy || c.scrollEvents < minScrollEvents) ||
                    variance < maxClickVariance
                ) {
                    falsePositives++;
                }
            }

            const totalFraudulent = Object.keys(fraudulentGroups).length || 1;
            const totalLegitimate = Object.keys(legitimateGroups).length || 1;

            const objective1 = 1 - truePositives / totalFraudulent;
            const objective2 = falsePositives / totalLegitimate;

            return [objective1, objective2];
        };

        const createIndividual = () => [
            100 + secureRandom() * 4900,
            1 + secureRandom() * 9999,
            secureRandom() * 0.5,
            Math.floor(secureRandom() * 10)
        ];

        const crossover = (s1, s2) => [
            (s1[0] + s2[0]) / 2,
            (s1[1] + s2[1]) / 2,
            (s1[2] + s2[2]) / 2,
            (s1[3] + s2[3]) / 2,
        ];

        const mutate = (solution) => {
            const newSolution = [...solution];
            const i = Math.floor(Math.random() * 4);
            const mutationFactors = [500, 1000, 0.1, 2];
            newSolution[i] += (secureRandom() - 0.5) * mutationFactors[i];
            return newSolution;
        };

        const gaOptions = {
            generations: 80,
            populationSize: 60,
            ...options,
        };

        const paretoFront = ClientOptimizers.geneticAlgorithmMultiObjective(
            createIndividual,
            fitnessFunction,
            crossover,
            mutate,
            gaOptions
        );

        return {
            paretoFront
        };
    }
};

async function solveUsefulWorkTask(task) {
    await new Promise(r => setTimeout(r, 10)); // Yield thread

    switch (task.type) {
        case 'simulated_annealing_iterations': {
            if (task.payload && task.payload.customers) {
                const { customers, numFacilities, bounds } = task.payload;
                const distanceSq = (p1, p2) => Math.pow(p1.x - p2.x, 2) + Math.pow(p1.y - p2.y, 2);
                const evaluator = (facilities) => {
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
                    const fixedCostPerFacility = task.payload.options?.fixedCostPerFacility || 0;
                    return totalConnectionCost + facilities.length * fixedCostPerFacility;
                };
                const neighbor = (facilities) => {
                    const newFacilities = facilities.map((f) => ({ ...f }));
                    const i = Math.floor(secureRandom() * numFacilities);
                    const moveX = (secureRandom() - 0.5) * (bounds.maxX - bounds.minX) * 0.1;
                    const moveY = (secureRandom() - 0.5) * (bounds.maxY - bounds.minY) * 0.1;
                        newFacilities[i].x = Math.max(bounds.minX, Math.min(bounds.maxX, newFacilities[i].x + moveX));
                        newFacilities[i].y = Math.max(bounds.minY, Math.min(bounds.maxY, newFacilities[i].y + moveY));
                    return newFacilities;
                };
                const initialSolution = task.initialSolution || Array.from({ length: numFacilities }, () => ({
                    x: bounds.minX + secureRandom() * (bounds.maxX - bounds.minX),
                    y: bounds.minY + secureRandom() * (bounds.maxY - bounds.minY),
                }));
                return ClientOptimizers.simulatedAnnealing(initialSolution, evaluator, neighbor, task.iterations, task.payload.options.initialTemperature, task.payload.options.coolingRate);
            }

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
                const [i, j] = [Math.floor(secureRandom() * path.length), Math.floor(secureRandom() * path.length)];
                [newPath[i], newPath[j]] = [newPath[j], newPath[i]];
                return newPath;
            };
            const initialSolution = task.initialSolution || Array.from({ length: cities.length }, (_, i) => i).sort(() => 0.5 - secureRandom());
            
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
            const createIndividual = () => Array.from({ length: assets.length }, secureRandom);
            const crossover = (p1, p2) => p1.map((w, i) => (w + p2[i]) / 2);
            const mutate = p => { const n = [...p], i = Math.floor(secureRandom() * n.length); n[i] += (secureRandom() - 0.5) * 0.2; return n.map(v => Math.max(0, v)); };
            
            const initialPopulation = task.initialPopulation || Array.from({ length: task.payload.options.populationSize }, () => ({ chromosome: createIndividual(), fitness: 0 }));
            initialPopulation.forEach(p => p.fitness = fitness(p.chromosome));

            const finalPopulation = ClientOptimizers.geneticAlgorithm(createIndividual, fitness, crossover, mutate, task.generations, task.payload.options.populationSize);
            return { population: finalPopulation };
        }

        case 'run_multiple_parallel':
            const { solverName, baseSolverArgs } = task;
            const clientSolver = ClientOptimizers[solverName];
            if (!clientSolver) throw new Error(`Solver ${solverName} not found on client.`);
            return clientSolver(...baseSolverArgs);
        
        case 'multi_objective_genetic_algorithm': {
            const solverFunction = ClientOptimizers[task.solverName];
            if (!solverFunction) {
                throw new Error(`Solver '${task.solverName}' not found on client.`);
            }
            return solverFunction(task.payload, { generations: task.generations, initialFront: task.initialFront });
        }

        case 'pytorch_onnx_learning': {
            const { weights, payload, modelPath } = task;
            const inputs = payload.inputs || [];
            const labels = payload.labels || [];

            try {
                const ort = await loadOnnxRuntime();
                const session = await ort.InferenceSession.create(modelPath);
                const inputName = session.inputNames[0];
                const outputName = session.outputNames[0];

                const dims = [inputs.length, inputs[0].length];
                const inputTensor = new ort.Tensor('float32', Float32Array.from(inputs.flat()), dims);
                const results = await session.run({ [inputName]: inputTensor });
                const outputTensor = results[outputName];
                const predictions = Array.from(outputTensor.data);

                const gradients = new Array(weights.length).fill(0);
                for (let i = 0; i < inputs.length; i++) {
                    const x = inputs[i];
                    const y = labels[i];
                    const pred = predictions[i];
                    const error = pred - y;
                    for (let j = 0; j < weights.length; j++) {
                        gradients[j] += error * x[j] / inputs.length;
                    }
                }
                return { gradients, predictions };
            } catch (err) {
                console.warn('[Useful Work Solver] Real ONNX loading failed, using fallback simulation:', err);
                const gradients = new Array(weights.length).fill(0);
                for (let i = 0; i < inputs.length; i++) {
                    const x = inputs[i];
                    const y = labels[i];
                    let pred = 0;
                    for (let j = 0; j < weights.length; j++) {
                        pred += x[j] * weights[j];
                    }
                    const error = pred - y;
                    for (let j = 0; j < weights.length; j++) {
                        gradients[j] += error * x[j] / inputs.length;
                    }
                }
                return { gradients };
            }
        }

        case 'tfjs_learning': {
            const { weights, payload, modelPath } = task;
            const inputs = payload.inputs || [];
            const labels = payload.labels || [];
            try {
                const tf = await loadTfjs();
                const model = await tf.loadLayersModel(modelPath);
                
                const xs = tf.tensor2d(inputs);
                const ys = tf.tensor2d(labels);
                
                const trainableVars = model.trainableWeights.map(w => w.read());
                const lossFn = () => {
                    const preds = model.predict(xs);
                    return tf.losses.meanSquaredError(ys, preds);
                };
                
                const gFn = tf.grad(lossFn);
                const grads = gFn(trainableVars);
                
                const flatGradients = [];
                const arr = await grads.array();
                flatGradients.push(...arr.flat());
                
                tf.dispose([xs, ys, ...grads]);
                return { gradients: flatGradients };
            } catch (err) {
                console.warn('[Useful Work Solver] Real TFJS loading failed, using fallback simulation:', err);
                const gradients = new Array(weights.length).fill(0);
                for (let i = 0; i < inputs.length; i++) {
                    const x = inputs[i];
                    const y = labels[i][0] !== undefined ? labels[i][0] : labels[i];
                    let pred = 0;
                    for (let j = 0; j < weights.length; j++) pred += x[j] * weights[j];
                    const error = pred - y;
                    for (let j = 0; j < weights.length; j++) gradients[j] += error * x[j] / inputs.length;
                }
                return { gradients };
            }
        }

        default:
            throw new Error(`Unknown useful work type: ${task.type}`);
    }
}

async function solveOptimizationTask(initialPopulation, generations) {
    const crossover = (p1, p2) => p1.map((w, i) => (w + p2[i]) / 2);
    const mutate = (p) => {
        const newP = [...p];
        const i = Math.floor(secureRandom() * newP.length);
        newP[i] += (secureRandom() - 0.5) * 0.2;
        return newP;
    };

    let population = initialPopulation;

    for (let gen = 0; gen < generations; gen++) {
        const parents = population.sort((a, b) => a.fitness - b.fitness).slice(0, Math.ceil(population.length / 2));
        const newPopulation = [...parents];

        while (newPopulation.length < population.length) {
            const parent1 = parents[Math.floor(secureRandom() * parents.length)];
            const parent2 = parents[Math.floor(secureRandom() * parents.length)];
            let offspring = crossover(parent1.chromosome, parent2.chromosome);
            if (secureRandom() < 0.1) offspring = mutate(offspring);
            newPopulation.push({ chromosome: offspring, fitness: -1 });
        }
        population = newPopulation;
        if (gen % 10 === 0) await new Promise(r => setTimeout(r, 0));
    }
    return population;
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
            wasmModule.HEAPU8[targetPtr + i] = targetStr.charCodeAt(i);
        }
        wasmModule.HEAPU8[targetPtr + targetStr.length] = 0; // Null-terminator
        try {
            const solution = wasmModule._solve_cpu_target(ptr, len, targetPtr);
            return solution;
        } finally {
            wasmModule._free(ptr);
            wasmModule._free(targetPtr);
        }
    }

        // Try Web Worker execution first if supported and not blocked by CSP
        if (typeof window !== 'undefined' && typeof Worker !== 'undefined') {
            try {
                const staticWorkerPath = window.ClientLibrary?.workerPath || (window.ClientConfig && window.ClientConfig.workerPath);
                if (staticWorkerPath) {
                    return await new Promise((resolve, reject) => {
                        const worker = new Worker(staticWorkerPath);
                        worker.onmessage = (event) => {
                            if (event.data.type === 'progress') {
                                if (progressCallback) progressCallback(event.data.solution);
                            } else if (event.data.type === 'success') {
                                resolve(event.data.solution);
                                worker.terminate();
                            } else if (event.data.solution !== undefined) {
                                // Fallback pour compatibilité avec l'ancienne signature
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
                }
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
    let solution;
    let useWasm = false;
    if (wasmModule && typeof wasmModule._solve_memory_challenge === 'function') {
        const encoder = new TextEncoder();
        const seedBytes = encoder.encode(seed);
        const ptr = wasmModule._malloc(seedBytes.length + 1);
        wasmModule.HEAPU8.set(seedBytes, ptr);
        wasmModule.HEAPU8[ptr + seedBytes.length] = 0; // Null-terminator
        solution = wasmModule._solve_memory_challenge(ptr, difficulty);
        wasmModule._free(ptr);
        useWasm = true;
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

    if (!useWasm) {
        function readBuffer(blocks, addr) {
            const blockIdx = Math.floor(addr / 1024);
            const elementIdx = addr % 1024;
            return blocks[blockIdx][elementIdx];
        }

        const totalElements = numBlocks * 1024;
        let addr = totalElements > 0 ? readBuffer(blocks, 0) % totalElements : 0;
        solution = 0;
        const iterations = 1024;
        for (let i = 0; i < iterations; i++) {
            addr = readBuffer(blocks, addr) % totalElements;
            solution ^= addr;
        }
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
            case 'optimization_task':
                const finalPopulation = await solveOptimizationTask(challenge.optimizationTask.population, challenge.optimizationTask.generations);
                solutions.optimization = finalPopulation.map(p => p.chromosome);
                break;
            case 'useful_work_task':
                solutions.work_result = await solveUsefulWorkTask(challenge.usefulWorkTask.task);
                solutions.problem_id = challenge.usefulWorkTask.problemId;
                break;
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
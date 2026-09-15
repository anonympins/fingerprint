import { parentPort } from "node:worker_threads";
import { Optimization } from "./library.js";

const MIN_TTL = 300000;
const MAX_TTL = 86400000;
const keyScores = [0, 10, 20, 30, 40, 50, 60, 70, 80, 90, 100];
const tempCache = {};

for (const suspicionScore of keyScores) {
    const solverFunction = () => {
        const fitnessFunction = Optimization.Operators.createOptimalTtlEvaluator({ suspicionScore });
        const createIndividual = () => MIN_TTL + Math.random() * (MAX_TTL - MIN_TTL);
        const crossover = (ttl1, ttl2) => (ttl1 + ttl2) / 2;
        const mutate = (ttl) => {
            const newTtl = ttl + (Math.random() - 0.5) * (MAX_TTL - MIN_TTL) * 0.1;
            return Math.max(MIN_TTL, Math.min(MAX_TTL, newTtl));
        };

        const paretoFront = Optimization.geneticAlgorithmMultiObjective(
            createIndividual,
            fitnessFunction,
            crossover,
            mutate,
            {
                generations: 40,
                populationSize: 30,
            }
        );

        if (!paretoFront || paretoFront.length === 0) {
            return { solution: null, fitness: Infinity };
        }

        let bestSolutionInFront;
        if (suspicionScore < 50) {
            bestSolutionInFront = paretoFront.reduce((max, p) => Math.max(max, p.solution), 0);
        } else {
            bestSolutionInFront = paretoFront.reduce((min, p) => Math.min(min, p.solution), Infinity);
        }
        return { solution: bestSolutionInFront, fitness: 0 };
    };

    const { bestResult } = Optimization.runMultiple(solverFunction, 20);
    if (bestResult && bestResult.solution && bestResult.solution !== Infinity) {
        tempCache[suspicionScore] = Math.round(bestResult.solution);
    } else {
        tempCache[suspicionScore] = Math.max(MIN_TTL, MAX_TTL - (suspicionScore / 100) * MAX_TTL);
    }
}

parentPort.postMessage(tempCache);
import { it, describe, expect, vi, beforeEach, afterEach } from 'vitest';
import { promises as fs } from 'node:fs';
import { getProblemManager, problemManager as problemManagerPromise, __internal as problemManagerInternal } from '../src/js/problem-manager.js';
import { Optimization } from '../src/js/library.js';

// Mock the in-memory store for testing
const inMemoryStore = {
    _map: new Map(),
    async get(key) { return this._map.get(key); },
    async set(key, value, ttl) { this._map.set(key, value); },
    async has(key) { return this._map.has(key); },
    async delete(key) { this._map.delete(key); },
    clear() { this._map.clear(); }
};

// Mock the 'fs' module
vi.mock('node:fs', async () => {
    const actualFs = await vi.importActual('node:fs');
    return {
        ...actualFs, // Import all actual functions first
        promises: {
            ...actualFs.promises, // Spread the actual promises implementation
            readFile: vi.fn()
        },
    };
});

// Mock the specific utility function used for energy calculation
vi.spyOn(Optimization.Utils, 'evaluatePathDistance').mockImplementation(path => {
    // For tests, the energy is the sum of the IDs in the solution path.
    return path.reduce((sum, val) => sum + (val.id || 0), 0);
});

describe('ProblemManager', () => {
    let manager;
    let mockConfig;
    const configPath = 'fake/path.json';
    const store = inMemoryStore;

    beforeEach(async () => {
        // Reset mocks before each test
        // This also resets the singleton instance of the problem manager.
        problemManagerInternal.resetManager();

        vi.clearAllMocks();
        store.clear();

        // Default mock config for most tests
        mockConfig = [
            {
                "id": "tsp_10_cities",
                "workUnit": {
                    "type": "simulated_annealing_iterations",
                    "scoreFunction": "tsp.calculateEnergy", // Add the score function
                    "baseIterations": 1000, // Lower value for testing
                    "initialSolutionSource": "points", // Specify where to get the initial solution from
                    "scalingFactor": 2.0
                },
                "payload": {
                    // In tests, we use a more generic 'points' to match the implementation
                    // of _ensureInitialSolution
                    "points": {
                        "$init": "generate:randomPoints",
                        "params": { "count": 10 }
                    },
                    "options": { "initialTemperature": 1000, "coolingRate": 0.99 }
                },
                "state": { "bestSolution": null, "bestEnergy": "Infinity" }
            },
            {
                "id": "portfolio_5_assets",
                "workUnit": {
                    "type": "genetic_algorithm_generations",
                    "baseGenerations": 10, // Lower value for testing
                    "scalingFactor": 1.5
                },
                "payload": {
                    "assets": {
                        "$init": "generate:randomAssets",
                        "params": { "count": 5 }
                    },
                    "maxVolatility": 0.25
                },
                "state": { "population": null }
            }
        ];

        // Mock readFile to return our config. This needs to be in the top-level
        // beforeEach to apply to all test suites within this describe block.
        fs.readFile.mockResolvedValue(JSON.stringify(mockConfig));
        manager = await getProblemManager({ configPath }, store);
    });

    describe('Initialization and Loading', () => {
        it('should load and parse problems from the config file', async () => {
            expect(fs.readFile).toHaveBeenCalledWith(configPath, 'utf-8');
            expect(manager.problems.length).toBe(mockConfig.length);
            expect(manager.problems[0].id).toBe('tsp_10_cities');
            // Check if initial state was saved to the store
            const storedState = await store.get('problem-state:tsp_10_cities');
            expect(storedState).toEqual(mockConfig[0].state);
        });

        it('should dynamically generate cities and assets', async () => {
            const tspProblem = manager.problems.find(p => p.id === 'tsp_10_cities');
            const portfolioProblem = manager.problems.find(p => p.id === 'portfolio_5_assets');

            expect(tspProblem.payload.points.length).toBe(10);
            expect(tspProblem.payload.points[0]).toHaveProperty('x');
            expect(tspProblem.payload.points[0]).toHaveProperty('y');

            expect(Array.isArray(portfolioProblem.payload.assets)).toBe(true);
            expect(portfolioProblem.payload.assets.length).toBe(5);
            expect(portfolioProblem.payload.assets[0]).toHaveProperty('expectedReturn');
            expect(portfolioProblem.payload.assets[0]).toHaveProperty('volatility');
        });

        it('should handle file read errors gracefully', async () => {
            fs.readFile.mockRejectedValue(new Error('File not found'));
            const manager = await getProblemManager({ configPath: 'nonexistent.json' }, store);
            expect(manager.problems).toEqual([]);
        });
    });

    describe('dispatchWork', () => {
        it('should return null if no problems are loaded', async () => {
            fs.readFile.mockRejectedValue(new Error('File read error'));
            const manager = await getProblemManager({ configPath: 'bad.json' }, store);
            expect(manager.dispatchWork(0.5)).toBeNull();
        });

        it('should cycle through problems in a round-robin fashion', async () => {
            const work1 = manager.dispatchWork(0.1);
            const work2 = manager.dispatchWork(0.1);
            const work3 = manager.dispatchWork(0.1);

            expect(work1.problemId).toBe('tsp_10_cities');
            expect(work2.problemId).toBe('portfolio_5_assets');
            expect(work3.problemId).toBe('tsp_10_cities'); // Cycled back
        });

        it('should calculate exponential difficulty based on suspicionFactor', async () => {
            const suspicionFactor = 0.5;

            // Test for TSP problem
            const { task: tspTask } = manager.dispatchWork(suspicionFactor);
            
            // The base is now the MAX of the config and the hardcoded minimum (15000)
            const expectedBaseIterations = Math.max(15000, mockConfig[0].workUnit.baseIterations);
            const expectedTspIterations = Math.floor(expectedBaseIterations * Math.pow(2.0, suspicionFactor));
            expect(tspTask.iterations).toBe(expectedTspIterations);

            // Test for Portfolio problem
            const { task: portfolioTask } = manager.dispatchWork(suspicionFactor);
            const expectedBaseGenerations = Math.max(50, mockConfig[1].workUnit.baseGenerations);
            const expectedPortfolioGenerations = Math.floor(expectedBaseGenerations * Math.pow(1.5, suspicionFactor));
            expect(portfolioTask.generations).toBe(expectedPortfolioGenerations);
        });
    });

    describe('integrateSolution', () => {
        it('should update the best solution if a better one is provided', async () => {
            const problem = manager.problems.find(p => p.id === 'tsp_10_cities');
            problem.state.bestEnergy = 1000; // Set a high initial energy

            const newBetterSolution = { solution: [{ id: 1 }], energy: 500 };
            // Le mock de `evaluatePathDistance` va retourner 1 (la somme des IDs).
            // C'est cette valeur qui doit être stockée, pas 500.
            const expectedRecalculatedEnergy = 1;

            await manager.integrateSolution('tsp_10_cities', newBetterSolution);

            expect(problem.state.bestSolution).toEqual(newBetterSolution.solution);
            expect(problem.state.bestEnergy).toBe(expectedRecalculatedEnergy); // Vérifier le score recalculé
            const storedState = await store.get('problem-state:tsp_10_cities');
            expect(storedState.bestEnergy).toBe(expectedRecalculatedEnergy);
        });

        it('should not update the best solution if a worse one is provided', async () => {
            const problem = manager.problems.find(p => p.id === 'tsp_10_cities');
            const initialSolution = [{ id: 10 }];
            problem.state.bestSolution = initialSolution;
            problem.state.bestEnergy = 10; // Le score initial est 10 (calculé à partir de l'ID)

            const newWorseSolution = { solution: [{ id: 20 }], energy: 200 };
            // Le mock de `evaluatePathDistance` va retourner 20.
            // Comme 20 n'est pas meilleur que 10, la solution ne doit pas changer.

            await manager.integrateSolution('tsp_10_cities', newWorseSolution);

            expect(problem.state.bestSolution).toEqual(initialSolution);
            expect(problem.state.bestEnergy).toBe(10);
            const storedState = await store.get('problem-state:tsp_10_cities');
            expect(storedState.bestEnergy).toBe(10);
        });

        it('should handle solutions for non-existent problems gracefully', async () => {
            // This should not throw an error
            await manager.integrateSolution('non_existent_problem', { energy: 1 });
            expect(await store.has('problem-state:non_existent_problem')).toBe(false);
        });

        it('should integrate a new Pareto front for multi-objective problems', async () => {
            // **LA CORRECTION** : Réinitialiser le singleton avant de modifier la configuration.
            problemManagerInternal.resetManager();

            // Add a multi-objective problem to the config for this test
            mockConfig.push({
                "id": "multi_obj_test",
                "workUnit": { "type": "multi_objective_genetic_algorithm" },
                "state": { "paretoFront": [{ solution: 'A', objectives: [10, 20] }] }
            });
            fs.readFile.mockResolvedValue(JSON.stringify(mockConfig));
            manager = await getProblemManager(configPath, store);

            const problem = manager.problems.find(p => p.id === 'multi_obj_test');

            // The new front contains a solution that dominates the old one.
            const newFrontFromClient = [{ solution: 'B', objectives: [5, 15] }];

            await manager.integrateSolution('multi_obj_test', { paretoFront: newFrontFromClient });

            // The new front should contain only the new, dominant solution.
            // We check the content instead of object equality for robustness.
            expect(problem.state.paretoFront).toHaveLength(1);
            expect(problem.state.paretoFront[0]).toEqual({ solution: 'B', objectives: [5, 15] });
            expect(problem.state.lastUpdate).toBeDefined();
            const storedState = await store.get('problem-state:multi_obj_test');
            expect(storedState.paretoFront[0].solution).toBe('B');
        });
    });

    describe('getBestSolutions', () => {
        beforeEach(async () => {
            // Mock the initial solution generation to be predictable
            mockConfig[0].payload.points = [
                { id: 1, x: 10, y: 10 },
                { id: 2, x: 20, y: 20 },
                { id: 3, x: 30, y: 30 }
            ];

            // The function that is actually called is `Optimization.Utils.evaluatePathDistance`.
            // We need to mock its return value to be predictable for the test.
            // The mock implementation `solution.reduce(...)` will sum the `id` properties.
            // For the points above, the sum is 1 + 2 + 3 = 6.
            vi.spyOn(Optimization.Utils, 'evaluatePathDistance').mockReturnValue(6);
        });

        it('should generate an initial solution if none exists', async () => {
            const problem = manager.problems.find(p => p.id === 'tsp_10_cities');
            problem.state.bestSolution = null; // Ensure no solution exists

            await manager.getBestSolutions('tsp_10_cities');

            expect(problem.state.bestSolution).not.toBeNull();
            expect(problem.state.bestEnergy).toBe(6); // Mocked energy value
            const storedState = await store.get('problem-state:tsp_10_cities');
            expect(storedState.bestEnergy).toBe(6);
        });

        it('should return the best solution for a specific problem ID', async () => {
            const problem = manager.problems.find(p => p.id === 'tsp_10_cities');
            problem.state.bestSolution = [{ id: 'A' }];
            problem.state.bestEnergy = 123;
            problem.state.lastUpdate = '2023-01-01T00:00:00.000Z';

            const result = await manager.getBestSolutions('tsp_10_cities');

            expect(result).toEqual({
                id: 'tsp_10_cities',
                solution: [{ id: 'A' }],
                score: 123,
                lastUpdate: '2023-01-01T00:00:00.000Z'
            });
        });

        it('should return an array of all best solutions if no ID is provided', async () => {
            const problem1 = manager.problems.find(p => p.id === 'tsp_10_cities');
            problem1.state.bestSolution = [{ id: 'A' }];
            problem1.state.bestEnergy = 123;

            // The portfolio problem has no solution, so it should be filtered out
            const results = await manager.getBestSolutions();

            expect(Array.isArray(results)).toBe(true);
            expect(results.length).toBe(1);
            expect(results[0].id).toBe('tsp_10_cities');
            expect(results[0].score).toBe(123);
        });

        it('should return null if a non-existent problem ID is requested', async () => {
            const result = await manager.getBestSolutions('non_existent_problem');
            expect(result).toBeNull();
        });
    });

    describe('updateProblemPayload', () => {
        it('should update the payload of a specific problem', async () => {
            const newPayload = {
                "points": [{ "x": 0, "y": 0 }],
                "options": { "initialTemperature": 500 }
            };

            const success = await manager.updateProblemPayload('tsp_10_cities', newPayload);
            expect(success).toBe(true);

            const problem = manager.problems.find(p => p.id === 'tsp_10_cities');
            expect(problem.payload).toEqual(newPayload);
        });

        it('should reset the state of the updated problem', async () => {
            const problem = manager.problems.find(p => p.id === 'tsp_10_cities');
            problem.state.bestSolution = [{ id: 1 }];
            problem.state.bestEnergy = 10;

            await manager.updateProblemPayload('tsp_10_cities', { new: 'payload' });
            expect(problem.state.bestSolution).toBeNull();
            expect(problem.state.bestEnergy).toBe("Infinity");
            const storedState = await store.get('problem-state:tsp_10_cities');
            expect(storedState.bestEnergy).toBe("Infinity");
        });
    });
});
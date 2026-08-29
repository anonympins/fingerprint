import { it, describe, expect, vi, beforeEach, afterEach } from 'vitest';
import { readFileSync, writeFileSync } from 'node:fs';
import { ProblemManager } from '../problem-manager.js';
import { Optimization } from '../library.js';

// Mock the 'fs' module
vi.mock('node:fs', async () => {
    const originalFs = await vi.importActual('node:fs');
    return {
        ...originalFs,
        readFileSync: vi.fn(),
        writeFileSync: vi.fn(),
    };
});

// Mock the Optimization library to have predictable results for energy calculation
vi.mock('../library.js', () => ({
    Optimization: {
        tsp: {
            // This mock was incorrect for the function it's mocking.
            // The real function is in `Utils`. Let's keep the mock simple.
            calculateEnergy: vi.fn(),
        },
        Utils: {
            // This is the function causing the error.
            evaluatePathDistance: vi.fn(solution => solution.reduce((sum, val) => sum + val.id, 0)),
        },
        Operators: { // Add the Operators object to the mock
            solveTSP: vi.fn(), // Mock solveTSP
            solvePortfolio: vi.fn(), // Mock solvePortfolio
            // This function is also used by problem-manager.js
            createPortfolioAllocator: vi.fn(() => vi.fn()),
        }
    }
}));

describe('ProblemManager', () => {
    let mockConfig;

    beforeEach(() => {
        // Reset mocks before each test
        vi.clearAllMocks();

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

        // Mock readFileSync to return our config
        readFileSync.mockReturnValue(JSON.stringify(mockConfig));
    });

    describe('Initialization and Loading', () => {
        it('should load and parse problems from the config file', () => {
            const manager = new ProblemManager('fake/path.json');
            expect(readFileSync).toHaveBeenCalledWith('fake/path.json', 'utf-8');
            expect(manager.problems.length).toBe(2);
            expect(manager.problems[0].id).toBe('tsp_10_cities');
        });

        it('should dynamically generate cities and assets', () => {
            const manager = new ProblemManager('fake/path.json');
            const tspProblem = manager.problems.find(p => p.id === 'tsp_10_cities');
            const portfolioProblem = manager.problems.find(p => p.id === 'portfolio_5_assets');

            // Check if 'points' was generated correctly
            expect(Array.isArray(tspProblem.payload.points)).toBe(true);
            expect(tspProblem.payload.points.length).toBe(10);
            expect(tspProblem.payload.points[0]).toHaveProperty('x');
            expect(tspProblem.payload.points[0]).toHaveProperty('y');

            // Check if 'assets' was generated correctly
            expect(Array.isArray(portfolioProblem.payload.assets)).toBe(true);
            expect(portfolioProblem.payload.assets.length).toBe(5);
            expect(portfolioProblem.payload.assets[0]).toHaveProperty('expectedReturn');
            expect(portfolioProblem.payload.assets[0]).toHaveProperty('volatility');
        });

        it('should handle file read errors gracefully', () => {
            readFileSync.mockImplementation(() => {
                throw new Error('File not found');
            });
            const manager = new ProblemManager('nonexistent.json');
            expect(manager.problems).toEqual([]);
        });
    });

    describe('dispatchWork', () => {
        it('should return null if no problems are loaded', () => {
            readFileSync.mockImplementation(() => { throw new Error('err'); });
            const manager = new ProblemManager('bad.json');
            expect(manager.dispatchWork(0.5)).toBeNull();
        });

        it('should cycle through problems in a round-robin fashion', () => {
            const manager = new ProblemManager('fake/path.json');
            const work1 = manager.dispatchWork(0.1);
            const work2 = manager.dispatchWork(0.1);
            const work3 = manager.dispatchWork(0.1);

            expect(work1.problemId).toBe('tsp_10_cities');
            expect(work2.problemId).toBe('portfolio_5_assets');
            expect(work3.problemId).toBe('tsp_10_cities'); // Cycled back
        });

        it('should calculate exponential difficulty based on suspicionFactor', () => {
            const manager = new ProblemManager('fake/path.json');
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
        it('should update the best solution if a better one is provided', () => {
            const manager = new ProblemManager('fake/path.json');
            const problem = manager.problems.find(p => p.id === 'tsp_10_cities');
            problem.state.bestEnergy = 1000; // Set a high initial energy

            const newBetterSolution = { solution: [{ id: 1 }], energy: 500 };
            // Le mock de `evaluatePathDistance` va retourner 1 (la somme des IDs).
            // C'est cette valeur qui doit être stockée, pas 500.
            const expectedRecalculatedEnergy = 1;

            manager.integrateSolution('tsp_10_cities', newBetterSolution);

            expect(problem.state.bestSolution).toEqual(newBetterSolution.solution);
            expect(problem.state.bestEnergy).toBe(expectedRecalculatedEnergy); // Vérifier le score recalculé
            expect(writeFileSync).toHaveBeenCalled();
        });

        it('should not update the best solution if a worse one is provided', () => {
            const manager = new ProblemManager('fake/path.json');
            const problem = manager.problems.find(p => p.id === 'tsp_10_cities');
            const initialSolution = [{ id: 10 }];
            problem.state.bestSolution = initialSolution;
            problem.state.bestEnergy = 10; // Le score initial est 10 (calculé à partir de l'ID)

            const newWorseSolution = { solution: [{ id: 20 }], energy: 200 };
            // Le mock de `evaluatePathDistance` va retourner 20.
            // Comme 20 n'est pas meilleur que 10, la solution ne doit pas changer.

            manager.integrateSolution('tsp_10_cities', newWorseSolution);

            expect(problem.state.bestSolution).toEqual(initialSolution);
            expect(problem.state.bestEnergy).toBe(10);
            // saveProblems is still called, so we check writeFileSync was called
            expect(writeFileSync).toHaveBeenCalled();
        });

        it('should handle solutions for non-existent problems gracefully', () => {
            const manager = new ProblemManager('fake/path.json');
            // This should not throw an error
            expect(() => manager.integrateSolution('non_existent_problem', { energy: 1 })).not.toThrow();
            // And it should not attempt to save
            expect(writeFileSync).not.toHaveBeenCalled();
        });
    });

    describe('getBestSolutions', () => {
        beforeEach(() => {
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
            Optimization.Utils.evaluatePathDistance.mockReturnValue(6);

            // The `tsp.calculateEnergy` mock is not strictly needed for this test to pass,
            // but it's good practice to keep mocks aligned with expected behavior.
            Optimization.tsp.calculateEnergy.mockReturnValue(6); // This is now consistent.
            readFileSync.mockReturnValue(JSON.stringify(mockConfig));
        });

        it('should generate an initial solution if none exists', () => {
            const manager = new ProblemManager('fake/path.json');
            const problem = manager.problems.find(p => p.id === 'tsp_10_cities');
            problem.state.bestSolution = null; // Ensure no solution exists

            manager.getBestSolutions('tsp_10_cities');

            expect(problem.state.bestSolution).not.toBeNull();
            expect(problem.state.bestEnergy).toBe(6); // Mocked energy value
            expect(writeFileSync).toHaveBeenCalled(); // Should save the newly generated solution
        });

        it('should return the best solution for a specific problem ID', () => {
            const manager = new ProblemManager('fake/path.json');
            const problem = manager.problems.find(p => p.id === 'tsp_10_cities');
            problem.state.bestSolution = [{ id: 'A' }];
            problem.state.bestEnergy = 123;
            problem.state.lastUpdate = '2023-01-01T00:00:00.000Z';

            const result = manager.getBestSolutions('tsp_10_cities');

            expect(result).toEqual({
                id: 'tsp_10_cities',
                solution: [{ id: 'A' }],
                score: 123,
                lastUpdate: '2023-01-01T00:00:00.000Z'
            });
        });

        it('should return an array of all best solutions if no ID is provided', () => {
            const manager = new ProblemManager('fake/path.json');
            const problem1 = manager.problems.find(p => p.id === 'tsp_10_cities');
            problem1.state.bestSolution = [{ id: 'A' }];
            problem1.state.bestEnergy = 123;

            // The portfolio problem has no solution, so it should be filtered out
            const results = manager.getBestSolutions();

            expect(Array.isArray(results)).toBe(true);
            expect(results.length).toBe(1);
            expect(results[0].id).toBe('tsp_10_cities');
            expect(results[0].score).toBe(123);
        });

        it('should return null if a non-existent problem ID is requested', () => {
            const manager = new ProblemManager('fake/path.json');
            const result = manager.getBestSolutions('non_existent_problem');
            expect(result).toBeNull();
        });
    });
});
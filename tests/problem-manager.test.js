import { it, describe, expect, vi, beforeEach, afterEach } from 'vitest';
import { readFileSync } from 'node:fs';
import { ProblemManager } from '../problem-manager.js';

// Mock the 'fs' module
vi.mock('node:fs', async () => {
    const originalFs = await vi.importActual('node:fs');
    return {
        ...originalFs,
        readFileSync: vi.fn(),
        writeFileSync: vi.fn(),
    };
});

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
                    "baseIterations": 1000, // Lower value for testing
                    "scalingFactor": 2.0
                },
                "payload": {
                    "cities": {
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

            // Check if 'cities' was generated correctly
            expect(Array.isArray(tspProblem.payload.cities)).toBe(true);
            expect(tspProblem.payload.cities.length).toBe(10);
            expect(tspProblem.payload.cities[0]).toHaveProperty('x');
            expect(tspProblem.payload.cities[0]).toHaveProperty('y');

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
});
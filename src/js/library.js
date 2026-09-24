/**
 * @file @/library.js
 * @description A library of tools based on the fundamental principle of dichotomy (division in two).
 * Includes algorithms for sorted arrays, data structures, and problem solvers.
 *
 * @template T
 * @callback Comparator
 * @param {T} element - Array element.
 * @param {any} target - Target value.
 * @returns {number} -1 if element < target, 0 if element == target, 1 if element > target.
 *
 */

import {Worker} from "node:worker_threads";
import os from "node:os";
import crypto from "node:crypto";

/**
 * Generates a cryptographically secure random float between 0 (inclusive) and 1 (exclusive).
 * @returns {number}
 */
const random = () => {
  return crypto.randomInt(0, 4294967296) / 4294967296;
};

const Optimization = {
  // eslint-disable-line no-unused-vars
  /**
   * Finds an optimized solution using Simulated Annealing.
   * @template TSolution - Type of the solution (number, array, object...).
   * @param {TSolution} initialSolution - Starting point for optimization.
   * @param {function(TSolution): number} evaluator - Evaluates a solution (goal is to MINIMIZE score).
   * @param {function(TSolution): TSolution} neighbor - Generates a random neighbor solution.
   * @param {number} [initialTemperature=1000] - Initial temperature.
   * @param {number} [coolingRate=0.995] - Cooling rate factor.
   * @param {number} [maxIterations=10000] - Total iterations.
   * @returns {{solution: TSolution, energy: number}} Best solution and corresponding energy score.
   */
  simulatedAnnealing(
    initialSolution,
    evaluator,
    neighbor,
    initialTemperature = 1000,
    coolingRate = 0.995,
    maxIterations = 10000,
  ) {
    let currentSolution = initialSolution;
    let currentEnergy = evaluator(currentSolution);

    let bestSolution = currentSolution;
    let bestEnergy = currentEnergy;

    let temperature = initialTemperature;

    for (let i = 0; i < maxIterations; i++) {
      const newSolution = neighbor(currentSolution);
      const newEnergy = evaluator(newSolution);

      // Calculate acceptance probability for a worse solution
      const acceptanceProbability = Math.exp(
        (currentEnergy - newEnergy) / temperature,
      );

      // Decide whether to transition to the candidate solution
      if (newEnergy < currentEnergy || random() < acceptanceProbability) {
        currentSolution = newSolution;
        currentEnergy = newEnergy;
      }

      // Update global best found so far
      if (currentEnergy < bestEnergy) {
        bestSolution = currentSolution;
        bestEnergy = currentEnergy;
      }

      // Cool down temperature
      temperature *= coolingRate;
    }

    return { solution: bestSolution, energy: bestEnergy };
  },

  /**
   * Solves an optimization problem using a Genetic Algorithm.
   * @template TChromosome - Type of the chromosome.
   * @param {function(): TChromosome} createIndividual - Creates a random individual.
   * @param {function(TChromosome): number} fitnessFunction - Evaluates an individual (MINIMIZATION).
   * @param {function(TChromosome, TChromosome): TChromosome} crossover - Crosses two parents.
   * @param {function(TChromosome): TChromosome} mutate - Applies random mutation.
   * @param {object} options - Algorithm options.
   * @param {number} [options.populationSize=100] - Population size.
   * @param {number} [options.generations=100] - Number of generations.
   * @param {number} [options.crossoverRate=0.8] - Crossover rate.
   * @param {number} [options.mutationRate=0.1] - Mutation rate.
   * @param {function} [options.selectionFunction] - Parent selection function.
   * @param {boolean} [options.returnPopulation=false] - Whether to return final population instead of single best.
   * @returns {{solution: TChromosome, fitness: number}} Best individual found.
   */
  geneticAlgorithm(
    createIndividual,
    fitnessFunction,
    crossover,
    mutate,
    options = {},
  ) {
    const populationSize = options.populationSize || 100;
    const generations = options.generations || 100;
    const crossoverRate =
      options.crossoverRate !== undefined ? options.crossoverRate : 0.8;
    const mutationRate =
      options.mutationRate !== undefined ? options.mutationRate : 0.1;
    const selectionFunction =
      options.selectionFunction ||
      this.Operators.createTournamentSelection({ size: 5 });
    const returnPopulation = options.returnPopulation || false;

    // 1. Initialization
    let population = Array.from({ length: populationSize }, () => {
      const chromosome = createIndividual();
      return { chromosome, fitness: fitnessFunction(chromosome) };
    });

    // Sort initial population to find best
    population.sort((a, b) => a.fitness - b.fitness);
    let bestOverall = population[0];

    // 2. Generation loop
    for (let gen = 0; gen < generations; gen++) {
      const newPopulation = [];

      // Elitism: retain best individual from previous generation
      newPopulation.push(population[0]);

      while (newPopulation.length < populationSize) {
        // 3. Selection
        const parent1 = selectionFunction(population);
        const parent2 = selectionFunction(population);

        let offspringChromosome;
        // 4. Crossover
        if (random() < crossoverRate) {
          offspringChromosome = crossover(
            parent1.chromosome,
            parent2.chromosome,
          );
        } else {
          offspringChromosome = parent1.chromosome;
        }

        // 5. Mutation
        if (random() < mutationRate) {
          offspringChromosome = mutate(offspringChromosome);
        }

        // Ensure operators returned a valid individual
        if (offspringChromosome) {
          newPopulation.push({
            chromosome: offspringChromosome,
            fitness: fitnessFunction(offspringChromosome),
          });
        } else {
          newPopulation.push(parent1);
        }
      }

      population = newPopulation;

      // Sort new population for elitism and update best overall
      population.sort((a, b) => a.fitness - b.fitness);

      if (population[0].fitness < bestOverall.fitness) {
        bestOverall = population[0];
      }
    }

    if (returnPopulation) {
      return population;
    }

    return { solution: bestOverall.chromosome, fitness: bestOverall.fitness };
  },

  /**
   * Executes a stochastic solver multiple times and returns the best result.
   * @param {function(): {solution: any, energy?: number, fitness?: number}} solverFunction - Solver function.
   * @param {number} numCycles - Number of execution cycles.
   * @param {boolean} [logProgress=false] - Log progress to console.
   * @returns {{bestResult: object, stats: {scores: Array<number>, average: number, stdDev: number}}} Best result and run stats.
   */
  runMultiple(solverFunction, numCycles, logProgress = false) {
    let bestResult = null;
    const allScores = [];

    for (let i = 0; i < numCycles; i++) {
      const currentResult = solverFunction();

      // Handle simulated annealing (energy) and genetic algorithm (fitness) results (lower is better)
      const currentScore =
        currentResult.energy !== undefined
          ? currentResult.energy
          : currentResult.fitness;
      allScores.push(currentScore);

      if (logProgress) {
        console.log(
          `   -> Cycle ${i + 1}/${numCycles}: Score found = ${currentScore.toFixed(2)}`,
        );
      }

      if (
        !bestResult ||
        currentScore <
          (bestResult.energy !== undefined
            ? bestResult.energy
            : bestResult.fitness)
      ) {
        bestResult = currentResult;
      }
    }

    // Statistical calculations
    const sum = allScores.reduce((a, b) => a + b, 0);
    const average = sum / numCycles;
    const variance =
      allScores.reduce((a, b) => a + Math.pow(b - average, 2), 0) / numCycles;
    const stdDev = Math.sqrt(variance);

    return {
      bestResult,
      stats: {
        scores: allScores,
        average: average,
        stdDev: stdDev,
      },
    };
  },

  /**
   * Finds a local minimum of a differentiable function using Gradient Descent.
   * @template TSolution - Solution type (number or array of numbers).
   * @param {TSolution} initialSolution - Starting point.
   * @param {function(TSolution): TSolution} gradientFunction - Computes gradient at given point.
   * @param {object} options - Algorithm options.
   * @param {number} [options.learningRate=0.01] - Step size.
   * @param {number} [options.maxIterations=1000] - Max iterations.
   * @param {number} [options.tolerance=1e-6] - Stopping threshold.
   * @returns {TSolution} Local minimum found.
   */
  gradientDescent(initialSolution, gradientFunction, options = {}) {
    const {
      learningRate = 0.01,
      maxIterations = 1000,
      tolerance = 1e-6,
    } = options;

    let currentSolution = Array.isArray(initialSolution)
      ? [...initialSolution]
      : initialSolution;

    for (let i = 0; i < maxIterations; i++) {
      const gradient = gradientFunction(currentSolution);

      if (Array.isArray(currentSolution)) {
        const prevSolution = [...currentSolution];
        for (let j = 0; j < currentSolution.length; j++) {
          currentSolution[j] -= learningRate * gradient[j];
        }
        const change = prevSolution.reduce(
          (sum, val, idx) => sum + Math.abs(val - currentSolution[idx]),
          0,
        );
        if (change < tolerance) break;
      } else {
        // Single variable scalar case
        const prevSolution = currentSolution;
        currentSolution -= learningRate * gradient;
        if (Math.abs(prevSolution - currentSolution) < tolerance) break;
      }
    }
    return currentSolution;
  },

  /**
   * Executes a stochastic solver multiple times in parallel using a worker pool.
   * @param {string} solverName - Name of the solver function in `Optimization.Operators`.
   * @param {Array<any>} baseSolverArgs - Base arguments for solver.
   * @param {number} numCycles - Total cycles to run.
   * @param {boolean} [logProgress=false] - Log progress.
   * @param {object} [options={}] - Concurrency options.
   * @param {number} [options.concurrency] - Worker concurrency count (defaults to CPU count).
   * @param {function(number): Array<any>} [options.workerDataGenerator] - Dynamic argument generator per task index.
   * @returns {Promise<{bestResult: object, stats: {scores: Array<number>, average: number, stdDev: number}}>} Best result and stats.
   */
  async runMultipleParallel(
    solverName,
    baseSolverArgs = [], // Default to empty array if not provided
    numCycles,
    logProgress = false,
    options = {},
  ) {
    const concurrency = options.concurrency || os.cpus().length;
    const workerDataGenerator = options.workerDataGenerator;

    if (logProgress) {
      console.log(
        `   (Using a pool of ${concurrency} workers for ${numCycles} cycles with solver ${solverName})`,
      );
    }

    const allResults = new Array(numCycles);
    const tasks = Array.from({ length: numCycles }, (_, i) => i);
    let tasksCompleted = 0;

    const runWorker = async (workerId) => {
      while (tasks.length > 0) {
        const taskIndex = tasks.shift();
        if (taskIndex === undefined) continue;

        const workerData = {
          solverName,
          solverArgs: workerDataGenerator
            ? workerDataGenerator(taskIndex)
            : baseSolverArgs,
        };

        const result = await new Promise(async (resolve, reject) => {
          // Resolve worker script path relative to current module
          const worker = new Worker(new URL('./optimization.worker.js', import.meta.url), { workerData });
          worker.on("message", resolve);
          worker.on("error", reject);
          worker.on("exit", (code) => {
            if (code !== 0)
              reject(
                new Error(`Worker ${workerId} exited with code ${code}`),
              );
          });
        });

        allResults[taskIndex] = result;
        tasksCompleted++;
        if (logProgress) {
          const score =
            result.energy !== undefined ? result.energy : result.fitness;
          console.log(
            `   -> Cycle ${tasksCompleted}/${numCycles} (Worker ${workerId}): Score = ${score.toFixed(2)}`,
          );
        }
      }
    };

    const workerPromises = Array.from({ length: concurrency }, (_, i) =>
      runWorker(i + 1),
    );
    await Promise.all(workerPromises);

    // Remainder follows runMultiple logic
    let bestResult = null;
    const allScores = [];
    allResults.forEach((result) => {
      const score =
        result.energy !== undefined ? result.energy : result.fitness;
      allScores.push(score);
      if (
        !bestResult ||
        score <
          (bestResult.energy !== undefined
            ? bestResult.energy
            : bestResult.fitness)
      ) {
        bestResult = result;
      }
    });

    const sum = allScores.reduce((a, b) => a + b, 0);
    const average = sum / numCycles;
    const variance =
      allScores.reduce((a, b) => a + Math.pow(b - average, 2), 0) / numCycles;
    const stdDev = Math.sqrt(variance);

    return {
      bestResult,
      stats: { scores: allScores, average, stdDev, concurrency },
    };
  },
};

/**
 * Determines whether solution A Pareto-dominates solution B (minimization problem).
 * @private
 * @param {number[]} objectivesA - Objective scores for solution A.
 * @param {number[]} objectivesB - Objective scores for solution B.
 * @returns {boolean} - True if A dominates B.
 */
function paretoDominates(objectivesA, objectivesB) {
  let aIsBetterInOne = false;
  for (let i = 0; i < objectivesA.length; i++) {
    if (objectivesA[i] > objectivesB[i]) {
      return false; // A is worse on at least one objective
    }
    if (objectivesA[i] < objectivesB[i]) {
      aIsBetterInOne = true; // A is strictly better on at least one objective
    }
  }
  return aIsBetterInOne;
}

/**
 * Sorts a population into non-dominated Pareto fronts (inspired by NSGA-II).
 * @private
 * @param {Array<{individual: any, objectives: number[]}>} populationWithObjectives - Population to sort.
 * @returns {Array<Array<{individual: any, objectives: number[]}>>} - Array of fronts, first being the best.
 */
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

/**
 * Calculates crowding distance for a front to preserve diversity.
 * @private
 * @param {Array<{individual: any, objectives: number[]}>} front - Pareto front.
 */
function calculateCrowdingDistance(front) {
  if (front.length === 0) return;
  front.forEach((p) => (p.crowdingDistance = 0));
  const numObjectives = front[0].objectives.length;

  for (let i = 0; i < numObjectives; i++) {
    front.sort((a, b) => a.objectives[i] - b.objectives[i]);
    const minObj = front[0].objectives[i];
    const maxObj = front[front.length - 1].objectives[i];

    // Boundary solutions receive infinite distance to encourage spread
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

/**
 * Multi-objective genetic algorithm (inspired by NSGA-II) to find a Pareto front.
 * @param {function(): any} createIndividual - Creates a random individual.
 * @param {function(any): number[]} fitnessFunction - Evaluates individual and returns array of objectives to MINIMIZE.
 * @param {function(any, any): any} crossover - Crossover function.
 * @param {function(any): any} mutate - Mutation function.
 * @param {object} options - Algorithm options.
 * @returns {Array<{solution: any, objectives: number[]}>} Non-dominated Pareto front.
 */
Optimization.geneticAlgorithmMultiObjective = function (
  createIndividual,
  fitnessFunction,
  crossover,
  mutate,
  options = {},
) {
  const {
    generations = 150,
    populationSize = 60,
    mutationRate = 0.1,
    currentConfig = null,
  } = options;

  let population = Array.from({ length: populationSize }, () => ({
    individual: createIndividual(),
  }));
  population.forEach((p) => (p.objectives = fitnessFunction(p.individual)));

  for (let gen = 0; gen < generations; gen++) {
    // 1. Generate offspring
    const offspring = [];
    for (let i = 0; i < populationSize; i++) {
        const parent1 = population[crypto.randomInt(0, population.length)];
        const parent2 = population[crypto.randomInt(0, population.length)];
      let childIndividual = crossover(parent1.individual, parent2.individual);
        if (random() < mutationRate) {
        childIndividual = mutate(childIndividual, currentConfig);
      }
      const child = { individual: childIndividual };
      child.objectives = fitnessFunction(child.individual);
      offspring.push(child);
    }

    // 2. Combine parent and offspring populations
    const combinedPopulation = [...population, ...offspring];

    // 3. Sort into Pareto fronts
    const fronts = nonDominatedSort(combinedPopulation);

    // 4. Build next generation population
    const newPopulation = [];
    for (const front of fronts) {
      if (newPopulation.length + front.length <= populationSize) {
        newPopulation.push(...front);
      } else {
        // Use crowding distance truncation if front overflows population size
        calculateCrowdingDistance(front);
        front.sort((a, b) => b.crowdingDistance - a.crowdingDistance);
        const remaining = populationSize - newPopulation.length;
        newPopulation.push(...front.slice(0, remaining));
        break;
      }
    }
    population = newPopulation;
  }

  // Return the first front of the final population
  const finalFronts = nonDominatedSort(population);
  const bestFront = finalFronts.length > 0 ? finalFronts[0] : [];

  // Deduplicate solutions with identical objectives
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
};

/**
 * Optimization utilities.
 */
Optimization.Utils = {
    /** Calculates Euclidean distance between two points/cities. */
    distance: (city1, city2) => Math.sqrt(Math.pow(city1.x - city2.x, 2) + Math.pow(city1.y - city2.y, 2)),

    /** Evaluates the total round-trip distance of a TSP path. */
    evaluatePathDistance: (cities, path) => {
        let totalDistance = 0;
        for (let i = 0; i < path.length - 1; i++) {
            totalDistance += Optimization.Utils.distance(cities[path[i]], cities[path[i + 1]]);
        }
        totalDistance += Optimization.Utils.distance(cities[path[path.length - 1]], cities[path[0]]); // Return to start
        return totalDistance;
    }
};

/**
 * CMA-ES (Covariance Matrix Adaptation Evolution Strategy) optimization algorithm.
 * State-of-the-art evolutionary algorithm for black-box optimization of non-linear, non-convex functions.
 * Particularly effective for problems involving continuous real-valued variables.
 * @param {function(Array<number>): number} fitnessFunction - The objective function to MINIMIZE.
 * @param {Array<number>} initialSolution - Starting point for the search (numeric vector).
 * @param {number} initialStepSize - Initial search step size (sigma).
 * @param {object} [options={}] - Algorithm options.
 * @param {number} [options.maxGenerations=100] - Maximum number of generations.
 * @param {number} [options.populationSize] - Population size (lambda). Automatically computed if omitted.
 * @param {number} [options.tolerance=1e-6] - Tolerance threshold for early stopping.
 * @returns {{solution: Array<number>, fitness: number}} Best solution found and its fitness score.
 */
Optimization.cmaes = function(fitnessFunction, initialSolution, initialStepSize, options = {}) {
    const n = initialSolution.length; // Problem dimension

    // --- Algorithm strategy parameters ---
    const { maxGenerations = 100, tolerance = 1e-6 } = options;
    const populationSize = options.populationSize || (4 + Math.floor(3 * Math.log(n))); // Lambda
    const mu = Math.floor(populationSize / 2); // Parent count for recombination

    // Recombination weights
    let weights = Array.from({ length: mu }, (_, i) => Math.log(mu + 0.5) - Math.log(i + 1));
    const sumWeights = weights.reduce((s, w) => s + w, 0);
    weights = weights.map(w => w / sumWeights);
    const muEff = 1 / weights.reduce((s, w) => s + w * w, 0);

    // Adaptation parameters
    const cc = (4 + muEff / n) / (n + 4 + 2 * muEff / n);
    const cs = (muEff + 2) / (n + muEff + 5);
    const c1 = 2 / (Math.pow(n + 1.3, 2) + muEff);
    const cmu = Math.min(1 - c1, 2 * (muEff - 2 + 1 / muEff) / (Math.pow(n + 2, 2) + muEff));
    const damps = 1 + 2 * Math.max(0, Math.sqrt((muEff - 1) / (n + 1)) - 1) + cs;

    // --- Dynamic state variables ---
    let mean = [...initialSolution]; // Distribution mean / search center
    let stepSize = initialStepSize; // Sigma
    let C = Array.from({ length: n }, (_, i) => Array.from({ length: n }, (_, j) => (i === j ? 1 : 0))); // Covariance matrix
    let pc = Array(n).fill(0); // Evolution path for C
    let ps = Array(n).fill(0); // Evolution path for sigma

    let bestFitness = Infinity;
    let bestSolution = null;

    // Cholesky decomposition helper (simplified for symmetric positive-definite matrices)
    function cholesky(A) {
        const L = Array.from({ length: n }, () => Array(n).fill(0));
        for (let i = 0; i < n; i++) {
            for (let j = 0; j <= i; j++) {
                let sum = 0;
                for (let k = 0; k < j; k++) {
                    sum += L[i][k] * L[j][k];
                }
                if (i === j) {
                    const val = A[i][i] - sum;
                    if (val < 0) return null; // Not positive definite
                    L[i][j] = Math.sqrt(val);
                } else {
                    if (L[j][j] === 0) return null;
                    L[i][j] = (A[i][j] - sum) / L[j][j];
                }
            }
        }
        return L;
    }

    for (let gen = 0; gen < maxGenerations; gen++) {
        // 1. Sample new population
        const population = [];
        const arx = []; // Search vectors
        const L = cholesky(C);
        if (!L) {
            console.warn("[CMA-ES] Covariance matrix is no longer positive definite. Stopping.");
            break;
        }

        for (let i = 0; i < populationSize; i++) {
            const z = Array.from({ length: n }, () => random() * 2 - 1); // Standard normal approximation
            const y = Array(n).fill(0); // z transformed by L
            for (let r = 0; r < n; r++) {
                for (let c = 0; c < n; c++) {
                    y[r] += L[r][c] * z[c];
                }
            }
            arx.push(y);
            const individual = mean.map((m, j) => m + stepSize * y[j]);
            population.push({ individual, fitness: fitnessFunction(individual) });
        }

        // 2. Sort and select elite parents
        population.sort((a, b) => a.fitness - b.fitness);
        const parents = population.slice(0, mu);

        if (parents[0].fitness < bestFitness) {
            bestFitness = parents[0].fitness;
            bestSolution = parents[0].individual;
        }

        // 3. Update distribution mean
        const oldMean = [...mean];
        const y_w = Array(n).fill(0);
        for (let j = 0; j < n; j++) {
            for (let i = 0; i < mu; i++) {
                const parentIndex = population.indexOf(parents[i]);
                y_w[j] += weights[i] * arx[parentIndex][j];
            }
        }
        mean = oldMean.map((m, i) => m + stepSize * y_w[i]);

        // 4. Adapt evolution paths
        const C_inv_sqrt = cholesky(C); // Simplification, ideally inverse square root
        const C_inv_sqrt_y_w = y_w; // Approximation
        ps = ps.map((p, i) => (1 - cs) * p + Math.sqrt(cs * (2 - cs) * muEff) * C_inv_sqrt_y_w[i]);
        
        const hsig = Math.sqrt(ps.reduce((s, v) => s + v*v, 0)) / (1 - Math.pow(1 - cs, 2 * (gen + 1))) / n < 1.4 + 2 / (n + 1);
        pc = pc.map((p, i) => (1 - cc) * p + (hsig ? Math.sqrt(cc * (2 - cc) * muEff) * y_w[i] : 0));

        // 5. Adapt covariance matrix C
        let rankOneUpdate = Array.from({ length: n }, (_, i) => Array.from({ length: n }, (_, j) => c1 * pc[i] * pc[j]));
        let rankMuUpdate = Array.from({ length: n }, () => Array(n).fill(0));
        for (let k = 0; k < mu; k++) {
            const y_k = arx[population.indexOf(parents[k])];
            for (let i = 0; i < n; i++) {
                for (let j = 0; j < n; j++) {
                    rankMuUpdate[i][j] += cmu * weights[k] * y_k[i] * y_k[j];
                }
            }
        }
        C = C.map((row, i) => row.map((val, j) => (1 - c1 - cmu) * val + rankOneUpdate[i][j] + rankMuUpdate[i][j]));

        // 6. Adapt step size (sigma)
        stepSize *= Math.exp((cs / damps) * (Math.sqrt(ps.reduce((s, v) => s + v*v, 0)) / Math.sqrt(n) - 1));
    }

    return { solution: bestSolution, fitness: bestFitness };
};

/**
 * @namespace Optimization.Operators
 * @description Evaluator factories for complex, multi-dimensional optimization problems
 * designed for use with Optimization solvers (Simulated Annealing, Genetic Algorithms, etc.).
 */
Optimization.Operators = {}; // Namespace creation

/**
 * Creates a tournament selection operator for genetic algorithms.
 * @param {object} [options] - Tournament options.
 * @param {number} [options.size=5] - Number of candidates per tournament.
 * @returns {function(Array<{chromosome: any, fitness: number}>): {chromosome: any, fitness: number}} Tournament selection operator.
 */
Optimization.Operators.createTournamentSelection = (options = {}) => {
  const tournamentSize = options.size || 5;

  return function tournamentSelection(population) {
    let best = null;

    for (let i = 0; i < tournamentSize; i++) {
      const individual =
        population[crypto.randomInt(0, population.length)];
      if (!best || individual.fitness < best.fitness) {
        best = individual;
      }
    }
    // Returns the best candidate. In degenerate edge cases (all fitness scores are Infinity),
    // fallback to a random candidate instead of returning null.
    if (!best) {
      return population[crypto.randomInt(0, population.length)];
    }
    return best;
  };
};

/**
 * Creates a covariance matrix from pairwise asset correlations.
 * Provides an intuitive representation for cross-asset risk modeling.
 * @param {object} config - Configuration object.
 * @param {Array<{name: string, volatility: number}>} config.assets - Asset definitions with volatilities.
 * @param {Array<{assets: [string, string], correlation: number}>} config.correlations - Pairwise correlation entries.
 * @returns {Array<Array<number>>} Resulting covariance matrix.
 */
Optimization.Operators.createCovarianceMatrixFromCorrelations = ({
  assets,
  correlations,
}) => {
  const n = assets.length;
  const matrix = Array.from({ length: n }, () => Array(n).fill(0));

  // Fast lookup map for asset details by name
  const assetInfo = new Map();
  assets.forEach((asset, index) => {
    assetInfo.set(asset.name, { index, volatility: asset.volatility });
  });

  // 1. Fill diagonal with individual variances (volatility^2)
  for (let i = 0; i < n; i++) {
    const variance = Math.pow(assets[i].volatility, 2);
    matrix[i][i] = variance;
  }

  // 2. Fill off-diagonal cells with computed covariances
  for (const corr of correlations) {
    const [nameA, nameB] = corr.assets;
    if (!assetInfo.has(nameA) || !assetInfo.has(nameB)) {
      console.warn(
        `Warning: One of assets [${nameA}, ${nameB}] was not found. Correlation ignored.`,
      );
      continue;
    }

    const infoA = assetInfo.get(nameA);
    const infoB = assetInfo.get(nameB);

    // Cov(A,B) = Corr(A,B) * Vol(A) * Vol(B)
    const covariance = corr.correlation * infoA.volatility * infoB.volatility;

    matrix[infoA.index][infoB.index] = covariance;
    matrix[infoB.index][infoA.index] = covariance; // Symmetric matrix
  }

  return matrix;
};

// Market imbalance is the absolute delta between supply and demand (goal is minimization)
Optimization.Operators.createMarketEquilibriumEvaluator = (
  demandModel,
  supplyModel,
) => {
  return function marketImbalance(price) {
    const d = demandModel(price);
    const s = supplyModel(price);
    return Math.abs(d - s);
  };
};

/**
 * Creates a fitness function for portfolio allocation.
 * An individual is a weight array (e.g. [0.5, 0.2, 0.3]) normalized to sum to 1.
 * @param {object} config - Configuration object.
 * @param {Array<{name: string, expectedReturn: number, volatility: number}>} config.assets - Target assets.
 * @param {number} config.maxVolatility - Maximum portfolio volatility threshold constraint.
 * @param {Array<Array<number>>} [config.covarianceMatrix] - Covariance matrix for exact variance evaluation.
 * @returns {function(Array<number>): number} Fitness evaluator returning negative return with risk penalty.
 */
Optimization.Operators.createPortfolioAllocator = ({
  assets,
  maxVolatility,
  covarianceMatrix,
}) => {
  // Evaluates a portfolio weight vector.
  // Since solvers minimize, we minimize NEGATIVE expected return.
  return function portfolioFitness(weights) {
    // Normalize weights to ensure total equals 1.0
    const totalWeight = weights.reduce((sum, w) => sum + w, 0);
    if (totalWeight === 0) return Infinity; // Prevent zero-division
    const normalizedWeights = weights.map((w) => w / totalWeight);

    let portfolioReturn = normalizedWeights.reduce(
      (sum, w, i) => sum + w * assets[i].expectedReturn,
      0,
    );
    let portfolioVolatility;

    if (covarianceMatrix) {
      // Accurate covariance volatility: Volatility^2 = w' * C * w
      let variance = 0;
      for (let i = 0; i < assets.length; i++) {
        for (let j = 0; j < assets.length; j++) {
          variance +=
            normalizedWeights[i] *
            normalizedWeights[j] *
            covarianceMatrix[i][j];
        }
      }
      portfolioVolatility = Math.sqrt(variance);
    } else {
      // Simplified weighted average volatility
      portfolioVolatility = normalizedWeights.reduce(
        (sum, w, i) => sum + w * assets[i].volatility,
        0,
      );
    }

    for (let i = 0; i < assets.length; i++) {}

    // High penalty if risk ceiling is violated
    if (portfolioVolatility > maxVolatility) {
      return 1000 + (portfolioVolatility - maxVolatility) * 1000; // Proportional penalty
    }

    // Maximize return <=> minimize negative return
    return -portfolioReturn;
  };
};

/**
 * Solves the Traveling Salesperson Problem (TSP) using Simulated Annealing.
 * @param {Array<{x: number, y: number}>} cities - City coordinates array.
 * @param {object} [options] - Simulated Annealing parameters.
 * @returns {{solution: Array<number>, energy: number}} Optimal tour (city indices) and total distance.
 */
Optimization.Operators.solveTSP = (cities, options = {}) => {
  // Euclidean distance between two cities
  const distance = (city1, city2) =>
    Math.sqrt(Math.pow(city1.x - city2.x, 2) + Math.pow(city1.y - city2.y, 2));

  // Total route tour distance evaluator
  const pathEvaluator = (path) => {
    let totalDistance = 0;
    for (let i = 0; i < path.length - 1; i++) {
      totalDistance += distance(cities[path[i]], cities[path[i + 1]]);
    }
    totalDistance += distance(cities[path[path.length - 1]], cities[path[0]]); // Return to origin
    return totalDistance;
  };

  // Neighborhood: inverts a random sub-sequence (2-opt heuristic)
  const pathNeighbor = (path) => {
    const newPath = [...path];
    if (newPath.length <= 1) return newPath;
    let i = crypto.randomInt(0, newPath.length);
    let j = crypto.randomInt(0, newPath.length);
    while (i === j) {
      j = crypto.randomInt(0, newPath.length);
    }
    const [start, end] = [Math.min(i, j), Math.max(i, j)];

    const segment = newPath.slice(start, end + 1).reverse();
    newPath.splice(start, segment.length, ...segment);
    return newPath;
  };

  // Initial solution: randomized route
  const initialPath = Array.from({ length: cities.length }, (_, i) => i).sort(
    () => random() - 0.5,
  );

  // Default hyperparameters for TSP
  const saOptions = {
    initialTemperature: 10000,
    coolingRate: 0.999,
    maxIterations: 100000,
    ...options,
  };

  return Optimization.simulatedAnnealing(
    initialPath,
    pathEvaluator,
    pathNeighbor,
    saOptions.initialTemperature,
    saOptions.coolingRate,
    saOptions.maxIterations,
  );
};

/**
 * Solves portfolio allocation using a Genetic Algorithm.
 * @param {Array<{name: string, expectedReturn: number, volatility: number}>} assets - Available assets.
 * @param {number} maxVolatility - Maximum allowed volatility constraint.
 * @param {object} [options] - Genetic algorithm options.
 * @returns {{solution: Array<number>, fitness: number}} Optimal weights and associated fitness.
 */
Optimization.Operators.solvePortfolio = (
  assets,
  maxVolatility,
  options = {},
) => {
  // Fitness function created from the allocator operator
  const fitnessFunction = Optimization.Operators.createPortfolioAllocator({
    assets,
    maxVolatility,
    covarianceMatrix: options.covarianceMatrix,
  });

  // Problem-specific genetic operators
  const createIndividual = () =>
    Array.from({ length: assets.length }, () => random());

  const crossover = (p1, p2) => p1.map((w1, i) => (w1 + p2[i]) / 2); // Arithmetic average

  const mutate = (p) => {
    const newP = [...p];
      const i = crypto.randomInt(0, newP.length);
    newP[i] += (random() - 0.5) * 0.2; // Gentle mutation
    newP[i] = Math.max(0, newP[i]); // Weights cannot be negative
    return newP;
  };

  const gaOptions = {
    generations: 150,
    populationSize: 100,
    ...options,
  };

  return Optimization.geneticAlgorithm(
    createIndividual,
    fitnessFunction,
    crossover,
    mutate,
    gaOptions,
  );
};

/**
 * Creates a 2D evaluator to determine base commission and quality bonus factor to maximize platform revenue.
 * @param {object} config - Configuration object.
 * @param {number} config.totalAdvertiserCredits - Total advertiser credits.
 * @param {Array<{qualityScore: number}>} config.websites - Array of websites with quality scores.
 * @returns {function(Array<number>): number} Evaluator for `[baseCommission, bonusFactor]` returning NEGATIVE revenue.
 */
Optimization.Operators.createAdvancedPlatformRevenueEvaluator = ({
  totalAdvertiserCredits,
  websites,
}) => {
  // Advertiser demand model (increases with inventory quality)
  const advertiserDemandModel = (averageSiteQuality) => {
    // Baseline demand tied to available credits
    const baseDemand = (totalAdvertiserCredits || 100) * 10;
    // Demand scales with average inventory quality
    return baseDemand * (1 + averageSiteQuality);
  };

  // Publisher / webmaster supply model
  // Each site's click supply scales with its effective payout rate
  const webmasterSupplyModel = (baseCommission, bonusFactor) => {
    let totalOfferedClicks = 0;
    const baseSupplyPerSite = 500; // Baseline potential clicks per site

    for (const site of websites) {
      // Effective commission is discounted for higher quality sites
      const effectiveCommission = Math.max(
        0,
        baseCommission - site.qualityScore * bonusFactor,
      );
      const webmasterPayoutRate = 1 - effectiveCommission;

      // Supply is proportional to payout rate
      totalOfferedClicks += baseSupplyPerSite * webmasterPayoutRate;
    }
    return totalOfferedClicks;
  };

  // Objective function for optimization algorithms
  return function revenueEvaluator(solution) {
    const [baseCommission, bonusFactor] = solution;

    // Constraints: heavily penalize out-of-bound solutions
    if (
      baseCommission < 0.01 ||
      baseCommission > 0.8 ||
      bonusFactor < 0 ||
      bonusFactor > baseCommission
    ) {
      return Infinity;
    }

    const averageQuality =
      websites.length > 0
        ? websites.reduce((sum, site) => sum + site.qualityScore, 0) /
          websites.length
        : 0.5;

    const demand = advertiserDemandModel(averageQuality);
    const supply = webmasterSupplyModel(baseCommission, bonusFactor);

    const clicks = Math.min(demand, supply);
    const averageCommission = Math.max(
      0,
      baseCommission - averageQuality * bonusFactor,
    );

    // Maximize revenue <=> minimize negative revenue
    return -(clicks * averageCommission);
  };
};

/**
 * Solves the Facility Location Problem using Simulated Annealing.
 * @param {Array<{x: number, y: number}>} customers - Customer coordinate pairs.
 * @param {number} numFacilities - Number of facilities to place.
 * @param {{minX: number, maxX: number, minY: number, maxY: number}} bounds - Boundary box for placing facilities.
 * @param {number} [options.fixedCostPerFacility=0] - Fixed installation cost per facility.
 * @param {object} [options] - Simulated Annealing options.
 * @returns {{solution: Array<{x: number, y: number}>, energy: number}} Optimal facility locations and total cost.
 */
Optimization.Operators.solveFacilityLocation = (
  customers,
  numFacilities,
  bounds,
  options = {},
) => {
  const fixedCostPerFacility = options.fixedCostPerFacility || 0;
  const distanceSq = (p1, p2) =>
    Math.pow(p1.x - p2.x, 2) + Math.pow(p1.y - p2.y, 2); // Squared Euclidean distance for efficiency

  // Evaluator: computes sum of shortest distances from each customer to nearest facility
  const facilityEvaluator = (facilities) => {
    let totalConnectionCost = 0;
    for (const customer of customers) {
      let minDistanceToCustomer = Infinity;
      for (const facility of facilities) {
        const d = distanceSq(customer, facility);
        if (d < minDistanceToCustomer) {
          minDistanceToCustomer = d;
        }
      }
      totalConnectionCost += Math.sqrt(minDistanceToCustomer); // True Euclidean distance for cost
    }
    // Total cost = connection cost + fixed facility maintenance costs
    return totalConnectionCost + facilities.length * fixedCostPerFacility;
  };

  // Neighborhood: randomly perturb one facility position
  const facilityNeighbor = (facilities) => {
    const newFacilities = facilities.map((f) => ({ ...f }));
      const i = crypto.randomInt(0, numFacilities);
    const moveX = (random() - 0.5) * (bounds.maxX - bounds.minX) * 0.1;
    const moveY = (random() - 0.5) * (bounds.maxY - bounds.minY) * 0.1;

    newFacilities[i].x = Math.max(
      bounds.minX,
      Math.min(bounds.maxX, newFacilities[i].x + moveX),
    );
    newFacilities[i].y = Math.max(
      bounds.minY,
      Math.min(bounds.maxY, newFacilities[i].y + moveY),
    );

    return newFacilities;
  };

  // Initial solution: distribute facilities randomly across bounds
  const initialFacilities = Array.from({ length: numFacilities }, () => ({
    x: bounds.minX + random() * (bounds.maxX - bounds.minX),
    y: bounds.minY + random() * (bounds.maxY - bounds.minY),
  }));

  const saOptions = {
    initialTemperature: 100000,
    coolingRate: 0.999,
    maxIterations: 50000,
    ...options,
  };

  const result = Optimization.simulatedAnnealing(
    initialFacilities,
    facilityEvaluator,
    facilityNeighbor,
    saOptions.initialTemperature,
    saOptions.coolingRate,
    saOptions.maxIterations,
  );

  return result;
};

// Baseline click cost: 1 credit = 1 click
const BASE_CLICK_COST = 1;
/**
 * Creates a multi-objective evaluator to determine optimal Cost Per Click (CPC).
 * @param {object} context - Configuration context.
 * @param {object} context.advertiser - Advertiser paying for the click.
 * @param {object} context.ad - Ad details.
 * @param {Array<object>} context.competingAds - Competing ads targeting the same keywords.
 * @param {object} context.website - Publisher website hosting the ad.
 * @param {object} context.platformParams - Platform commission parameters.
 * @param {number} context.estimatedImpressions - Estimated daily impressions.
 */
Optimization.Operators.createOptimalCPCEvaluator = (context) => {
  const { optimalBaseCommission, optimalBonusFactor } = context.platformParams;
  const websiteQualityScore = (context.website?.relevanceScore || 50) / 100;

  // Effective commission rate for this publisher
  const effectiveCommissionRate = Math.max(
    0,
    optimalBaseCommission - websiteQualityScore * optimalBonusFactor,
  );

  // Demand model: how many clicks can the advertiser afford?
  const advertiserDemand = (cpc) => {
    if (cpc <= 0) return Infinity;
    return (context.advertiser.credits || 0) / cpc;
  };

  // Available inventory supply
  const supply = context.estimatedImpressions || 1; // Fallback to 1 to prevent zero-division

  // Competition factor scales price based on competition density (capped at 2.5)
  const competitionFactor = Math.min(
    2.5,
    1 + context.competingAds.length * 0.1,
  );

  return function cpcFitness(cpcMultiplier) {
    // Final CPC is baseline cost adjusted by optimizer multiplier and competition factor
    const adjustedCPC = BASE_CLICK_COST * cpcMultiplier * competitionFactor;
    if (adjustedCPC < 0.1) return [Infinity, Infinity, Infinity]; // Minimum CPC constraint

    const demand = advertiserDemand(adjustedCPC);
    const estimatedClicks = Math.min(demand, supply);

    // Objective 1: Maximize platform revenue (minimize negative revenue)
    const platformRevenue =
      estimatedClicks * adjustedCPC * effectiveCommissionRate;

    // Objective 2: Maximize advertiser value (clicks delivered, minimize negative)
    const advertiserValue = estimatedClicks;

    // Objective 3: Minimize market imbalance (supply vs demand)
    const marketImbalance = Math.abs(demand - supply);

    return [-platformRevenue, -advertiserValue, marketImbalance];
  };
};

/**
 * Applies competition factor to baseline CPC.
 * @private
 * @param {number} baseCpc - Baseline CPC from genetic algorithm.
 * @param {Array<object>} competingAds - Competing ads.
 * @returns {number} Final adjusted CPC.
 */
function applyCompetitionFactor(baseCpc, competingAds) {
  const competitionFactor = Math.min(
    2.5,
    1 + (competingAds || []).length * 0.1,
  );
  const finalCpc = baseCpc * competitionFactor;
  return Math.max(0.1, finalCpc);
}
/**
 * Solves optimal CPC configuration using a multi-objective genetic algorithm.
 * @param {object} context - Context required for evaluation (advertiser, ad, etc.).
 * @param {object} [options] - Genetic algorithm options.
 * @returns {Array<{solution: number, objectives: number[]}>} Pareto front of optimal CPC solutions.
 */
Optimization.Operators.solveOptimalCPC = (context, options = {}) => {
  const fitnessFunction =
    Optimization.Operators.createOptimalCPCEvaluator(context);

  // An individual is a CPC multiplier scalar
  const createIndividual = () => {
    return 0.5 + random() * 4.5;
  };

  // Crossover: average of parent multipliers
  const crossover = (cpc1, cpc2) => {
    return (cpc1 + cpc2) / 2;
  };

  // Mutation: slight random variation
  const mutate = (cpc) => {
    const newCpc = cpc + (random() - 0.5) * 0.5;
    return Math.max(0.1, newCpc);
  };

  const gaOptions = {
    generations: 50,
    populationSize: 40,
    ...options,
  };

  const paretoFront = Optimization.geneticAlgorithmMultiObjective(
    createIndividual,
    fitnessFunction,
    crossover,
    mutate,
    gaOptions,
  );

  // Apply competition factor to final Pareto solutions
  return paretoFront.map((result) => {
    const cpcMultiplier = result.solution;
    const finalCpc = applyCompetitionFactor(
      BASE_CLICK_COST * cpcMultiplier,
      context.competingAds,
    );
    return {
      ...result,
      solution: Math.max(0.1, finalCpc),
    };
  });
};

/**
 * Creates a multi-objective evaluator to find optimal TTL (Time-To-Live) for a security ticket.
 * @param {object} context - Configuration context.
 * @param {number} context.suspicionScore - User suspicion score (0-100).
 * @returns {function(number): number[]} Fitness function returning [risk, friction] objective scores.
 */
Optimization.Operators.createOptimalTtlEvaluator = ({ suspicionScore }) => {
  // Normalize score to ensure strong weight in risk calculation
  const normalizedScore = Math.max(1, suspicionScore);

  return function ttlFitness(ttl) {
    // Constraints: TTL must be within realistic bounds (5m to 24h)
    if (ttl < 300000 || ttl > 86400000) return [Infinity, Infinity];

    // Objective 1: Minimize Security Risk (product of suspicion score and session duration)
    const risk = normalizedScore * ttl;

    // Objective 2: Minimize UX Friction (inverse of TTL, penalized when suspicion is low)
    const friction = (1 / ttl) * (101 - normalizedScore);

    // Return scaled objectives to balance dimensions
    return [risk / 1e7, friction * 1e9];
  };
};

/**
 * Calculates Benford's Law deviation for a series of numbers.
 * Elevated scores indicate unnatural/synthetic data distributions.
 * @param {Array<number|string>} numbers - Array of numeric samples.
 * @returns {number} Deviation score (0 = perfect match, > 0.15 = suspicious).
 */
Optimization.Operators.benfordTest = (numbers) => {
    if (!Array.isArray(numbers)) {
        return 0;
    }
    const counts = Array(10).fill(0);
    let validCount = 0;

    for (let i = 0; i < numbers.length; i++) {
        let n = numbers[i];
        if (typeof n === 'string') {
            n = parseFloat(n);
        }
        if (typeof n !== 'number' || isNaN(n) || !isFinite(n)) {
            continue;
        }
        const val = Math.abs(n);
        if (val === 0) {
            continue;
        }
        const log = Math.log10(val);
        const factor = Math.pow(10, Math.floor(log));
        let digit = Math.floor(val / factor);
        if (digit >= 1 && digit <= 9) {
            counts[digit]++;
            validCount++;
        }
    }

    if (validCount < 10) {
        return 0; // Insufficient data points for reliable statistical testing
    }

    // Expected Benford's Law distribution for leading digits 1 through 9
    const benfordDistribution = [
        0, // Index 0 unused
        30.1, 17.6, 12.5, 9.7, 7.9, 6.7, 5.8, 5.1, 4.6
    ];

    let totalDeviation = 0;
    for (let i = 1; i <= 9; i++) {
        const observedFrequency = (counts[i] / validCount) * 100;
        const expectedFrequency = benfordDistribution[i];
        totalDeviation += Math.pow(observedFrequency - expectedFrequency, 2);
    }

    // Normalize deviation into an interpretable metric scale
    return Math.sqrt(totalDeviation) / 50;
};




/**
 * Creates a multi-objective evaluator to identify optimal fraud detection thresholds.
 * @param {object} config - Configuration object.
 * @param {Array<object>} config.legitimateClicks - Sample of legitimate click events.
 * @param {Array<object>} config.fraudulentClicks - Sample of identified fraudulent clicks (e.g. honeypots).
 * @returns {function(Array<number>): number[]} Fitness function returning [1 - TPR, FPR].
 */
Optimization.Operators.createFraudThresholdEvaluator = ({
  legitimateClicks,
  fraudulentClicks,
}) => {
  // Helper to compute click coordinate variance for a given fingerprint
  const calculateClickVariance = (clicks) => {
    if (!clicks || clicks.length < 2) return 0;
    const meanX = clicks.reduce((sum, c) => sum + c.clickX, 0) / clicks.length;
    const meanY = clicks.reduce((sum, c) => sum + c.clickY, 0) / clicks.length;
    const variance =
      clicks.reduce(
        (sum, c) =>
          sum + Math.pow(c.clickX - meanX, 2) + Math.pow(c.clickY - meanY, 2),
        0,
      ) / clicks.length;
    return variance;
  };

  // Pre-group click events by fingerprint
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

  return function fraudFitness(solution) {
    const [minTimeToClick, maxClickVariance, minMouseEntropy, minScrollEvents] =
      solution;

    // Logical threshold boundary constraints
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

    let truePositives = 0; // Bots accurately detected
    let falsePositives = 0; // Humans falsely flagged

    // Evaluate fraudulent clicks
    for (const fingerprint in fraudulentGroups) {
      const clicks = fraudulentGroups[fingerprint];
      if (!clicks) continue;
      const variance = calculateClickVariance(clicks);
      const isTooFast = clicks.some((c) => c.timeToClick < minTimeToClick);
      const isTooUniform = variance < maxClickVariance;
      const hasLowEntropy = clicks.some(
        (c) => c.mouseEntropy < minMouseEntropy,
      );
      const hasFewScrolls = clicks.some(
        (c) => c.scrollEvents < minScrollEvents,
      );

      if (isTooFast || isTooUniform || hasLowEntropy || hasFewScrolls) {
        truePositives++;
      }
    }

    // Evaluate legitimate clicks
    for (const fingerprint in legitimateGroups) {
      const clicks = legitimateGroups[fingerprint];
      if (!clicks) continue;
      const variance = calculateClickVariance(clicks);
      if (
        clicks.some(
          (c) =>
            c.timeToClick < minTimeToClick ||
            c.mouseEntropy < minMouseEntropy ||
            c.scrollEvents < minScrollEvents,
        ) ||
        variance < maxClickVariance
      ) {
        falsePositives++;
      }
    }

    const totalFraudulent = Object.keys(fraudulentGroups).length || 1;
    const totalLegitimate = Object.keys(legitimateGroups).length || 1;

    // Objective 1: Maximize fraud detection rate (minimize 1 - TPR)
    const objective1 = 1 - truePositives / totalFraudulent;

    // Objective 2: Minimize false positive rate (minimize FPR)
    const objective2 = falsePositives / totalLegitimate;

    return [objective1, objective2];
  };
};

/**
 * Solves fraud detection optimization by finding the Pareto front of threshold values.
 * @param {object} context - Context containing click datasets.
 * @param {Array<object>} context.legitimateClicks - Sample of legitimate clicks.
 * @param {Array<object>} context.fraudulentClicks - Sample of fraudulent clicks.
 * @param {object} [options] - Genetic algorithm options.
 * @returns {Array<{solution: Array<number>, objectives: number[]}>} Pareto front of [minTimeToClick, maxClickVariance, minMouseEntropy, minScrollEvents].
 */
Optimization.Operators.solveFraudDetection = (context, options = {}) => {
  const fitnessFunction =
    Optimization.Operators.createFraudThresholdEvaluator(context);

  // An individual is a 4-threshold array: [minTimeToClick, maxClickVariance, minMouseEntropy, minScrollEvents]
  const createIndividual = () => {
    const minTimeToClick = 100 + random() * 4900; // between 100ms and 5s
    const maxClickVariance = 1 + random() * 9999; // between 1 and 10000
    const minMouseEntropy = random() * 0.5; // between 0 and 0.5
    const minScrollEvents = crypto.randomInt(0, 10); // between 0 and 10
    return [minTimeToClick, maxClickVariance, minMouseEntropy, minScrollEvents];
  };

  // Crossover: arithmetic mean of parent thresholds
  const crossover = (s1, s2) => {
    return [
      (s1[0] + s2[0]) / 2,
      (s1[1] + s2[1]) / 2,
      (s1[2] + s2[2]) / 2,
      (s1[3] + s2[3]) / 2,
    ];
  };

  // Mutation: slight random perturbation of a single threshold
  const mutate = (solution) => {
    const newSolution = [...solution];
    const i = crypto.randomInt(0, 4);
    // Specific mutation step scales for each dimension
    const mutationFactors = [500, 1000, 0.1, 2];
    const mutationFactor = mutationFactors[i];
    newSolution[i] += (random() - 0.5) * mutationFactor;
    return newSolution;
  };

  const gaOptions = {
    generations: 80,
    populationSize: 60,
    ...options,
  };

  return Optimization.geneticAlgorithmMultiObjective(
    createIndividual,
    fitnessFunction,
    crossover,
    mutate,
    gaOptions,
  );
};

/**
 * Creates a multi-objective evaluator for end-to-end security configuration auto-tuning.
 * Jointly optimizes action thresholds, suspicion weights, and pattern detection parameters.
 * @param {object} context - Configuration context.
 * @param {Array<object>} context.trafficData - Collected traffic logs.
 * @returns {function(object): number[]} Fitness function returning [weighted FPR, weighted FNR].
 */
Optimization.Operators.createFullSecurityConfigEvaluator = (context) => {
  const trafficData = context.trafficData || [];
  const currentConfig = context.currentConfig || null;


  const THREAT_PROFILES = {
    account_takeover: {
      importance: 10.0,
      ux_vs_security_ratio: 0.1, // 10% FPR / 90% FNR (Highest security priority)
      target_threshold: 'block',
      indicators: ['requestPatternScore', 'behaviorScore', 'timeInconsistencyScore', 'clickVarianceScore']
    },
    active_exploitation: {
      importance: 8.0,
      ux_vs_security_ratio: 0.2, // 20% FPR / 80% FNR (Security prioritized)
      target_threshold: 'block',
      indicators: ['honeypotScore', 'headerAnomalyScore']
    },
    mass_scraping: {
      importance: 3.0,
      ux_vs_security_ratio: 0.8, // 80% FPR / 20% FNR (UX prioritized)
      target_threshold: 'low',
      indicators: ['requestPatternScore', 'renderingAnomalyScore', 'clientHintsInconsistencyScore', 'virtualizationScore']
    },
    distributed_botnets: {
      importance: 6.0,
      ux_vs_security_ratio: 0.5, // Balanced
      target_threshold: 'high',
      indicators: ['subnetScore', 'botnetClusterScore', 'ipReputationScore', 'tlsSpoofingScore']
    },
    basic_automation: {
      importance: 5.0,
      ux_vs_security_ratio: 0.4, // 40% FPR / 60% FNR
      target_threshold: 'medium',
      indicators: ['botScore', 'tlsSpoofingScore', 'tcpAnomalyScore', 'virtualizationScore']
    }
  };

  // Immutable baseline anchors to calibrate the suspicion scale
  const STATIC_ANCHORS = [
    {
      type: 'request_passed',
      weight: 15.0,
      vector: {
        historyScore: 0, rotationScore: 0, headerAnomalyScore: 0, requestPatternScore: 0,
        inconsistencyScore: 0, behaviorScore: 0, honeypotScore: 0, botScore: 0,
        crossLayerInconsistencyScore: 0, timeInconsistencyScore: 0, tlsSpoofingScore: 0,
        clickVarianceScore: 0, clientHintsInconsistencyScore: 0, subnetScore: 0,
        ipReputationScore: 0, botnetClusterScore: 0, tcpAnomalyScore: 0,
        quicAnomalyScore: 0, renderingAnomalyScore: 0, threatIntelScore: 0,
        virtualizationScore: 0
      }
    },
    {
      type: 'request_blocked',
      weight: 15.0,
      vector: {
        historyScore: 100, rotationScore: 100, headerAnomalyScore: 80, requestPatternScore: 100,
        inconsistencyScore: 100, behaviorScore: 0, honeypotScore: 100, botScore: 100,
        crossLayerInconsistencyScore: 80, timeInconsistencyScore: 100, tlsSpoofingScore: 100,
        clickVarianceScore: 100, clientHintsInconsistencyScore: 90, subnetScore: 100,
        ipReputationScore: 100, botnetClusterScore: 100, tcpAnomalyScore: 100,
        quicAnomalyScore: 100, renderingAnomalyScore: 100, threatIntelScore: 100,
        virtualizationScore: 100
      }
    },
    {
      type: 'request_passed', // Clean human profile with minor noise (must remain below alert threshold, e.g. < 20)
      weight: 10.0,
      vector: {
        historyScore: 15, rotationScore: 10, headerAnomalyScore: 20, requestPatternScore: 15,
        inconsistencyScore: 10, behaviorScore: 15, honeypotScore: 0, botScore: 0,
        crossLayerInconsistencyScore: 10, timeInconsistencyScore: 10, tlsSpoofingScore: 10,
        clickVarianceScore: 0, clientHintsInconsistencyScore: 10, subnetScore: 5,
        ipReputationScore: 5, botnetClusterScore: 5, tcpAnomalyScore: 10,
        quicAnomalyScore: 10, renderingAnomalyScore: 5, threatIntelScore: 0,
        virtualizationScore: 0
      }
    },
    {
      type: 'challenge_issued', // Stealth automated bot profile (must be challenged, e.g. > 35)
      weight: 10.0,
      vector: {
        historyScore: 20, rotationScore: 20, headerAnomalyScore: 20, requestPatternScore: 40,
        inconsistencyScore: 30, behaviorScore: 30, honeypotScore: 0, botScore: 0,
        crossLayerInconsistencyScore: 20, timeInconsistencyScore: 20, tlsSpoofingScore: 30,
        clickVarianceScore: 20, clientHintsInconsistencyScore: 20, subnetScore: 15,
        ipReputationScore: 15, botnetClusterScore: 20, tcpAnomalyScore: 30,
        quicAnomalyScore: 20, renderingAnomalyScore: 20, threatIntelScore: 0,
        virtualizationScore: 30
      }
    }
  ];

  return function fullConfigFitness(config) {
    const threatStats = {};
    for (const threatName in THREAT_PROFILES) {
      threatStats[threatName] = { fp: 0, fn: 0, totalHumans: 0, totalBots: 0 };
    }

    let maxHumanScore = 0;
    let minBotScore = 100;

    const calculateScore = (log) => {
      let score = 0;
      for (const key in config.weights) {
        score += (log.vector?.[key] || 0) * config.weights[key];
      }
      return score;
    };

    const confidenceWeights = {
      request_passed: 0.7,
      challenge_issued: 1.0,
      request_blocked: 1.0,
      challenge_solved: 1.5,
      trap_triggered: 2.0,
    };

    // 1. Evaluate on real traffic logs
    for (const log of trafficData) {
      const weight = log.weight || 1.0;
      const confidence = (confidenceWeights[log.type] || 1.0) * weight;
      const isLikelyBot = log.type === 'challenge_issued' || log.type === 'request_blocked' || log.type === 'trap_triggered';
      const isLikelyHuman = log.type === 'request_passed' || log.type === 'challenge_solved';

      const score = calculateScore(log);

      if (isLikelyBot) {
        minBotScore = Math.min(minBotScore, score);
      } else if (isLikelyHuman) {
        maxHumanScore = Math.max(maxHumanScore, score);
      }

      for (const threatName in THREAT_PROFILES) {
        const profile = THREAT_PROFILES[threatName];
        let threatActivity = 0.0;
        for (const indicator of profile.indicators) {
          threatActivity += (log.vector?.[indicator] || 0.0);
        }
        if (threatActivity <= 0.0) {
          continue;
        }
        const effectiveConfidence = confidence * (threatActivity / 100.0);
        const targetThreshold = config.thresholds[profile.target_threshold] || 20;

        if (isLikelyBot) {
          threatStats[threatName].totalBots += effectiveConfidence;
          if (score < targetThreshold) {
            threatStats[threatName].fn += effectiveConfidence;
          }
        } else if (isLikelyHuman) {
          threatStats[threatName].totalHumans += effectiveConfidence;
          if (score >= targetThreshold) {
            threatStats[threatName].fp += effectiveConfidence;
          }
        }
      }

    }
    // 2. Evaluate against immutable baseline anchors to stabilize scale
    for (const anchor of STATIC_ANCHORS) {
      const score = calculateScore(anchor);
      const weight = anchor.weight;
      const isBot = anchor.type === 'request_blocked' || anchor.type === 'challenge_issued';

      if (isBot){
        minBotScore = Math.min(minBotScore, score);
      } else {
        maxHumanScore = Math.max(maxHumanScore, score);
      }

      for (const threatName in THREAT_PROFILES) {
        const profile = THREAT_PROFILES[threatName];
        let threatActivity = 0.0;
        for (const indicator of profile.indicators) {
          threatActivity += (anchor.vector?.[indicator] || 0.0);
        }
        if (threatActivity <= 0.0) {
          continue;
        }
        const effectiveWeight = weight * (threatActivity / 100.0);
        const targetThreshold = config.thresholds[profile.target_threshold] || 20;

        if (isBot) {
          threatStats[threatName].totalBots += effectiveWeight;
          if (score < targetThreshold) {
            threatStats[threatName].fn += effectiveWeight * 10; // Strict punitive penalty
          }
        } else {
          threatStats[threatName].totalHumans += effectiveWeight;
          if (score >= targetThreshold) {
            threatStats[threatName].fp += effectiveWeight * 10; // Strict punitive penalty
          }
        }
      }
    }
    let weightedFpr = 0;
    let weightedFnr = 0;
    let totalImportance = 0;

    for (const threatName in THREAT_PROFILES) {
      totalImportance += THREAT_PROFILES[threatName].importance;
    }

    for (const threatName in THREAT_PROFILES) {
      const profile = THREAT_PROFILES[threatName];
      const stats = threatStats[threatName];

      const fpr = stats.totalHumans > 0 ? stats.fp / stats.totalHumans : 0;
      const fnr = stats.totalBots > 0 ? stats.fn / stats.totalBots : 0;

      const importanceWeight = profile.importance / totalImportance;
      const uxRatio = profile.ux_vs_security_ratio;
      const secRatio = 1.0 - uxRatio;

      weightedFpr += fpr * importanceWeight * uxRatio;
      weightedFnr += fnr * importanceWeight * secRatio;
    }

    // 3. L2 drift penalty against baseline configuration
    let regularizationPenalty = 0;
    if (currentConfig && currentConfig.weights) {
      for (const key in config.weights) {
        const originalVal = currentConfig.weights[key] || 0;
        regularizationPenalty += Math.pow(config.weights[key] - originalVal, 2);
      }
    }

    // 4. Maximizing separation margin (SVM-like Margin Loss)
    const marginOverlap = Math.max(0, maxHumanScore - minBotScore);
    const marginPenalty = marginOverlap / 100;

    const obj1 = weightedFpr + (regularizationPenalty * 0.05);
    const obj2 = weightedFnr + marginPenalty;
    return [obj1, obj2];
  };
};

/**
 * Solves the full security configuration auto-tuning problem.
 * @param {object} context - Context containing traffic event logs.
 * @param {object} [options] - Genetic algorithm options.
 * @returns {Array<{solution: object, objectives: number[]}>} Pareto front of optimal security configurations.
 */ // eslint-disable-line max-len
Optimization.Operators.solveFullSecurityTuning = (context, options = {}) => {
    const fitnessFunction = Optimization.Operators.createFullSecurityConfigEvaluator(context);
    const currentConfig = context.currentConfig || {};
    const baseWeights = currentConfig.weights || {
      historyScore: 0.3,
      rotationScore: 0.5,
      headerAnomalyScore: 0.1,
      requestPatternScore: 0.6,
      inconsistencyScore: 0.8,
      honeypotScore: 1.0,
      behaviorScore: 0.7,
      crossLayerInconsistencyScore: 0.4,
      timeInconsistencyScore: 0.9,
      tlsSpoofingScore: 0.8,
      botScore: 1.0,
      subnetScore: 0.4,
      ipReputationScore: 0.5,
      botnetClusterScore: 0.6,
      tcpAnomalyScore: 0.8,
      quicAnomalyScore: 0.8,
      renderingAnomalyScore: 0.8,
      threatIntelScore: 1.0,
      virtualizationScore: 0.8
    };

    // An "individual" is a complete security configuration object
    const createIndividual = () => ({
        thresholds: {
            low: 15 + random() * 20, // 15-35
            medium: 40 + random() * 25,
            high: 70 + random() * 20,
          block: 90 + random() * 9,
        },
        weights: (() => {
          const w = {};
          for (const key in baseWeights) {
            w[key] = baseWeights[key] * (0.75 + random() * 0.5); // +/- 25%
          }
          return w;
        })(),
        patterns: {
            velocityThreshold: 100 + random() * 400,
            velocityWeight: 10 + random() * 40,
            burstThreshold: 300 + random() * 700,
            burstWeight: 20 + random() * 40,
            scrapeThreshold: 500 + random() * 1000,
            scrapeWeight: 15 + random() * 35,
            sequenceLength: 3 + crypto.randomInt(0, 3),
            sequenceWeight: 20 + random() * 50,
            regularityThreshold: 50 + random() * 200,
            regularityWeight: 20 + random() * 40,
            decayFactor: 0.85 + random() * 0.14,
            inactivityReset: 15000 + random() * 45000,
        }
    });

    // Crossover and mutation operators for complex structured configurations
    const crossover = (c1, c2) => {
        const child = JSON.parse(JSON.stringify(c1)); // Deep copy
        // Crossover across each parameter section
        for (const key in child.thresholds) {
            child.thresholds[key] = (c1.thresholds[key] + c2.thresholds[key]) / 2;
        }
        for (const key in child.weights) {
          child.weights[key] = (c1.weights[key] + c2.weights[key]) / 2;
        }
        for (const key in child.patterns) {
            child.patterns[key] = (c1.patterns[key] + c2.patterns[key]) / 2;
        }
        return child;
    };

    const mutate = (c, currentConfig) => {
        const newConfig = JSON.parse(JSON.stringify(c));

        // Weighted section selection: prioritize 'patterns' and 'weights'
        // as they have a more direct impact on detection accuracy than thresholds.
        const sections = [
          { name: 'patterns', weight: 0.50 },
          { name: 'thresholds', weight: 0.25 },
          { name: 'weights', weight: 0.25 }
        ];
        const rand = random();
        let cumulativeWeight = 0;
        let sectionToMutate = 'patterns'; // Fallback
        for (const section of sections) {
            cumulativeWeight += section.weight;
            if (rand < cumulativeWeight) {
                sectionToMutate = section.name;
                break;
            }
        }

        const keys = Object.keys(newConfig[sectionToMutate]);
        const keyToMutate = keys[crypto.randomInt(0, keys.length)];

    
        // Ensure mutated parameters stay within reasonable bounds
        if (sectionToMutate === 'weights') {
          newConfig[sectionToMutate][keyToMutate] = Math.max(0.05, Math.min(1.5, newConfig[sectionToMutate][keyToMutate] + (random() - 0.5) * 0.1));
        } else if (sectionToMutate === 'thresholds') {
          newConfig[sectionToMutate][keyToMutate] = Math.round(newConfig[sectionToMutate][keyToMutate] + (random() - 0.5) * 5.0);
        } else {
          if (keyToMutate === 'decayFactor') {
            newConfig.patterns.decayFactor = Math.max(0.8, Math.min(0.999, newConfig.patterns.decayFactor + (random() - 0.5) * 0.05));
          } else if (keyToMutate.includes('Threshold') || keyToMutate.includes('Reset')) {
            newConfig.patterns[keyToMutate] = Math.max(50, newConfig.patterns[keyToMutate] + (random() - 0.5) * 50.0);
          }
        }
    
        // Maximum drift constraint (+/- 30% relative to current reference configuration)
        if (currentConfig && currentConfig[sectionToMutate] && currentConfig[sectionToMutate][keyToMutate] !== undefined) {
            const originalValue = currentConfig[sectionToMutate][keyToMutate];
            if (typeof originalValue === 'number' && originalValue !== 0) { // Avoid division by zero or locking zeroes
                const minAllowed = originalValue * 0.7; // -30%
                const maxAllowed = originalValue * 1.3; // +30%
                newConfig[sectionToMutate][keyToMutate] = Math.max(minAllowed, Math.min(maxAllowed, newConfig[sectionToMutate][keyToMutate]));
            }
        }

        return newConfig;
    };

    return Optimization.geneticAlgorithmMultiObjective(
        createIndividual,
        fitnessFunction,
        crossover,
        (c) => mutate(c, context.currentConfig), // Pass currentConfig to mutation function
        { generations: 50, populationSize: 50, ...options }
    );
};

export { Optimization };

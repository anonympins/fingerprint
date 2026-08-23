/**
 * @file @/library.js
 * @description Une bibliothèque d'outils basés sur le principe fondamental de la dichotomie (division en deux).
 * Inclut des algorithmes pour les tableaux triés, des structures de données et des solveurs de problèmes conceptuels.
 *
 * @template T
 * @callback Comparator
 * @param {T} element - L'élément du tableau.
 * @param {any} target - La valeur cible.
 * @returns {number} -1 si element < target, 0 si element == target, 1 si element > target.
 *
 */

import { Worker } from "worker_threads";
import os from "os";

const Optimization = {
  // eslint-disable-line no-unused-vars
  /**
   * Trouve une bonne solution à un problème d'optimisation en utilisant le Recuit Simulé.
   * Cet algorithme est efficace pour trouver un optimum global dans un grand espace de recherche
   * avec de nombreux optima locaux (plusieurs "pics" ou "vallées").
   * @template TSolution - Le type de la solution (peut être un nombre, un tableau, un objet...).
   * @param {TSolution} initialSolution - Le point de départ de la recherche.
   * @param {function(TSolution): number} evaluator - Fonction qui évalue une solution. L'objectif est de minimiser ce score.
   * @param {function(TSolution): TSolution} neighbor - Fonction qui génère une solution "voisine" aléatoire.
   * @param {number} [initialTemperature=1000] - La température de départ.
   * @param {number} [coolingRate=0.995] - Le taux de refroidissement (proche de 1).
   * @param {number} [maxIterations=10000] - Le nombre total d'itérations.
   * @returns {{solution: TSolution, energy: number}} Le meilleur couple solution/score trouvé.
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

      // Calcule la probabilité d'accepter une moins bonne solution.
      const acceptanceProbability = Math.exp(
        (currentEnergy - newEnergy) / temperature,
      );

      // Décide si on se déplace vers la nouvelle solution.
      if (newEnergy < currentEnergy || Math.random() < acceptanceProbability) {
        currentSolution = newSolution;
        currentEnergy = newEnergy;
      }

      // Met à jour la meilleure solution trouvée jusqu'à présent.
      if (currentEnergy < bestEnergy) {
        bestSolution = currentSolution;
        bestEnergy = currentEnergy;
      }

      // Refroidit la température.
      temperature *= coolingRate;
    }

    return { solution: bestSolution, energy: bestEnergy };
  },

  /**
   * Résout un problème d'optimisation en utilisant un Algorithme Génétique.
   * Idéal pour les problèmes complexes où l'espace de recherche est vaste et non-linéaire.
   * @template TChromosome - Le type de la solution (un "chromosome").
   * @param {function(): TChromosome} createIndividual - Fonction pour créer un individu aléatoire.
   * @param {function(TChromosome): number} fitnessFunction - Évalue un individu. L'objectif est de MINIMISER ce score.
   * @param {function(TChromosome, TChromosome): TChromosome} crossover - Croise deux parents pour créer un enfant.
   * @param {function(TChromosome): TChromosome} mutate - Applique une mutation aléatoire à un individu.
   * @param {object} options - Options de l'algorithme.
   * @param {number} [options.populationSize=100] - Taille de la population.
   * @param {number} [options.generations=100] - Nombre de générations à simuler.
   * @param {number} [options.crossoverRate=0.8] - Probabilité de croisement.
   * @param {number} [options.mutationRate=0.1] - Probabilité de mutation.
   * @param {function} [options.selectionFunction] - Fonction de sélection des parents. Par défaut, un tournoi.
   * @param {boolean} [options.returnPopulation=false] - Si true, retourne la population finale au lieu du meilleur individu.
   * @returns {{solution: TChromosome, fitness: number}} Le meilleur individu trouvé.
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

    // 1. Initialisation
    // La population est un tableau d'objets { chromosome, fitness }
    // La fitness est calculée une seule fois par individu.
    let population = Array.from({ length: populationSize }, () => {
      const chromosome = createIndividual();
      return { chromosome, fitness: fitnessFunction(chromosome) };
    });

    // Trier la population initiale pour trouver le meilleur
    population.sort((a, b) => a.fitness - b.fitness);
    let bestOverall = population[0];

    // 2. Boucle des générations
    for (let gen = 0; gen < generations; gen++) {
      const newPopulation = [];

      // Élitisme : le meilleur individu de la génération précédente est conservé.
      // Il est déjà à l'index 0 grâce au tri à la fin de la boucle précédente.
      newPopulation.push(population[0]);

      while (newPopulation.length < populationSize) {
        // 3. Sélection
        const parent1 = selectionFunction(population);
        const parent2 = selectionFunction(population);

        let offspringChromosome;
        // 4. Croisement
        if (Math.random() < crossoverRate) {
          offspringChromosome = crossover(
            parent1.chromosome,
            parent2.chromosome,
          );
        } else {
          offspringChromosome = parent1.chromosome;
        }

        // 5. Mutation
        if (Math.random() < mutationRate) {
          offspringChromosome = mutate(offspringChromosome);
        }

        // S'assurer que les opérateurs ont bien retourné un individu
        if (offspringChromosome) {
          newPopulation.push({
            chromosome: offspringChromosome,
            fitness: fitnessFunction(offspringChromosome),
          });
        } else {
          // Si le croisement/mutation échoue, on réinsère un parent pour garder la taille de la population
          newPopulation.push(parent1);
        }
      }

      population = newPopulation;

      // Trier la nouvelle population pour la prochaine génération (élitisme) et la mise à jour du meilleur
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
   * Exécute un solveur stochastique plusieurs fois et retourne le meilleur résultat.
   * C'est une méta-heuristique pour augmenter la probabilité de trouver un optimum global
   * en échange d'un temps de calcul plus long.
   * @param {function(): {solution: any, energy?: number, fitness?: number}} solverFunction - Une fonction qui, lorsqu'elle est appelée, exécute un algorithme d'optimisation et retourne un objet résultat.
   * @param {number} numCycles - Le nombre de fois où exécuter le solveur.
   * @param {boolean} [logProgress=false] - Si true, affiche le score de chaque cycle dans la console.
   * @returns {{bestResult: object, stats: {scores: Array<number>, average: number, stdDev: number}}} Le meilleur résultat et des statistiques sur les exécutions.
   */
  runMultiple(solverFunction, numCycles, logProgress = false) {
    let bestResult = null;
    const allScores = [];

    for (let i = 0; i < numCycles; i++) {
      const currentResult = solverFunction();

      // Gère les résultats du Recuit Simulé (energy) et des Algorithmes Génétiques (fitness).
      // On suppose que pour les deux, un score plus bas est meilleur.
      const currentScore =
        currentResult.energy !== undefined
          ? currentResult.energy
          : currentResult.fitness;
      allScores.push(currentScore);

      if (logProgress) {
        console.log(
          `   -> Cycle ${i + 1}/${numCycles}: Score trouvé = ${currentScore.toFixed(2)}`,
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

    // Calcul des statistiques
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
   * Trouve un minimum local d'une fonction en utilisant l'algorithme de Descente de Gradient.
   * Nécessite que la fonction soit différentiable et que son gradient soit connu.
   * @template TSolution - Le type de la solution (nombre ou tableau de nombres).
   * @param {TSolution} initialSolution - Le point de départ.
   * @param {function(TSolution): TSolution} gradientFunction - Fonction qui calcule le gradient au point donné.
   * @param {object} options - Options de l'algorithme.
   * @param {number} [options.learningRate=0.01] - Le "pas" de la descente.
   * @param {number} [options.maxIterations=1000] - Nombre d'itérations.
   * @param {number} [options.tolerance=1e-6] - Seuil pour arrêter si la solution ne change plus beaucoup.
   * @returns {TSolution} La solution (minimum local) trouvée.
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
        // Cas d'une seule variable (nombre)
        const prevSolution = currentSolution;
        currentSolution -= learningRate * gradient;
        if (Math.abs(prevSolution - currentSolution) < tolerance) break;
      }
    }
    return currentSolution;
  },

  /**
   * Exécute un solveur stochastique plusieurs fois en parallèle en utilisant un pool de workers pour éviter de surcharger le système.
   * @param {string} solverName - Le nom de la fonction solveur à appeler dans `Optimization.Operators`.
   * @param {Array<any>} baseSolverArgs - Les arguments de base à passer au solveur (sans les données aléatoires qui seront générées par worker).
   * @param {number} numCycles - Le nombre total de cycles à exécuter.
   * @param {boolean} [logProgress=false] - Si true, affiche la progression dans la console.
   * @param {object} [options={}] - Options pour la parallélisation.
   * @param {number} [options.concurrency] - Le nombre de workers à utiliser en parallèle. Par défaut, le nombre de cœurs CPU.
   * @returns {Promise<{bestResult: object, stats: {scores: Array<number>, average: number, stdDev: number}}>} Le meilleur résultat et des statistiques.
   */
  async runMultipleParallel(
    solverName,
    baseSolverArgs,
    numCycles,
    logProgress = false,
    options = {},
  ) {
    const concurrency = options.concurrency || os.cpus().length;
    if (logProgress) {
      console.log(
        `   (Utilisation d'un pool de ${concurrency} workers pour ${numCycles} cycles)`,
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
          solverArgs: [
            // Chaque worker génère son propre jeu de données aléatoires pour garantir l'indépendance des cycles.
            Array.from({ length: 50 }, () => ({
              x: Math.random() * 100,
              y: Math.random() * 100,
            })),
            ...baseSolverArgs,
          ],
        };

        const result = await new Promise((resolve, reject) => {
          const worker = new Worker("./worker.js", { workerData });
          worker.on("message", resolve);
          worker.on("error", reject);
          worker.on("exit", (code) => {
            if (code !== 0)
              reject(
                new Error(`Worker ${workerId} a terminé avec le code ${code}`),
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

    // Le reste de la logique est identique à `runMultiple`
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
 * Détermine si la solution A domine la solution B en multi-objectifs (problème de minimisation).
 * @private
 * @param {number[]} objectivesA - Tableau des scores des objectifs pour la solution A.
 * @param {number[]} objectivesB - Tableau des scores des objectifs pour la solution B.
 * @returns {boolean} - True si A domine B.
 */
function paretoDominates(objectivesA, objectivesB) {
  let aIsBetterInOne = false;
  for (let i = 0; i < objectivesA.length; i++) {
    if (objectivesA[i] > objectivesB[i]) {
      return false; // A est pire sur au moins un objectif, donc ne domine pas.
    }
    if (objectivesA[i] < objectivesB[i]) {
      aIsBetterInOne = true; // A est strictement meilleur sur au moins un objectif.
    }
  }
  return aIsBetterInOne; // A domine B si elle n'est jamais pire et au moins une fois meilleure.
}

/**
 * Trie une population en fronts de Pareto non-dominés (inspiré de NSGA-II).
 * @private
 * @param {Array<{individual: any, objectives: number[]}>} populationWithObjectives - La population à trier.
 * @returns {Array<Array<{individual: any, objectives: number[]}>>} - Un tableau de fronts, où le premier est le meilleur.
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
 * Calcule la distance de promiscuité (crowding distance) pour un front, afin de préserver la diversité.
 * @private
 * @param {Array<{individual: any, objectives: number[]}>} front - Le front de Pareto.
 */
function calculateCrowdingDistance(front) {
  if (front.length === 0) return;
  front.forEach((p) => (p.crowdingDistance = 0));
  const numObjectives = front[0].objectives.length;

  for (let i = 0; i < numObjectives; i++) {
    front.sort((a, b) => a.objectives[i] - b.objectives[i]);
    const minObj = front[0].objectives[i];
    const maxObj = front[front.length - 1].objectives[i];

    // Les solutions aux extrémités sont cruciales, on leur donne une distance infinie.
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
 * Algorithme génétique multi-objectifs (inspiré de NSGA-II) pour trouver un front de Pareto.
 * @param {function(): any} createIndividual - Fonction qui crée un individu aléatoire.
 * @param {function(any): number[]} fitnessFunction - Fonction qui évalue un individu et retourne un tableau d'objectifs à MINIMISER.
 * @param {function(any, any): any} crossover - Fonction de croisement.
 * @param {function(any): any} mutate - Fonction de mutation.
 * @param {object} options - Options de l'algorithme.
 * @returns {Array<{solution: any, objectives: number[]}>} Le premier front de Pareto (l'ensemble des meilleures solutions de compromis).
 */
Optimization.geneticAlgorithmMultiObjective = function (
  createIndividual,
  fitnessFunction,
  crossover,
  mutate,
  options = {},
) {
  const {
    generations = 100,
    populationSize = 50,
    mutationRate = 0.1,
  } = options;

  let population = Array.from({ length: populationSize }, () => ({
    individual: createIndividual(),
  }));
  population.forEach((p) => (p.objectives = fitnessFunction(p.individual)));

  for (let gen = 0; gen < generations; gen++) {
    // 1. Créer une population d'enfants
    const offspring = [];
    for (let i = 0; i < populationSize; i++) {
      // Sélection simple pour l'exemple
      const parent1 = population[Math.floor(Math.random() * population.length)];
      const parent2 = population[Math.floor(Math.random() * population.length)];
      let childIndividual = crossover(parent1.individual, parent2.individual);
      if (Math.random() < mutationRate) {
        childIndividual = mutate(childIndividual);
      }
      const child = { individual: childIndividual };
      child.objectives = fitnessFunction(child.individual);
      offspring.push(child);
    }

    // 2. Combiner parents et enfants
    const combinedPopulation = [...population, ...offspring];

    // 3. Trier la population combinée en fronts
    const fronts = nonDominatedSort(combinedPopulation);

    // 4. Construire la nouvelle population
    const newPopulation = [];
    for (const front of fronts) {
      if (newPopulation.length + front.length <= populationSize) {
        newPopulation.push(...front);
      } else {
        // Si le front est trop grand, on utilise la distance de promiscuité pour choisir les individus les plus diversifiés.
        calculateCrowdingDistance(front);
        front.sort((a, b) => b.crowdingDistance - a.crowdingDistance); // Trier par distance décroissante
        const remaining = populationSize - newPopulation.length;
        newPopulation.push(...front.slice(0, remaining));
        break;
      }
    }
    population = newPopulation;
  }

  // Retourner le premier front de la population finale
  const finalFronts = nonDominatedSort(population);
  const bestFront = finalFronts.length > 0 ? finalFronts[0] : [];

  // Filtrer le front pour ne garder que les solutions avec des objectifs uniques
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
 * Utilitaires pour les problèmes d'optimisation.
 */
Optimization.Utils = {
    /** Calcule la distance euclidienne entre deux points (villes). */
    distance: (city1, city2) => Math.sqrt(Math.pow(city1.x - city2.x, 2) + Math.pow(city1.y - city2.y, 2)),

    /** Évalue la distance totale d'un chemin TSP donné. */
    evaluatePathDistance: (cities, path) => {
        let totalDistance = 0;
        for (let i = 0; i < path.length - 1; i++) {
            totalDistance += Optimization.Utils.distance(cities[path[i]], cities[path[i + 1]]);
        }
        totalDistance += Optimization.Utils.distance(cities[path[path.length - 1]], cities[path[0]]); // Retour au départ
        return totalDistance;
    }
};

/**
 * Algorithme d'optimisation CMA-ES (Covariance Matrix Adaptation Evolution Strategy).
 * C'est un algorithme de pointe pour l'optimisation en boîte noire de fonctions non-linéaires et non-convexes.
 * Il est particulièrement efficace pour les problèmes avec des variables continues.
 * @param {function(Array<number>): number} fitnessFunction - La fonction à MINIMISER.
 * @param {Array<number>} initialSolution - Le point de départ de la recherche (un vecteur de nombres).
 * @param {number} initialStepSize - La taille de pas initiale (sigma).
 * @param {object} [options={}] - Options de l'algorithme.
 * @param {number} [options.maxGenerations=100] - Nombre maximum de générations.
 * @param {number} [options.populationSize] - Taille de la population (lambda). Calculée par défaut si non fournie.
 * @param {number} [options.tolerance=1e-6] - Seuil de tolérance pour l'arrêt précoce.
 * @returns {{solution: Array<number>, fitness: number}} La meilleure solution trouvée.
 */
Optimization.cmaes = function(fitnessFunction, initialSolution, initialStepSize, options = {}) {
    const n = initialSolution.length; // Dimension du problème

    // --- Paramètres de l'algorithme (stratégie) ---
    const { maxGenerations = 100, tolerance = 1e-6 } = options;
    const populationSize = options.populationSize || (4 + Math.floor(3 * Math.log(n))); // Lambda
    const mu = Math.floor(populationSize / 2); // Nombre de parents pour la recombinaison

    // Poids de recombinaison
    let weights = Array.from({ length: mu }, (_, i) => Math.log(mu + 0.5) - Math.log(i + 1));
    const sumWeights = weights.reduce((s, w) => s + w, 0);
    weights = weights.map(w => w / sumWeights);
    const muEff = 1 / weights.reduce((s, w) => s + w * w, 0);

    // Paramètres d'adaptation
    const cc = (4 + muEff / n) / (n + 4 + 2 * muEff / n);
    const cs = (muEff + 2) / (n + muEff + 5);
    const c1 = 2 / (Math.pow(n + 1.3, 2) + muEff);
    const cmu = Math.min(1 - c1, 2 * (muEff - 2 + 1 / muEff) / (Math.pow(n + 2, 2) + muEff));
    const damps = 1 + 2 * Math.max(0, Math.sqrt((muEff - 1) / (n + 1)) - 1) + cs;

    // --- Variables d'état dynamiques ---
    let mean = [...initialSolution]; // Le centre de la distribution de recherche
    let stepSize = initialStepSize; // Sigma
    let C = Array.from({ length: n }, (_, i) => Array.from({ length: n }, (_, j) => (i === j ? 1 : 0))); // Matrice de covariance
    let pc = Array(n).fill(0); // Chemin d'évolution pour C
    let ps = Array(n).fill(0); // Chemin d'évolution pour sigma

    let bestFitness = Infinity;
    let bestSolution = null;

    // Fonction pour la décomposition de Cholesky (simplifiée, pour matrice symétrique définie positive)
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
                    if (val < 0) return null; // Non définie positive
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
        // 1. Échantillonnage de la nouvelle population
        const population = [];
        const arx = []; // Vecteurs de recherche
        const L = cholesky(C);
        if (!L) {
            console.warn("[CMA-ES] La matrice de covariance n'est plus définie positive. Arrêt.");
            break;
        }

        for (let i = 0; i < populationSize; i++) {
            const z = Array.from({ length: n }, () => Math.random() * 2 - 1); // Vecteur normal standard
            const y = Array(n).fill(0); // z transformé par L
            for (let r = 0; r < n; r++) {
                for (let c = 0; c < n; c++) {
                    y[r] += L[r][c] * z[c];
                }
            }
            arx.push(y);
            const individual = mean.map((m, j) => m + stepSize * y[j]);
            population.push({ individual, fitness: fitnessFunction(individual) });
        }

        // 2. Trier et sélectionner les meilleurs
        population.sort((a, b) => a.fitness - b.fitness);
        const parents = population.slice(0, mu);

        if (parents[0].fitness < bestFitness) {
            bestFitness = parents[0].fitness;
            bestSolution = parents[0].individual;
        }

        // 3. Mise à jour des variables d'état
        const oldMean = [...mean];
        const y_w = Array(n).fill(0);
        for (let j = 0; j < n; j++) {
            for (let i = 0; i < mu; i++) {
                const parentIndex = population.indexOf(parents[i]);
                y_w[j] += weights[i] * arx[parentIndex][j];
            }
        }
        mean = oldMean.map((m, i) => m + stepSize * y_w[i]);

        // 4. Adaptation des chemins d'évolution
        const C_inv_sqrt = cholesky(C); // Simplification, devrait être l'inverse de la racine
        const C_inv_sqrt_y_w = y_w; // Approximation
        ps = ps.map((p, i) => (1 - cs) * p + Math.sqrt(cs * (2 - cs) * muEff) * C_inv_sqrt_y_w[i]);
        
        const hsig = Math.sqrt(ps.reduce((s, v) => s + v*v, 0)) / (1 - Math.pow(1 - cs, 2 * (gen + 1))) / n < 1.4 + 2 / (n + 1);
        pc = pc.map((p, i) => (1 - cc) * p + (hsig ? Math.sqrt(cc * (2 - cc) * muEff) * y_w[i] : 0));

        // 5. Adaptation de la matrice de covariance C
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

        // 6. Adaptation de la taille de pas (sigma)
        stepSize *= Math.exp((cs / damps) * (Math.sqrt(ps.reduce((s, v) => s + v*v, 0)) / Math.sqrt(n) - 1));
    }

    return { solution: bestSolution, fitness: bestFitness };
};

/**
 * @namespace Optimization.Operators
 * @description Une bibliothèque de "fabriques d'évaluateurs" pour des problèmes d'optimisation complexes,
 * souvent multidimensionnels, à utiliser avec les algorithmes de `Optimization` (Recuit Simulé, Algorithmes Génétiques, etc.).
 */
Optimization.Operators = {}; // Création du namespace

/**
 * Crée une fonction de sélection par tournoi pour un algorithme génétique.
 * @param {object} [options] - Options pour le tournoi.
 * @param {number} [options.size=5] - Le nombre de participants par tournoi.
 * @returns {function(Array<{chromosome: any, fitness: number}>): {chromosome: any, fitness: number}} Une fonction de sélection.
 */
Optimization.Operators.createTournamentSelection = (options = {}) => {
  const tournamentSize = options.size || 5;

  return function tournamentSelection(population) {
    let best = null;

    for (let i = 0; i < tournamentSize; i++) {
      const individual =
        population[Math.floor(Math.random() * population.length)];
      if (!best || individual.fitness < best.fitness) {
        best = individual;
      }
    }
    // Retourne le meilleur trouvé. Dans le pire des cas (tous les scores sont Infinity),
    // on retourne le premier candidat sélectionné au lieu de null.
    if (!best) {
      return population[Math.floor(Math.random() * population.length)];
    }
    return best;
  };
};

/**
 * Crée une matrice de covariance à partir de coefficients de corrélation déclarés.
 * C'est une manière plus intuitive de définir les relations de risque entre les actifs.
 * @param {object} config - L'objet de configuration.
 * @param {Array<{name: string, volatility: number}>} config.assets - La liste des actifs avec leur volatilité.
 * @param {Array<{assets: [string, string], correlation: number}>} config.correlations - Une liste de relations de corrélation.
 * @returns {Array<Array<number>>} La matrice de covariance calculée.
 */
Optimization.Operators.createCovarianceMatrixFromCorrelations = ({
  assets,
  correlations,
}) => {
  const n = assets.length;
  const matrix = Array.from({ length: n }, () => Array(n).fill(0));

  // Créer un map pour un accès rapide aux infos des actifs par leur nom.
  const assetInfo = new Map();
  assets.forEach((asset, index) => {
    assetInfo.set(asset.name, { index, volatility: asset.volatility });
  });

  // 1. Remplir la diagonale avec les variances (volatilité^2)
  for (let i = 0; i < n; i++) {
    const variance = Math.pow(assets[i].volatility, 2);
    matrix[i][i] = variance;
  }

  // 2. Remplir les autres cellules avec les covariances calculées
  for (const corr of correlations) {
    const [nameA, nameB] = corr.assets;
    if (!assetInfo.has(nameA) || !assetInfo.has(nameB)) {
      console.warn(
        `Avertissement: L'un des actifs [${nameA}, ${nameB}] n'a pas été trouvé. La corrélation est ignorée.`,
      );
      continue;
    }

    const infoA = assetInfo.get(nameA);
    const infoB = assetInfo.get(nameB);

    // Cov(A,B) = Corr(A,B) * Vol(A) * Vol(B)
    const covariance = corr.correlation * infoA.volatility * infoB.volatility;

    matrix[infoA.index][infoB.index] = covariance;
    matrix[infoB.index][infoA.index] = covariance; // La matrice est symétrique
  }

  return matrix;
};

// Le "déséquilibre" est la différence absolue entre l'offre et la demande. On veut le minimiser.
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

// Un "individu" est un tableau de 3 poids (ex: [0.5, 0.2, 0.3]) qui doivent sommer à 1.
/**
 * Crée une fonction de fitness pour l'optimisation de portefeuille.
 * @param {object} config - L'objet de configuration.
 * @param {Array<{name: string, expectedReturn: number, volatility: number}>} config.assets - Les actifs disponibles.
 * @param {number} config.maxVolatility - La contrainte de volatilité maximale du portefeuille.
 * @param {Array<Array<number>>} [config.covarianceMatrix] - Matrice de covariance pour un calcul de risque précis.
 * @returns {function(Array<number>): number} Une fonction de fitness qui évalue un portefeuille (tableau de poids).
 */
Optimization.Operators.createPortfolioAllocator = ({
  assets,
  maxVolatility,
  covarianceMatrix,
}) => {
  // La fonction de fitness évalue un portefeuille (un tableau de poids).
  // L'objectif est de MINIMISER le score, donc on minimise le rendement NÉGATIF.
  return function portfolioFitness(weights) {
    // Normaliser les poids pour qu'ils somment à 1
    const totalWeight = weights.reduce((sum, w) => sum + w, 0);
    if (totalWeight === 0) return Infinity; // Éviter la division par zéro, score très mauvais
    const normalizedWeights = weights.map((w) => w / totalWeight);

    let portfolioReturn = normalizedWeights.reduce(
      (sum, w, i) => sum + w * assets[i].expectedReturn,
      0,
    );
    let portfolioVolatility;

    if (covarianceMatrix) {
      // Calcul de la volatilité avec la matrice de covariance (plus précis)
      // Volatilité^2 = w' * C * w
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
      // Calcul simplifié (moins précis) : moyenne pondérée des volatilités individuelles.
      portfolioVolatility = normalizedWeights.reduce(
        (sum, w, i) => sum + w * assets[i].volatility,
        0,
      );
    }

    for (let i = 0; i < assets.length; i++) {}

    // Forte pénalité si la contrainte de risque n'est pas respectée.
    if (portfolioVolatility > maxVolatility) {
      return 1000 + (portfolioVolatility - maxVolatility) * 1000; // Pénalité proportionnelle à la violation.
    }

    // On veut maximiser le rendement, donc on minimise son opposé.
    return -portfolioReturn;
  };
};

/**
 * Crée un solveur complet pour le problème du voyageur de commerce (TSP) en utilisant le Recuit Simulé.
 * Cette fonction factorise la création de l'évaluateur de chemin et de la fonction de voisinage.
 * @param {Array<{x: number, y: number}>} cities - Un tableau d'objets représentant les coordonnées des villes.
 * @param {object} [options] - Options pour l'algorithme de recuit simulé.
 * @returns {{solution: Array<number>, energy: number}} Le chemin optimal (indices des villes) et sa distance.
 */
Optimization.Operators.solveTSP = (cities, options = {}) => {
  // Fonction interne pour calculer la distance entre deux villes.
  const distance = (city1, city2) =>
    Math.sqrt(Math.pow(city1.x - city2.x, 2) + Math.pow(city1.y - city2.y, 2));

  // Évaluateur : calcule la longueur totale d'un chemin donné.
  const pathEvaluator = (path) => {
    let totalDistance = 0;
    for (let i = 0; i < path.length - 1; i++) {
      totalDistance += distance(cities[path[i]], cities[path[i + 1]]);
    }
    totalDistance += distance(cities[path[path.length - 1]], cities[path[0]]); // Retour au départ
    return totalDistance;
  };

  // Voisinage : génère un chemin voisin en inversant une sous-séquence (heuristique 2-opt).
  const pathNeighbor = (path) => {
    const newPath = [...path];
    let i = Math.floor(Math.random() * newPath.length);
    let j = Math.floor(Math.random() * newPath.length);
    if (i === j) j = (j + 1) % newPath.length;
    const [start, end] = [Math.min(i, j), Math.max(i, j)];

    const segment = newPath.slice(start, end + 1).reverse();
    newPath.splice(start, segment.length, ...segment);
    return newPath;
  };

  // Solution initiale : un chemin aléatoire.
  const initialPath = Array.from({ length: cities.length }, (_, i) => i).sort(
    () => Math.random() - 0.5,
  );

  // Paramètres par défaut pour le TSP, pouvant être surchargés par `options`.
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
 * Crée un solveur complet pour le problème d'optimisation de portefeuille en utilisant un Algorithme Génétique.
 * @param {Array<{name: string, expectedReturn: number, volatility: number}>} assets - Les actifs disponibles.
 * @param {number} maxVolatility - La contrainte de volatilité maximale du portefeuille.
 * @param {object} [options] - Options pour l'algorithme génétique.
 * @returns {{solution: Array<number>, fitness: number}} L'allocation de poids optimale et le score de fitness associé.
 */
Optimization.Operators.solvePortfolio = (
  assets,
  maxVolatility,
  options = {},
) => {
  // La fonction de fitness est créée par notre opérateur existant.
  const fitnessFunction = Optimization.Operators.createPortfolioAllocator({
    assets,
    maxVolatility,
    covarianceMatrix: options.covarianceMatrix,
  });

  // Fonctions spécifiques au problème pour l'AG, maintenant encapsulées.
  const createIndividual = () =>
    Array.from({ length: assets.length }, () => Math.random());

  const crossover = (p1, p2) => p1.map((w1, i) => (w1 + p2[i]) / 2); // Moyenne des poids

  const mutate = (p) => {
    const newP = [...p];
    const i = Math.floor(Math.random() * newP.length);
    newP[i] += (Math.random() - 0.5) * 0.2; // Mutation douce
    newP[i] = Math.max(0, newP[i]); // Les poids ne peuvent être négatifs
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
 * Crée un évaluateur 2D pour trouver la commission de base et le facteur de bonus qualité qui maximisent les revenus de la plateforme.
 * @param {object} config - L'objet de configuration.
 * @param {number} config.totalAdvertiserCredits - Le total des crédits disponibles chez les annonceurs.
 * @param {Array<{qualityScore: number}>} config.websites - Un tableau d'objets représentant les sites monétisés, chacun avec un score de qualité.
 * @returns {function(Array<number>): number} Un évaluateur qui prend une solution `[baseCommission, bonusFactor]` et retourne le revenu NÉGATIF (car les solveurs minimisent).
 */
Optimization.Operators.createAdvancedPlatformRevenueEvaluator = ({
  totalAdvertiserCredits,
  websites,
}) => {
  // Modèle de la demande (Annonceurs)
  // La demande est sensible à la qualité globale de l'inventaire publicitaire.
  const advertiserDemandModel = (averageSiteQuality) => {
    // La demande de base est toujours liée aux crédits disponibles.
    const baseDemand = (totalAdvertiserCredits || 100) * 10;
    // La demande augmente avec la qualité moyenne des sites.
    return baseDemand * (1 + averageSiteQuality);
  };

  // Modèle de l'offre (Webmasters)
  // L'offre de chaque site dépend de sa rémunération individuelle.
  const webmasterSupplyModel = (baseCommission, bonusFactor) => {
    let totalOfferedClicks = 0;
    const baseSupplyPerSite = 500; // Clics potentiels par site

    for (const site of websites) {
      // La commission effective est réduite pour les sites de haute qualité.
      const effectiveCommission = Math.max(
        0,
        baseCommission - site.qualityScore * bonusFactor,
      );
      const webmasterPayoutRate = 1 - effectiveCommission;

      // L'offre d'un site est proportionnelle à son taux de rémunération.
      totalOfferedClicks += baseSupplyPerSite * webmasterPayoutRate;
    }
    return totalOfferedClicks;
  };

  // L'évaluateur pour l'algorithme d'optimisation (Recuit Simulé, etc.)
  return function revenueEvaluator(solution) {
    const [baseCommission, bonusFactor] = solution;

    // Contraintes : on pénalise fortement les solutions hors des clous.
    if (
      baseCommission < 0.01 ||
      baseCommission > 0.8 ||
      bonusFactor < 0 ||
      bonusFactor > baseCommission
    ) {
      return Infinity; // Score très mauvais
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

    // On veut MAXIMISER le revenu, donc on MINIMISE son opposé.
    return -(clicks * averageCommission);
  };
};

/**
 * Crée un solveur pour le problème de placement d'infrastructures (Facility Location Problem).
 * @param {Array<{x: number, y: number}>} customers - Coordonnées des clients.
 * @param {number} numFacilities - Le nombre d'infrastructures à placer.
 * @param {{minX: number, maxX: number, minY: number, maxY: number}} bounds - Les limites de la carte où placer les infrastructures.
 * @param {number} [options.fixedCostPerFacility=0] - Coût fixe pour chaque infrastructure installée.
 * @param {object} [options] - Options pour le recuit simulé.
 * @returns {{solution: Array<{x: number, y: number}>, energy: number}} Les coordonnées optimales des infrastructures et le coût total.
 */
Optimization.Operators.solveFacilityLocation = (
  customers,
  numFacilities,
  bounds,
  options = {},
) => {
  const fixedCostPerFacility = options.fixedCostPerFacility || 0;
  const distanceSq = (p1, p2) =>
    Math.pow(p1.x - p2.x, 2) + Math.pow(p1.y - p2.y, 2); // On utilise la distance au carré pour l'efficacité

  // Évaluateur : calcule la somme des distances de chaque client à son infrastructure la plus proche.
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
      totalConnectionCost += Math.sqrt(minDistanceToCustomer); // On utilise la vraie distance pour le coût
    }
    // Le coût total est la somme des coûts de connexion + le coût fixe des infrastructures.
    return totalConnectionCost + facilities.length * fixedCostPerFacility;
  };

  // Voisinage : déplace légèrement une infrastructure au hasard.
  const facilityNeighbor = (facilities) => {
    const newFacilities = facilities.map((f) => ({ ...f }));
    const i = Math.floor(Math.random() * numFacilities);
    const moveX = (Math.random() - 0.5) * (bounds.maxX - bounds.minX) * 0.1;
    const moveY = (Math.random() - 0.5) * (bounds.maxY - bounds.minY) * 0.1;

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

  // Solution initiale : place les infrastructures au hasard sur la carte.
  const initialFacilities = Array.from({ length: numFacilities }, () => ({
    x: bounds.minX + Math.random() * (bounds.maxX - bounds.minX),
    y: bounds.minY + Math.random() * (bounds.maxY - bounds.minY),
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

// --- SOLUTION : Définir un coût de base pour un clic ---
// 1 PRIM'S = 1 clic
const BASE_CLICK_COST = 1;
/**
 * Crée un évaluateur multi-objectifs pour déterminer le Coût Par Clic (CPC) optimal.
 * @param {object} config - L'objet de configuration.
 * @param {object} config.advertiser - L'annonceur qui paie le clic.
 * @param {object} config.ad - L'annonce qui a été cliquée.
 * @param {Array<object>} config.competingAds - Les autres annonces ciblant les mêmes mots-clés.
 * @param {object} config.website - Le site sur lequel le clic a eu lieu.
 * @param {object} config.platformParams - Les paramètres de la plateforme (taux de commission, etc.).
 * @param {number} config.estimatedImpressions - Le nombre d'impressions quotidiennes estimées pour ce contexte.
 */
Optimization.Operators.createOptimalCPCEvaluator = (context) => {
  const { optimalBaseCommission, optimalBonusFactor } = context.platformParams;
  const websiteQualityScore = (context.website?.relevanceScore || 50) / 100;

  // Le taux de commission effectif pour ce site
  const effectiveCommissionRate = Math.max(
    0,
    optimalBaseCommission - websiteQualityScore * optimalBonusFactor,
  );

  // Modèle de la demande : combien de clics l'annonceur peut-il s'offrir ?
  const advertiserDemand = (cpc) => {
    if (cpc <= 0) return Infinity;
    return (context.advertiser.credits || 0) / cpc;
  };

  // --- SOLUTION : Utiliser l'offre réelle et la concurrence ---
  // L'offre est maintenant le nombre d'impressions estimées, un chiffre concret.
  const supply = context.estimatedImpressions || 1; // Fallback à 1 pour éviter la division par zéro.

  // Le facteur de concurrence augmente le prix s'il y a plus de monde sur le même créneau.
  // Formule simple : 1 + (0.1 * nombre de concurrents), avec un plafond.
  const competitionFactor = Math.min(
    2.5,
    1 + context.competingAds.length * 0.1,
  );

  return function cpcFitness(cpcMultiplier) {
    // Le CPC final est le coût de base, ajusté par le multiplicateur de l'algo et la concurrence.
    const adjustedCPC = BASE_CLICK_COST * cpcMultiplier * competitionFactor;
    if (adjustedCPC < 0.1) return [Infinity, Infinity, Infinity]; // CPC minimum

    // La demande de l'annonceur est calculée avec le CPC ajusté.
    const demand = advertiserDemand(adjustedCPC);

    // Le nombre de clics est le minimum de l'offre et de la demande.
    const estimatedClicks = Math.min(demand, supply);

    // Objectif 1 : Maximiser le revenu de la plateforme (donc minimiser son opposé)
    const platformRevenue =
      estimatedClicks * adjustedCPC * effectiveCommissionRate;

    // Objectif 2 : Maximiser la valeur pour l'annonceur (nombre de clics, donc minimiser son opposé)
    const advertiserValue = estimatedClicks;

    // Objectif 3 : Minimiser le déséquilibre du marché (offre vs demande)
    const marketImbalance = Math.abs(demand - supply);

    return [-platformRevenue, -advertiserValue, marketImbalance];
  };
};

/**
 * Applique le facteur de concurrence au CPC de base.
 * @private
 * @param {number} baseCpc - Le CPC issu de l'algorithme génétique.
 * @param {Array<object>} competingAds - Les annonces concurrentes.
 * @returns {number} Le CPC final ajusté.
 */
function applyCompetitionFactor(baseCpc, competingAds) {
  // Formule simple : 1 + (0.1 * nombre de concurrents), avec un plafond pour éviter l'explosion des prix.
  const competitionFactor = Math.min(
    2.5,
    1 + (competingAds || []).length * 0.1,
  );
  const finalCpc = baseCpc * competitionFactor;
  // On s'assure de ne jamais descendre sous un seuil minimal.
  return Math.max(0.1, finalCpc);
}
/**
 * Résout le problème du CPC optimal en utilisant un algorithme génétique multi-objectifs.
 * @param {object} context - Le contexte nécessaire pour l'évaluation (advertiser, ad, etc.).
 * @param {object} [options] - Options pour l'algorithme génétique.
 * @returns {Array<{solution: number, objectives: number[]}>} Le front de Pareto des solutions CPC.
 */
Optimization.Operators.solveOptimalCPC = (context, options = {}) => {
  const fitnessFunction =
    Optimization.Operators.createOptimalCPCEvaluator(context);

  // Un "individu" est simplement une valeur de CPC.
  const createIndividual = () => {
    // Le CPC peut varier, par exemple, entre 0.5 et 5 PRIM'S.
    return 0.5 + Math.random() * 4.5;
  };

  // Croisement : moyenne des CPC des parents.
  const crossover = (cpc1, cpc2) => {
    return (cpc1 + cpc2) / 2;
  };

  // Mutation : légère variation aléatoire du CPC.
  const mutate = (cpc) => {
    const newCpc = cpc + (Math.random() - 0.5) * 0.5;
    return Math.max(0.1, newCpc); // Assurer un CPC minimum.
  };

  const gaOptions = {
    generations: 50,
    populationSize: 40,
    ...options,
  };

  // On utilise l'algorithme génétique multi-objectifs pour obtenir le front de Pareto.
  const paretoFront = Optimization.geneticAlgorithmMultiObjective(
    createIndividual,
    fitnessFunction,
    crossover,
    mutate,
    gaOptions,
  );

  // --- SOLUTION : Appliquer le facteur de concurrence sur les solutions finales ---
  return paretoFront.map((result) => {
    const cpcMultiplier = result.solution;
    // Le CPC final est calculé ici, en dehors de la fonction de fitness.
    const finalCpc = applyCompetitionFactor(
      BASE_CLICK_COST * cpcMultiplier,
      context.competingAds,
    );
    return {
      ...result,
      solution: Math.max(0.1, finalCpc), // On s'assure de ne jamais descendre sous le plancher absolu.
    };
  });
};

/**
 * Crée un évaluateur multi-objectifs pour trouver le TTL (Time-To-Live) optimal pour un ticket de sécurité.
 * @param {object} context - L'objet de configuration.
 * @param {number} context.suspicionScore - Le score de suspicion de l'utilisateur (0-100).
 * @returns {function(number): number[]} Une fonction de fitness qui prend un TTL (en ms) et retourne les scores des objectifs [risque, friction].
 */
Optimization.Operators.createOptimalTtlEvaluator = ({ suspicionScore }) => {
  // On normalise le score pour qu'il soit plus impactant dans le calcul du risque.
  const normalizedScore = Math.max(1, suspicionScore);

  return function ttlFitness(ttl) {
    // Contraintes : un TTL doit être dans une plage raisonnable (ex: 5min à 24h)
    if (ttl < 300000 || ttl > 86400000) return [Infinity, Infinity];

    // Objectif 1 : Minimiser le Risque.
    // Le risque est le produit du score et de la durée de la session.
    // Pour un score élevé, l'algo doit choisir un TTL faible pour minimiser ce produit.
    const risk = normalizedScore * ttl;

    // Objectif 2 : Minimiser la Friction UX.
    // La friction est l'inverse du TTL. On la pénalise d'autant plus que le score est FAIBLE.
    // (101 - score) assure que pour un score de 1, la pénalité d'un TTL court est maximale.
    // Pour un score de 100, cette pénalité est quasi nulle.
    const friction = (1 / ttl) * (101 - normalizedScore);

    // On retourne 2 objectifs avec des facteurs de mise à l'échelle pour les équilibrer.
    return [risk / 1e7, friction * 1e9];
  };
};



/**
 * Crée un évaluateur multi-objectifs pour trouver les seuils de détection de fraude optimaux.
 * @param {object} config - L'objet de configuration.
 * @param {Array<object>} config.legitimateClicks - Un échantillon de clics considérés comme légitimes.
 * @param {Array<object>} config.fraudulentClicks - Un échantillon de clics identifiés comme frauduleux (ex: honeypots).
 * @returns {function(Array<number>): number[]} Une fonction de fitness qui prend une solution `[minTimeToClick, maxClickVariance, minMouseEntropy, minScrollEvents]` et retourne les scores des objectifs.
 */
Optimization.Operators.createFraudThresholdEvaluator = ({
  legitimateClicks,
  fraudulentClicks,
}) => {
  // Fonction d'aide pour calculer la variance des positions de clic pour une empreinte
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

  // Pré-calculer la variance pour chaque empreinte dans les données
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

    // Contraintes pour garder des seuils logiques
    if (
      minTimeToClick < 100 ||
      minTimeToClick > 5000 ||
      maxClickVariance < 1 ||
      maxClickVariance > 10000 ||
      minMouseEntropy < 0 ||
      minMouseEntropy > 1 ||
      minScrollEvents < 0
    ) {
      return [Infinity, Infinity]; // Mauvais score si hors limites
    }

    let truePositives = 0; // Bots correctement identifiés
    let falsePositives = 0; // Humains incorrectement bloqués

    // Évaluer les clics frauduleux
    for (const fingerprint in fraudulentGroups) {
      const clicks = fraudulentGroups[fingerprint];
      if (!clicks) continue;
      const variance = calculateClickVariance(clicks);
      // Un groupe de clics est frauduleux si l'une des conditions est remplie
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

    // Évaluer les clics légitimes
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

    // Objectif 1 : Maximiser la détection de fraude (donc minimiser 1 - taux de détection)
    const objective1 = 1 - truePositives / totalFraudulent;

    // Objectif 2 : Minimiser le taux de faux positifs
    const objective2 = falsePositives / totalLegitimate;

    return [objective1, objective2];
  };
};

/**
 * Résout le problème de la détection de fraude en trouvant un front de Pareto de seuils optimaux.
 * @param {object} context - Le contexte contenant les données de clics.
 * @param {Array<object>} context.legitimateClicks - Échantillon de clics légitimes.
 * @param {Array<object>} context.fraudulentClicks - Échantillon de clics frauduleux.
 * @param {object} [options] - Options pour l'algorithme génétique.
 * @returns {Array<{solution: Array<number>, objectives: number[]}>} Le front de Pareto des solutions [minTimeToClick, maxClickVariance, minMouseEntropy, minScrollEvents].
 */
Optimization.Operators.solveFraudDetection = (context, options = {}) => {
  const fitnessFunction =
    Optimization.Operators.createFraudThresholdEvaluator(context);

  // Un "individu" est un tableau de 4 seuils : [minTimeToClick, maxClickVariance, minMouseEntropy, minScrollEvents]
  const createIndividual = () => {
    const minTimeToClick = 100 + Math.random() * 4900; // entre 100ms et 5s
    const maxClickVariance = 1 + Math.random() * 9999; // entre 1 et 10000
    const minMouseEntropy = Math.random() * 0.5; // entre 0 et 0.5
    const minScrollEvents = Math.floor(Math.random() * 10); // entre 0 et 10
    return [minTimeToClick, maxClickVariance, minMouseEntropy, minScrollEvents];
  };

  // Croisement : moyenne des seuils des parents
  const crossover = (s1, s2) => {
    return [
      (s1[0] + s2[0]) / 2,
      (s1[1] + s2[1]) / 2,
      (s1[2] + s2[2]) / 2,
      (s1[3] + s2[3]) / 2,
    ];
  };

  // Mutation : légère variation aléatoire d'un des seuils
  const mutate = (solution) => {
    const newSolution = [...solution];
    const i = Math.floor(Math.random() * 4);
    // Amplitudes de mutation différentes pour chaque seuil
    const mutationFactors = [500, 1000, 0.1, 2];
    const mutationFactor = mutationFactors[i];
    newSolution[i] += (Math.random() - 0.5) * mutationFactor;
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

export { Optimization };

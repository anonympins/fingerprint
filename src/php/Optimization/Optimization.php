<?php

declare(strict_types=1);

namespace Anonympins\Fingerprint\Optimization;

use Anonympins\Fingerprint\Utils\RequestUtils; // For benfordTest

/**
 * Génère un nombre flottant aléatoire cryptographiquement sûr entre 0 (inclus) et 1 (exclus).
 * @return float
 */
function secureRandom(): float
{
    // random_int(0, PHP_INT_MAX) est cryptographiquement sûr.
    // Diviser par PHP_INT_MAX + 1 pour s'assurer que le résultat est < 1.
    return random_int(0, PHP_INT_MAX) / (PHP_INT_MAX + 1);
}

/**
 * Classe d'implémentation des algorithmes d'optimisation.
 */
class Optimization
{
    /**
     * Trouve une bonne solution à un problème d'optimisation en utilisant le Recuit Simulé.
     * @param mixed $initialSolution - Le point de départ de la recherche.
     * @param callable $evaluator - Fonction qui évalue une solution. L'objectif est de minimiser ce score.
     * @param callable $neighbor - Fonction qui génère une solution "voisine" aléatoire.
     * @param float $initialTemperature - La température de départ.
     * @param float $coolingRate - Le taux de refroidissement (proche de 1).
     * @param int $maxIterations - Le nombre total d'itérations.
     * @return array{solution: mixed, energy: float} Le meilleur couple solution/score trouvé.
     */
    public static function simulatedAnnealing(
        $initialSolution,
        callable $evaluator,
        callable $neighbor,
        float $initialTemperature = 1000.0,
        float $coolingRate = 0.995,
        int $maxIterations = 10000
    ): array {
        $currentSolution = $initialSolution;
        $currentEnergy = $evaluator($currentSolution);

        $bestSolution = $currentSolution;
        $bestEnergy = $currentEnergy;

        $temperature = $initialTemperature;

        for ($i = 0; $i < $maxIterations; $i++) {
            $newSolution = $neighbor($currentSolution);
            $newEnergy = $evaluator($newSolution);

            $acceptanceProbability = exp(($currentEnergy - $newEnergy) / $temperature);

            if ($newEnergy < $currentEnergy || secureRandom() < $acceptanceProbability) {
                $currentSolution = $newSolution;
                $currentEnergy = $newEnergy;
            }

            if ($currentEnergy < $bestEnergy) {
                $bestSolution = $currentSolution;
                $bestEnergy = $currentEnergy;
            }

            $temperature *= $coolingRate;
        }

        return ['solution' => $bestSolution, 'energy' => $bestEnergy];
    }

    /**
     * Résout un problème d'optimisation en utilisant un Algorithme Génétique.
     * @param callable $createIndividual - Fonction pour créer un individu aléatoire.
     * @param callable $fitnessFunction - Évalue un individu. L'objectif est de MINIMISER ce score.
     * @param callable $crossover - Croise deux parents pour créer un enfant.
     * @param callable $mutate - Applique une mutation aléatoire à un individu.
     * @param array $options - Options de l'algorithme.
     * @return array{solution: mixed, fitness: float} Le meilleur individu trouvé.
     */
    public static function geneticAlgorithm(
        callable $createIndividual,
        callable $fitnessFunction,
        callable $crossover,
        callable $mutate,
        array $options = []
    ): array {
        $populationSize = $options['populationSize'] ?? 100;
        $generations = $options['generations'] ?? 100;
        $crossoverRate = $options['crossoverRate'] ?? 0.8;
        $mutationRate = $options['mutationRate'] ?? 0.1;
        $returnPopulation = $options['returnPopulation'] ?? false;

        // 1. Initialisation
        $population = [];
        for ($i = 0; $i < $populationSize; $i++) {
            $chromosome = $createIndividual();
            $population[] = ['chromosome' => $chromosome, 'fitness' => $fitnessFunction($chromosome)];
        }

        usort($population, fn($a, $b) => $a['fitness'] <=> $b['fitness']);
        $bestOverall = $population[0];

        // 2. Boucle des générations
        for ($gen = 0; $gen < $generations; $gen++) {
            $newPopulation = [];
            $newPopulation[] = $population[0]; // Élitisme

            while (count($newPopulation) < $populationSize) {
                // 3. Sélection (simple sélection aléatoire pour cet exemple)
                $parent1 = $population[array_rand($population)];
                $parent2 = $population[array_rand($population)];

                $offspringChromosome = null;
                // 4. Croisement
                if (secureRandom() < $crossoverRate) {
                    $offspringChromosome = $crossover($parent1['chromosome'], $parent2['chromosome']);
                } else {
                    $offspringChromosome = $parent1['chromosome'];
                }

                // 5. Mutation
                if (secureRandom() < $mutationRate) {
                    $offspringChromosome = $mutate($offspringChromosome);
                }

                if ($offspringChromosome !== null) {
                    $newPopulation[] = ['chromosome' => $offspringChromosome, 'fitness' => $fitnessFunction($offspringChromosome)];
                } else {
                    $newPopulation[] = $parent1; // Fallback
                }
            }

            $population = $newPopulation;
            usort($population, fn($a, $b) => $a['fitness'] <=> $b['fitness']);

            if ($population[0]['fitness'] < $bestOverall['fitness']) {
                $bestOverall = $population[0];
            }
        }

        if ($returnPopulation) {
            return $population;
        }

        return ['solution' => $bestOverall['chromosome'], 'fitness' => $bestOverall['fitness']];
    }

    /**
     * Détermine si la solution A domine la solution B en multi-objectifs (problème de minimisation).
     * @param float[] $objectivesA - Tableau des scores des objectifs pour la solution A.
     * @param float[] $objectivesB - Tableau des scores des objectifs pour la solution B.
     * @return bool - True si A domine B.
     */
    private static function paretoDominates(array $objectivesA, array $objectivesB): bool
    {
        $aIsBetterInOne = false;
        for ($i = 0; $i < count($objectivesA); $i++) {
            if ($objectivesA[$i] > $objectivesB[$i]) {
                return false;
            }
            if ($objectivesA[$i] < $objectivesB[$i]) {
                $aIsBetterInOne = true;
            }
        }
        return $aIsBetterInOne;
    }

    /**
     * Trie une population en fronts de Pareto non-dominés (inspiré de NSGA-II).
     * @param array $populationWithObjectives - La population à trier. Chaque élément est un array{individual: mixed, objectives: float[]}.
     * @return array - Un tableau de fronts, où le premier est le meilleur.
     */
    private static function nonDominatedSort(array $populationWithObjectives): array
    {
        $fronts = [[]];
        foreach ($populationWithObjectives as &$p1) {
            $p1['dominationCount'] = 0;
            $p1['dominatedSolutions'] = [];
            foreach ($populationWithObjectives as &$p2) {
                if ($p1 === $p2) continue;
                if (self::paretoDominates($p1['objectives'], $p2['objectives'])) {
                    $p1['dominatedSolutions'][] = &$p2;
                } elseif (self::paretoDominates($p2['objectives'], $p1['objectives'])) {
                    $p1['dominationCount']++;
                }
            }
        }
        unset($p1, $p2); // Break references

        // Initialize rank 0
        foreach ($populationWithObjectives as &$p1) {
            if ($p1['dominationCount'] === 0) {
                $p1['rank'] = 0;
                $fronts[0][] = &$p1;
            }
        }
        unset($p1);

        $i = 0;
        while (isset($fronts[$i]) && count($fronts[$i]) > 0) {
            $nextFront = [];
            foreach ($fronts[$i] as &$p1) {
                foreach ($p1['dominatedSolutions'] as &$p2) {
                    $p2['dominationCount']--;
                    if ($p2['dominationCount'] === 0) {
                        $p2['rank'] = $i + 1;
                        $nextFront[] = &$p2;
                    }
                }
            }
            unset($p1, $p2); // Break references
            $i++;
            if (count($nextFront) > 0) {
                $fronts[$i] = $nextFront;
            }
        }
        return $fronts;
    }

    /**
     * Calcule la distance de promiscuité (crowding distance) pour un front.
     * @param array $front - Le front de Pareto.
     */
    private static function calculateCrowdingDistance(array &$front): void
    {
        if (count($front) === 0) return;
        foreach ($front as &$p) {
            $p['crowdingDistance'] = 0.0;
        }
        unset($p); // Break reference

        $numObjectives = count($front[0]['objectives']);

        for ($i = 0; $i < $numObjectives; $i++) {
            usort($front, fn($a, $b) => $a['objectives'][$i] <=> $b['objectives'][$i]);

            $minObj = $front[0]['objectives'][$i];
            $maxObj = $front[count($front) - 1]['objectives'][$i];

            $front[0]['crowdingDistance'] = INF;
            $front[count($front) - 1]['crowdingDistance'] = INF;

            if ($maxObj === $minObj) continue;

            for ($j = 1; $j < count($front) - 1; $j++) {
                $front[$j]['crowdingDistance'] +=
                    ($front[$j + 1]['objectives'][$i] - $front[$j - 1]['objectives'][$i]) /
                    ($maxObj - $minObj);
            }
        }
    }

    /**
     * Algorithme génétique multi-objectifs (inspiré de NSGA-II) pour trouver un front de Pareto.
     * @param callable $createIndividual - Fonction qui crée un individu aléatoire.
     * @param callable $fitnessFunction - Fonction qui évalue un individu et retourne un tableau d'objectifs à MINIMISER.
     * @param callable $crossover - Fonction de croisement.
     * @param callable $mutate - Fonction de mutation.
     * @param array $options - Options de l'algorithme.
     * @return array - Le premier front de Pareto (l'ensemble des meilleures solutions de compromis).
     */
    public static function geneticAlgorithmMultiObjective(
        callable $createIndividual,
        callable $fitnessFunction,
        callable $crossover,
        callable $mutate,
        array $options = []
    ): array {
        $generations = $options['generations'] ?? 150;
        $populationSize = $options['populationSize'] ?? 60;
        $mutationRate = $options['mutationRate'] ?? 0.1;

        $population = [];
        for ($i = 0; $i < $populationSize; $i++) {
            $individual = $createIndividual();
            $population[] = ['individual' => $individual, 'objectives' => $fitnessFunction($individual)];
        }

        for ($gen = 0; $gen < $generations; $gen++) {
            $offspring = [];
            for ($i = 0; $i < $populationSize; $i++) {
                $parent1 = $population[array_rand($population)];
                $parent2 = $population[array_rand($population)];
                $childIndividual = $crossover($parent1['individual'], $parent2['individual']);
                if (secureRandom() < $mutationRate) {
                    $childIndividual = $mutate($childIndividual);
                }
                $offspring[] = ['individual' => $childIndividual, 'objectives' => $fitnessFunction($childIndividual)];
            }

            $combinedPopulation = array_merge($population, $offspring);
            $fronts = self::nonDominatedSort($combinedPopulation);

            $newPopulation = [];
            foreach ($fronts as $front) {
                if (count($newPopulation) + count($front) <= $populationSize) {
                    $newPopulation = array_merge($newPopulation, $front);
                } else {
                    self::calculateCrowdingDistance($front);
                    usort($front, fn($a, $b) => $b['crowdingDistance'] <=> $a['crowdingDistance']);
                    $remaining = $populationSize - count($newPopulation);
                    $newPopulation = array_merge($newPopulation, array_slice($front, 0, $remaining));
                    break;
                }
            }
            $population = $newPopulation;
        }

        $finalFronts = self::nonDominatedSort($population);
        $bestFront = $finalFronts[0] ?? [];

        $uniqueSolutionsMap = [];
        foreach ($bestFront as $p) {
            $key = json_encode($p['objectives']);
            if (!isset($uniqueSolutionsMap[$key])) {
                $uniqueSolutionsMap[$key] = ['solution' => $p['individual'], 'objectives' => $p['objectives']];
            }
        }
        return array_values($uniqueSolutionsMap);
    }

    /**
     * Namespace pour les opérateurs d'optimisation.
     */
    public static array $Operators = [];
}

/**
 * Opérateurs d'optimisation.
 */
Optimization::$Operators = [
    /**
     * Crée un évaluateur multi-objectifs pour l'auto-tuning complet de la configuration de sécurité.
     * @param array $context - Le contexte contenant les données de trafic.
     * @return callable - Une fonction de fitness qui prend une configuration complète et retourne les scores [taux de faux positifs, taux de faux négatifs, taux de challenge, coût moyen de challenge].
     */
    'createFullSecurityConfigEvaluator' => function (array $context): callable {
        $trafficData = $context['trafficData'];

        return function (array $config) use ($trafficData): array {
            $falsePositives = 0.0;
            $falseNegatives = 0.0;
            $totalHumans = 0.0;
            $totalBots = 0.0;
            $totalChallenges = 0.0;
            $totalChallengeCost = 0.0;

            $calculateScore = function (array $log) use ($config): float {
                $score = 0.0;
                foreach ($config['weights'] as $key => $weight) {
                    $score += ($log['vector'][$key] ?? 0.0) * $weight;
                }
                return $score;
            };

            $confidenceWeights = [
                'request_passed' => 0.7,
                'challenge_issued' => 1.0,
                'request_blocked' => 1.0,
                'challenge_solved' => 1.5,
                'trap_triggered' => 2.0,
            ];

            foreach ($trafficData as $log) {
                $confidence = $confidenceWeights[$log['type']] ?? 1.0;

                $isLikelyBot = in_array($log['type'], ['challenge_issued', 'request_blocked']);
                $isLikelyHuman = in_array($log['type'], ['request_passed', 'challenge_solved']);

                if ($isLikelyBot) {
                    $totalBots += $confidence;
                    $score = $calculateScore($log);
                    if ($score < ($config['thresholds']['low'] ?? 0)) {
                        $falseNegatives += $confidence;
                    } else {
                        $totalChallenges += $confidence;
                        $suspicionFactor = ($score - ($config['thresholds']['low'] ?? 0)) / ((($config['thresholds']['high'] ?? 0) - ($config['thresholds']['low'] ?? 0)) ?: 1);
                        $totalChallengeCost += min(1.0, max(0.0, $suspicionFactor)) * $confidence;
                    }
                } elseif ($isLikelyHuman) {
                    $totalHumans += $confidence;
                    $score = $calculateScore($log);
                    if ($score >= ($config['thresholds']['low'] ?? 0)) {
                        $falsePositives += $confidence;
                        $totalChallenges += $confidence;
                        $suspicionFactor = ($score - ($config['thresholds']['low'] ?? 0)) / ((($config['thresholds']['high'] ?? 0) - ($config['thresholds']['low'] ?? 0)) ?: 1);
                        $totalChallengeCost += min(1.0, max(0.0, $suspicionFactor)) * $confidence;
                    }
                }
            }

            $falsePositiveRate = $totalHumans > 0 ? $falsePositives / $totalHumans : 0.0;
            $falseNegativeRate = $totalBots > 0 ? $falseNegatives / $totalBots : 0.0;
            $challengeRate = ($totalHumans + $totalBots) > 0 ? $totalChallenges / ($totalHumans + $totalBots) : 0.0;
            $averageChallengeCost = $totalChallenges > 0 ? $totalChallengeCost / $totalChallenges : 0.0;

            return [$falsePositiveRate, $falseNegativeRate, $challengeRate, $averageChallengeCost];
        };
    },

    /**
     * Résout le problème de l'auto-tuning complet de la configuration de sécurité.
     * @param array $context - Le contexte contenant les données de trafic.
     * @param array $options - Options pour l'algorithme génétique.
     * @return array - Le front de Pareto des configurations optimales.
     */
    'solveFullSecurityTuning' => function (array $context, array $options = []): array {
        $fitnessFunction = Optimization::$Operators['createFullSecurityConfigEvaluator']($context);

        $createIndividual = function (): array {
            return [
                'thresholds' => [
                    'low' => 15 + secureRandom() * 20, // 15-35
                    'medium' => 40 + secureRandom() * 25, // 40-65
                    'high' => 70 + secureRandom() * 20, // 70-90
                ],
                'weights' => [
                    'historyScore' => secureRandom(),
                    'rotationScore' => secureRandom(),
                    'headerAnomalyScore' => secureRandom(),
                    'requestPatternScore' => 0.5 + secureRandom(),
                    'inconsistencyScore' => secureRandom(),
                    'honeypotScore' => 1.0,
                    'behaviorScore' => secureRandom(),
                    'crossLayerInconsistencyScore' => secureRandom(),
                    'timeInconsistencyScore' => secureRandom(),
                ],
                'patterns' => [
                    'velocityThreshold' => 100 + secureRandom() * 400,
                    'burstThreshold' => 300 + secureRandom() * 700,
                    'scrapeThreshold' => 500 + secureRandom() * 1000,
                    'sequenceLength' => (int)floor(3 + secureRandom() * 3),
                    'regularityThreshold' => 50 + secureRandom() * 200,
                    'decayFactor' => 0.85 + secureRandom() * 0.14,
                    'inactivityReset' => 15000 + secureRandom() * 45000,
                ]
            ];
        };

        $crossover = function (array $c1, array $c2): array {
            $child = $c1; // Start with a copy of c1

            foreach ($child['thresholds'] as $key => $value) {
                $child['thresholds'][$key] = ($c1['thresholds'][$key] + $c2['thresholds'][$key]) / 2;
            }
            foreach ($child['weights'] as $key => $value) {
                if ($key !== 'honeypotScore') { // Ne pas croiser le poids du honeypot
                    $child['weights'][$key] = ($c1['weights'][$key] + $c2['weights'][$key]) / 2;
                }
            }
            foreach ($child['patterns'] as $key => $value) {
                $child['patterns'][$key] = ($c1['patterns'][$key] + $c2['patterns'][$key]) / 2;
            }
            return $child;
        };

        $mutate = function (array $c): array {
            $newConfig = $c; // Start with a copy

            $sections = [
                'patterns' => 0.5,
                'weights' => 0.35,
                'thresholds' => 0.15
            ];
            $rand = secureRandom();
            $cumulativeWeight = 0.0;
            $sectionToMutate = 'patterns';
            foreach ($sections as $name => $weight) {
                $cumulativeWeight += $weight;
                if ($rand < $cumulativeWeight) {
                    $sectionToMutate = $name;
                    break;
                }
            }

            $keys = array_keys($newConfig[$sectionToMutate]);
            $keyToMutate = $keys[array_rand($keys)];

            if ($keyToMutate === 'honeypotScore') return $newConfig;

            $mutationAmount = (secureRandom() - 0.5) * 0.4; // +/- 20%
            $newConfig[$sectionToMutate][$keyToMutate] *= (1 + $mutationAmount);

            // S'assurer que les valeurs restent dans des limites raisonnables
            if ($sectionToMutate === 'weights') {
                $newConfig[$sectionToMutate][$keyToMutate] = max(0.0, min(1.5, $newConfig[$sectionToMutate][$keyToMutate]));
            }
            if ($keyToMutate === 'decayFactor') {
                $newConfig['patterns']['decayFactor'] = max(0.8, min(0.999, $newConfig['patterns']['decayFactor']));
            }
            if (str_contains($keyToMutate, 'Threshold') || str_contains($keyToMutate, 'Reset')) {
                $newConfig['patterns'][$keyToMutate] = max(50, (int)$newConfig['patterns'][$keyToMutate]);
            }

            return $newConfig;
        };

        return Optimization::geneticAlgorithmMultiObjective(
            $createIndividual,
            $fitnessFunction,
            $crossover,
            $mutate,
            array_merge(['generations' => 50, 'populationSize' => 50], $options)
        );
    },

    /**
     * Crée un évaluateur multi-objectifs pour trouver le TTL (Time-To-Live) optimal pour un ticket de sécurité.
     * @param array $context - L'objet de configuration.
     * @param float $context.suspicionScore - Le score de suspicion de l'utilisateur (0-100).
     * @return callable - Une fonction de fitness qui prend un TTL (en ms) et retourne les scores des objectifs [risque, friction].
     */
    'createOptimalTtlEvaluator' => function (array $context): callable {
        $suspicionScore = $context['suspicionScore'];
        $normalizedScore = max(1.0, $suspicionScore);

        return function (float $ttl) use ($normalizedScore): array {
            // Contraintes : un TTL doit être dans une plage raisonnable (ex: 5min à 24h)
            if ($ttl < 300000 || $ttl > 86400000) return [INF, INF];

            // Objectif 1 : Minimiser le Risque.
            $risk = $normalizedScore * $ttl;

            // Objectif 2 : Minimiser la Friction UX.
            $friction = (1.0 / $ttl) * (101.0 - $normalizedScore);

            // On retourne 2 objectifs avec des facteurs de mise à l'échelle pour les équilibrer.
            return [$risk / 1e7, $friction * 1e9];
        };
    },

    /**
     * Détermine le TTL optimal pour un ticket en utilisant un algorithme génétique multi-objectifs.
     * @param float $suspicionScore - Le score de suspicion de la requête.
     * @return int - Le TTL optimal calculé en millisecondes.
     */
    'determineOptimalTicketTtl' => function (float $suspicionScore): int {
        $minTtl = 300000; // 5 minutes
        $maxTtl = 86400000; // 24 heures

        $solverFunction = function () use ($suspicionScore, $minTtl, $maxTtl) {
            $fitnessFunction = Optimization::$Operators['createOptimalTtlEvaluator'](['suspicionScore' => $suspicionScore]);

            $createIndividual = fn() => $minTtl + secureRandom() * ($maxTtl - $minTtl);
            $crossover = fn($ttl1, $ttl2) => ($ttl1 + $ttl2) / 2;
            $mutate = function ($ttl) use ($minTtl, $maxTtl) {
                $newTtl = $ttl + (secureRandom() - 0.5) * ($maxTtl - $minTtl) * 0.1;
                return max($minTtl, min($maxTtl, $newTtl));
            };

            $paretoFront = Optimization::geneticAlgorithmMultiObjective(
                $createIndividual,
                $fitnessFunction,
                $crossover,
                $mutate,
                ['generations' => 40, 'populationSize' => 30]
            );

            if (empty($paretoFront)) {
                return ['solution' => null, 'fitness' => INF];
            }

            $bestSolutionInFront = null;
            if ($suspicionScore < 50) {
                // For low suspicion, prioritize longer TTL (less friction)
                $bestSolutionInFront = array_reduce($paretoFront, fn($max, $p) => max($max, $p['solution']), 0.0);
            } else {
                // For high suspicion, prioritize shorter TTL (less risk)
                $bestSolutionInFront = array_reduce($paretoFront, fn($min, $p) => min($min, $p['solution']), INF);
            }
            return ['solution' => $bestSolutionInFront, 'fitness' => 0.0];
        };

        // Run multiple cycles (simplified, no parallel for PHP example)
        $bestResult = null;
        for ($i = 0; $i < 20; $i++) {
            $currentResult = $solverFunction();
            if ($bestResult === null || $currentResult['fitness'] < $bestResult['fitness']) {
                $bestResult = $currentResult;
            }
        }

        if ($bestResult === null || $bestResult['solution'] === null || $bestResult['solution'] === INF) {
            return (int)round(max($minTtl, $maxTtl - ($suspicionScore / 100) * $maxTtl));
        }

        return (int)round($bestResult['solution']);
    },
];
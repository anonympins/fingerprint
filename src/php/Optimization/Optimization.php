<?php

declare(strict_types=1);

namespace Anonympins\Fingerprint\Optimization;

/**
 * Optimization algorithms library.
 */
class Optimization
{
    /**
     * Generates a cryptographically secure random float in [0, 1).
     */
    private static function secureRandom(): float
    {
        try {
            return random_int(0, PHP_INT_MAX - 1) / PHP_INT_MAX;
        } catch (\Exception $e) {
            return (float)mt_rand() / (float)mt_getrandmax(); // Fallback
        }
    }

    /**
     * Multi-objective genetic algorithm (inspired by NSGA-II).
     * @param callable $createIndividual
     * @param callable $fitnessFunction
     * @param callable $crossover
     * @param callable $mutate
     * @param array|null $currentConfig Reference baseline configuration.
     * @param array $options
     * @return array<int, array{solution: mixed, objectives: array<float>}>
     */
    public static function geneticAlgorithmMultiObjective(
        callable $createIndividual,
        callable $fitnessFunction,
        callable $crossover,
        callable $mutate, // La fonction mutate doit maintenant accepter $currentConfig
        ?array $currentConfig = null, // NOUVEAU: La configuration actuelle
        array $options = []
    ): array {
        $generations = $options['generations'] ?? 150;
        $populationSize = $options['populationSize'] ?? 60;
        $mutationRate = $options['mutationRate'] ?? 0.1;

        $population = [];
        for ($i = 0; $i < $populationSize; $i++) {
            $individual = $createIndividual();
            $population[] = [
                'individual' => $individual,
                'objectives' => $fitnessFunction($individual)
            ];
        }

        for ($gen = 0; $gen < $generations; $gen++) {
            // 1. Generate offspring population
            $offspring = [];
            for ($i = 0; $i < $populationSize; $i++) {
                $parent1 = $population[random_int(0, count($population) - 1)];
                $parent2 = $population[random_int(0, count($population) - 1)];
                $childIndividual = $crossover($parent1['individual'], $parent2['individual']);
                if (self::secureRandom() < $mutationRate) {
                    $childIndividual = $mutate($childIndividual, $currentConfig);
                }
                $offspring[] = [
                    'individual' => $childIndividual,
                    'objectives' => $fitnessFunction($childIndividual)
                ];
            }

            // 2. Combine parent and offspring populations
            $combinedPopulation = array_merge($population, $offspring);

            // 3. Sort into non-dominated Pareto fronts
            $fronts = self::nonDominatedSort($combinedPopulation);

            // 4. Build next generation
            $newPopulation = [];
            foreach ($fronts as $front) {
                if (count($newPopulation) + count($front) <= $populationSize) {
                    $newPopulation = array_merge($newPopulation, $front);
                } else {
                    self::calculateCrowdingDistance($front);
                    // Sort by crowding distance descending
                    usort($front, fn ($a, $b) => $b['crowdingDistance'] <=> $a['crowdingDistance']);
                    $remaining = $populationSize - count($newPopulation);
                    $newPopulation = array_merge($newPopulation, array_slice($front, 0, $remaining));
                    break;
                }
            }
            $population = $newPopulation;
        }

        // Return the first non-dominated front of the final population
        $finalFronts = self::nonDominatedSort($population);
        $bestFront = $finalFronts[0] ?? [];

        // Deduplicate solutions with identical objective scores
        $uniqueSolutionsMap = [];
        foreach ($bestFront as $p) {
            $key = json_encode($p['objectives']);
            if (!isset($uniqueSolutionsMap[$key])) {
                $uniqueSolutionsMap[$key] = [
                    'solution' => $p['individual'],
                    'objectives' => $p['objectives'],
                ];
            }
        }
        return array_values($uniqueSolutionsMap);
    }

    /**
     * Determines whether solution A Pareto-dominates solution B (minimization).
     * @param array<float> $objectivesA
     * @param array<float> $objectivesB
     */
    private static function paretoDominates(array $objectivesA, array $objectivesB): bool
    {
        $aIsBetterInOne = false;
        for ($i = 0; $i < count($objectivesA); $i++) {
            if ($objectivesA[$i] > $objectivesB[$i]) {
                return false; // A is worse on at least one objective
            }
            if ($objectivesA[$i] < $objectivesB[$i]) {
                $aIsBetterInOne = true; // A is strictly better on at least one objective
            }
        }
        return $aIsBetterInOne;
    }

    /**
     * Sorts population into non-dominated Pareto fronts (NSGA-II).
     * @param array<int, array> &$populationWithObjectives
     * @return array<int, array>
     */
    private static function nonDominatedSort(array &$populationWithObjectives): array
    {
        $fronts = [[]];
        $n = count($populationWithObjectives);

        for ($i = 0; $i < $n; $i++) {
            $p1 = &$populationWithObjectives[$i];
            $p1['dominationCount'] = 0;
            $p1['dominatedSolutions'] = [];

            for ($j = 0; $j < $n; $j++) {
                if ($i === $j) continue;
                $p2 = &$populationWithObjectives[$j];

                if (self::paretoDominates($p1['objectives'], $p2['objectives'])) {
                    $p1['dominatedSolutions'][] = $j;
                } elseif (self::paretoDominates($p2['objectives'], $p1['objectives'])) {
                    $p1['dominationCount']++;
                }
            }

            if ($p1['dominationCount'] === 0) {
                $p1['rank'] = 0;
                $fronts[0][] = $p1;
            }
        }

        $i = 0;
        while (!empty($fronts[$i])) {
            $nextFront = [];
            foreach ($fronts[$i] as $p1) {
                foreach ($p1['dominatedSolutions'] as $p2_idx) {
                    $p2 = &$populationWithObjectives[$p2_idx];
                    $p2['dominationCount']--;
                    if ($p2['dominationCount'] === 0) {
                        $p2['rank'] = $i + 1;
                        $nextFront[] = $p2;
                    }
                }
            }
            $i++;
            if (!empty($nextFront)) {
                $fronts[$i] = $nextFront;
            }
        }
        return $fronts;
    }

    /**
     * Computes crowding distance for a front to preserve diversity.
     * @param array<int, array> &$front
     */
    private static function calculateCrowdingDistance(array &$front): void
    {
        if (empty($front)) return;

        $numObjectives = count($front[0]['objectives']);
        $l = count($front);

        foreach ($front as &$p) {
            $p['crowdingDistance'] = 0;
        }

        for ($i = 0; $i < $numObjectives; $i++) {
            // Sort front by current objective
            usort($front, fn ($a, $b) => $a['objectives'][$i] <=> $b['objectives'][$i]);

            $minObj = $front[0]['objectives'][$i];
            $maxObj = $front[$l - 1]['objectives'][$i];

            // Boundary solutions receive infinite distance to encourage spread
            $front[0]['crowdingDistance'] = INF;
            $front[$l - 1]['crowdingDistance'] = INF;

            if ($maxObj === $minObj) continue;

            for ($j = 1; $j < $l - 1; $j++) {
                $front[$j]['crowdingDistance'] +=
                    ($front[$j + 1]['objectives'][$i] - $front[$j - 1]['objectives'][$i]) /
                    ($maxObj - $minObj);
            }
        }
    }

    /**
     * Calculates deviation from Benford's Law distribution.
     * Elevated values indicate synthetic or automated intervals.
     * @param array<int|float> $numbers
     */
    public static function benfordTest(array $numbers): float // Rendre la méthode publique et statique
    {
        $counts = array_fill(1, 9, 0);
        $validCount = 0;

        foreach ($numbers as $n) {
            if (is_string($n)) {
                $n = (float)$n;
            }
            if (!is_numeric($n)) {
                continue;
            }
            $val = abs((float)$n);
            if ($val == 0.0) {
                continue;
            }
            $log = log10($val);
            $factor = pow(10, (int)floor($log));
            $digit = (int)floor($val / $factor);
            if ($digit >= 1 && $digit <= 9) {
                $counts[$digit]++;
                $validCount++;
            }
        }

        if ($validCount < 10) {
            return 0.0;
        }

        $benfordDistribution = [1 => 30.1, 2 => 17.6, 3 => 12.5, 4 => 9.7, 5 => 7.9, 6 => 6.7, 7 => 5.8, 8 => 5.1, 9 => 4.6];

        $totalDeviation = 0.0;
        for ($i = 1; $i <= 9; $i++) {
            $observedFrequency = ($counts[$i] / $validCount) * 100.0;
            $expectedFrequency = $benfordDistribution[$i];
            $totalDeviation += pow($observedFrequency - $expectedFrequency, 2);
        }

        return sqrt($totalDeviation) / 50.0;
    }
}
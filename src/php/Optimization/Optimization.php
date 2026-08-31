<?php

declare(strict_types=1);

namespace Anonympins\Fingerprint\Optimization;

/**
 * Bibliothèque d'algorithmes d'optimisation.
 */
class Optimization
{
    /**
     * Génère un nombre flottant aléatoire cryptographiquement sûr entre 0 (inclus) et 1 (exclus).
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
     * Algorithme génétique multi-objectifs (inspiré de NSGA-II).
     * @param callable $createIndividual
     * @param callable $fitnessFunction
     * @param callable $crossover
     * @param callable $mutate
     * @param array $options
     * @return array<int, array{solution: mixed, objectives: array<float>}>
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
            $population[] = [
                'individual' => $individual,
                'objectives' => $fitnessFunction($individual)
            ];
        }

        for ($gen = 0; $gen < $generations; $gen++) {
            // 1. Créer une population d'enfants
            $offspring = [];
            for ($i = 0; $i < $populationSize; $i++) {
                $parent1 = $population[random_int(0, count($population) - 1)];
                $parent2 = $population[random_int(0, count($population) - 1)];
                $childIndividual = $crossover($parent1['individual'], $parent2['individual']);
                if (self::secureRandom() < $mutationRate) {
                    $childIndividual = $mutate($childIndividual);
                }
                $offspring[] = [
                    'individual' => $childIndividual,
                    'objectives' => $fitnessFunction($childIndividual)
                ];
            }

            // 2. Combiner parents et enfants
            $combinedPopulation = array_merge($population, $offspring);

            // 3. Trier la population combinée en fronts
            $fronts = self::nonDominatedSort($combinedPopulation);

            // 4. Construire la nouvelle population
            $newPopulation = [];
            foreach ($fronts as $front) {
                if (count($newPopulation) + count($front) <= $populationSize) {
                    $newPopulation = array_merge($newPopulation, $front);
                } else {
                    self::calculateCrowdingDistance($front);
                    // Trier par distance décroissante
                    usort($front, fn ($a, $b) => $b['crowdingDistance'] <=> $a['crowdingDistance']);
                    $remaining = $populationSize - count($newPopulation);
                    $newPopulation = array_merge($newPopulation, array_slice($front, 0, $remaining));
                    break;
                }
            }
            $population = $newPopulation;
        }

        // Retourner le premier front de la population finale
        $finalFronts = self::nonDominatedSort($population);
        $bestFront = $finalFronts[0] ?? [];

        // Filtrer pour ne garder que les solutions avec des objectifs uniques
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
     * Détermine si la solution A domine la solution B.
     * @param array<float> $objectivesA
     * @param array<float> $objectivesB
     */
    private static function paretoDominates(array $objectivesA, array $objectivesB): bool
    {
        $aIsBetterInOne = false;
        for ($i = 0; $i < count($objectivesA); $i++) {
            if ($objectivesA[$i] > $objectivesB[$i]) {
                return false; // A est pire sur au moins un objectif
            }
            if ($objectivesA[$i] < $objectivesB[$i]) {
                $aIsBetterInOne = true; // A est strictement meilleur sur au moins un
            }
        }
        return $aIsBetterInOne;
    }

    /**
     * Trie une population en fronts de Pareto non-dominés.
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
     * Calcule la distance de promiscuité (crowding distance) pour un front.
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
            // Trier le front par l'objectif courant
            usort($front, fn ($a, $b) => $a['objectives'][$i] <=> $b['objectives'][$i]);

            $minObj = $front[0]['objectives'][$i];
            $maxObj = $front[$l - 1]['objectives'][$i];

            // Les solutions aux extrémités ont une distance infinie
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
     * Calcule la déviation d'une série de chiffres par rapport à la loi de Benford.
     * @param array<int|float> $numbers
     */
    public static function benfordTest(array $numbers): float
    {
        if (count($numbers) < 10) {
            return 0.0; // Pas assez de données
        }

        $leadingDigits = array_map(function ($n) {
            $str = ltrim((string)$n, '0.');
            return $str[0] ?? '';
        }, $numbers);

        $leadingDigits = array_filter($leadingDigits, fn ($d) => $d >= '1' && $d <= '9');

        if (count($leadingDigits) < 10) {
            return 0.0;
        }

        $counts = array_fill(1, 9, 0);
        foreach ($leadingDigits as $digit) {
            $counts[(int)$digit]++;
        }

        $benfordDistribution = [1 => 30.1, 2 => 17.6, 3 => 12.5, 4 => 9.7, 5 => 7.9, 6 => 6.7, 7 => 5.8, 8 => 5.1, 9 => 4.6];

        $totalDeviation = 0.0;
        for ($i = 1; $i <= 9; $i++) {
            $observedFrequency = ($counts[$i] / count($leadingDigits)) * 100;
            $expectedFrequency = $benfordDistribution[$i];
            $totalDeviation += pow($observedFrequency - $expectedFrequency, 2);
        }

        return sqrt($totalDeviation) / 50.0;
    }
}
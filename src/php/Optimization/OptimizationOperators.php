<?php

declare(strict_types=1);

namespace Anonympins\Fingerprint\Optimization;

/**
 * Opérateurs pour les problèmes d'optimisation.
 */
class OptimizationOperators
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
     * Crée un évaluateur pour l'auto-tuning complet de la configuration de sécurité.
     * @param array $context
     * @return callable
     */
    public static function createFullSecurityConfigEvaluator(array $context): callable
    {
        $trafficData = $context['trafficData'];

        return function (array $config) use ($trafficData): array {
            $falsePositives = 0;
            $falseNegatives = 0;
            $totalHumans = 0;
            $totalBots = 0;

            $calculateScore = function (array $log) use ($config): float {
                $score = 0.0;
                foreach ($config['weights'] as $key => $weight) {
                    $score += ($log['vector'][$key] ?? 0) * $weight;
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
                $isLikelyBot = in_array($log['type'], ['challenge_issued', 'request_blocked', 'trap_triggered']);
                $isLikelyHuman = in_array($log['type'], ['request_passed', 'challenge_solved']);

                if ($isLikelyBot) {
                    $totalBots += $confidence;
                    $score = $calculateScore($log);
                    if ($score < $config['thresholds']['low']) {
                        $falseNegatives += $confidence;
                    }
                } elseif ($isLikelyHuman) {
                    $totalHumans += $confidence;
                    $score = $calculateScore($log);
                    if ($score >= $config['thresholds']['low']) {
                        $falsePositives += $confidence;
                    }
                }
            }

            $falsePositiveRate = $totalHumans > 0 ? $falsePositives / $totalHumans : 0;
            $falseNegativeRate = $totalBots > 0 ? $falseNegatives / $totalBots : 0;

            return [$falsePositiveRate, $falseNegativeRate];
        };
    }

    /**
     * Résout le problème de l'auto-tuning complet de la configuration de sécurité.
     * @param array $context
     * @param array $options
     * @return array
     */
    public static function solveFullSecurityTuning(array $context, array $options = []): array
    {
        $fitnessFunction = self::createFullSecurityConfigEvaluator($context);

        $createIndividual = function (): array {
            return [
                'thresholds' => [
                    'low' => 15 + self::secureRandom() * 20,
                    'medium' => 40 + self::secureRandom() * 25,
                    'high' => 70 + self::secureRandom() * 20,
                ],
                'weights' => [
                    'historyScore' => self::secureRandom(),
                    'rotationScore' => self::secureRandom(),
                    'headerAnomalyScore' => self::secureRandom(),
                    'requestPatternScore' => 0.5 + self::secureRandom(),
                    'inconsistencyScore' => self::secureRandom(),
                    'honeypotScore' => 1.0,
                    'behaviorScore' => self::secureRandom(),
                    'crossLayerInconsistencyScore' => self::secureRandom(),
                    'timeInconsistencyScore' => self::secureRandom(),
                ],
                'patterns' => [
                    'velocityThreshold' => 100 + self::secureRandom() * 400,
                    'burstThreshold' => 300 + self::secureRandom() * 700,
                    'scrapeThreshold' => 500 + self::secureRandom() * 1000,
                    'regularityThreshold' => 50 + self::secureRandom() * 200,
                    'decayFactor' => 0.85 + self::secureRandom() * 0.14,
                    'inactivityReset' => 15000 + self::secureRandom() * 45000,
                ]
            ];
        };

        $crossover = function (array $c1, array $c2): array {
            $child = $c1;
            foreach (['thresholds', 'weights', 'patterns'] as $section) {
                foreach ($child[$section] as $key => $value) {
                    if ($key !== 'honeypotScore') {
                        $child[$section][$key] = ($c1[$section][$key] + $c2[$section][$key]) / 2;
                    }
                }
            }
            return $child;
        };

        $mutate = function (array $c): array {
            $newConfig = $c;
            $sections = [
                ['name' => 'patterns', 'weight' => 0.5],
                ['name' => 'weights', 'weight' => 0.35],
                ['name' => 'thresholds', 'weight' => 0.15]
            ];
            $rand = self::secureRandom();
            $cumulativeWeight = 0;
            $sectionToMutate = 'patterns';
            foreach ($sections as $section) {
                $cumulativeWeight += $section['weight'];
                if ($rand < $cumulativeWeight) {
                    $sectionToMutate = $section['name'];
                    break;
                }
            }

            $keys = array_keys($newConfig[$sectionToMutate]);
            $keyToMutate = $keys[random_int(0, count($keys) - 1)];

            if ($keyToMutate === 'honeypotScore') return $newConfig;

            $mutationAmount = (self::secureRandom() - 0.5) * 0.4;
            $newConfig[$sectionToMutate][$keyToMutate] *= (1 + $mutationAmount);

            if ($sectionToMutate === 'weights') {
                $newConfig[$sectionToMutate][$keyToMutate] = max(0, min(1.5, $newConfig[$sectionToMutate][$keyToMutate]));
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
    }
}
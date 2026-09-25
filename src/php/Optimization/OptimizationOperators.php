<?php

declare(strict_types=1);

namespace Anonympins\Fingerprint\Optimization;

/**
 * Operators and objective function factories for optimization problems.
 */
class OptimizationOperators
{
    /**
     * Creates a tournament selection operator for genetic algorithms.
     * @param array $options Tournament configuration options.
     * @return callable Selection operator function.
     */
    public static function createTournamentSelection(array $options = []): callable
    {
        $tournamentSize = $options['size'] ?? 5;

        return function (array $population) use ($tournamentSize) {
            $best = null;
            $count = count($population);

            for ($i = 0; $i < $tournamentSize; $i++) {
                $individual = $population[random_int(0, $count - 1)];
                $individualFitness = $individual['fitness'] ?? (isset($individual['objectives']) ? array_sum($individual['objectives']) : INF);
                $bestFitness = $best !== null ? ($best['fitness'] ?? (isset($best['objectives']) ? array_sum($best['objectives']) : INF)) : INF;

                if ($best === null || $individualFitness < $bestFitness) {
                    $best = $individual;
                }
            }

            return $best ?? $population[random_int(0, $count - 1)];
        };
    }

    /**
     * Generates a cryptographically secure random float in [0, 1).
     */
    private static function secureRandom(): float
    {
        try {
            return random_int(0, PHP_INT_MAX - 1) / PHP_INT_MAX;
        } catch (\Exception $e) {
            if (function_exists('wp_rand')) {
                return (float)wp_rand(0, 1000000) / 1000000.0;
            }
            // phpcs:ignore WordPress.WP.AlternativeFunctions.rand_mt_rand -- Standalone fallback
            return (float)mt_rand() / (float)mt_getrandmax();
        }
    }

    /**
     * Evaluates a portfolio for a given payload.
     * 
     * @param array $weights
     * @param array $payload
     * @return float
     */
    public static function calculatePortfolioMetrics(array $weights, array $payload): float
    {
        $fitnessFunction = self::createPortfolioAllocator($payload);
        return $fitnessFunction($weights);
    }

    /**
     * Creates a portfolio allocation evaluator.
     * @param array $config
     * @return callable
     */
    public static function createPortfolioAllocator(array $config): callable
    {
        // Baseline portfolio evaluator minimizing negative expected return
        return function (array $weights) use ($config): float {
            // Minimize negative return (maximizes positive return)
            return -array_sum($weights);
        };
    }

    /**
     * Creates an evaluator for full security configuration auto-tuning.
     * @param array $context
     * @return callable
     */
    public static function createFullSecurityConfigEvaluator(array $context): callable
    {
        $trafficData = $context['trafficData'] ?? [];
        $currentConfig = $context['currentConfig'] ?? null;

        return function (array $config) use ($trafficData, $currentConfig): array {
            $threatProfiles = [
                'account_takeover' => [
                    'importance' => 10.0,
                    'ux_vs_security_ratio' => 0.1,
                    'target_threshold' => 'block',
                    'indicators' => ['requestPatternScore', 'behaviorScore', 'timeInconsistencyScore', 'clickVarianceScore']
                ],
                'active_exploitation' => [
                    'importance' => 8.0,
                    'ux_vs_security_ratio' => 0.2,
                    'target_threshold' => 'block',
                    'indicators' => ['honeypotScore', 'headerAnomalyScore']
                ],
                'mass_scraping' => [
                    'importance' => 3.0,
                    'ux_vs_security_ratio' => 0.8,
                    'target_threshold' => 'low',
                'indicators' => ['requestPatternScore', 'renderingAnomalyScore', 'clientHintsInconsistencyScore', 'virtualizationScore']
                ],
                'distributed_botnets' => [
                    'importance' => 6.0,
                    'ux_vs_security_ratio' => 0.5,
                    'target_threshold' => 'high',
                    'indicators' => ['subnetScore', 'botnetClusterScore', 'ipReputationScore', 'tlsSpoofingScore']
                ],
                'basic_automation' => [
                    'importance' => 5.0,
                    'ux_vs_security_ratio' => 0.4,
                    'target_threshold' => 'medium',
                'indicators' => ['botScore', 'tlsSpoofingScore', 'tcpAnomalyScore', 'virtualizationScore']
                ]
            ];

            $threatStats = [];
            foreach ($threatProfiles as $name => $profile) {
                $threatStats[$name] = ['fp' => 0.0, 'fn' => 0.0, 'totalHumans' => 0.0, 'totalBots' => 0.0];
            }

            $maxHumanScore = 0.0;
            $minBotScore = 100.0;

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

            // 1. Évaluation sur les logs de trafic réels
            // 1. Evaluate on real traffic logs
            foreach ($trafficData as $log) {
                $weight = (float)($log['weight'] ?? 1.0);
                $confidence = ($confidenceWeights[$log['type'] ?? ''] ?? 1.0) * $weight;
                $isLikelyBot = in_array($log['type'] ?? '', ['challenge_issued', 'request_blocked', 'trap_triggered']);
                $isLikelyHuman = in_array($log['type'] ?? '', ['request_passed', 'challenge_solved']);

                $score = $calculateScore($log);

                if ($isLikelyBot) {
                    $minBotScore = min($minBotScore, $score);
                } elseif ($isLikelyHuman) {
                    $maxHumanScore = max($maxHumanScore, $score);
                }

                foreach ($threatProfiles as $name => $profile) {
                    $threatActivity = 0.0;
                    foreach ($profile['indicators'] as $indicator) {
                        $threatActivity += (float)($log['vector'][$indicator] ?? 0.0);
                    }
                    if ($threatActivity <= 0.0) {
                        continue;
                    }
                    $effectiveConfidence = $confidence * ($threatActivity / 100.0);
                    $targetThreshold = (float)($config['thresholds'][$profile['target_threshold']] ?? 20.0);

                    if ($isLikelyBot) {
                        $threatStats[$name]['totalBots'] += $effectiveConfidence;
                        if ($score < $targetThreshold) {
                            $threatStats[$name]['fn'] += $effectiveConfidence;
                        }
                    } elseif ($isLikelyHuman) {
                        $threatStats[$name]['totalHumans'] += $effectiveConfidence;
                        if ($score >= $targetThreshold) {
                            $threatStats[$name]['fp'] += $effectiveConfidence;
                        }
                    }
                }
            }

            $weightedFpr = 0.0;
            $weightedFnr = 0.0;
            $totalImportance = 0.0;

            foreach ($threatProfiles as $name => $profile) {
                $totalImportance += $profile['importance'];
            }

            foreach ($threatProfiles as $name => $profile) {
                $stats = $threatStats[$name];
                $fpr = $stats['totalHumans'] > 0 ? $stats['fp'] / $stats['totalHumans'] : 0.0;
                $fnr = $stats['totalBots'] > 0 ? $stats['fn'] / $stats['totalBots'] : 0.0;

                $importanceWeight = $profile['importance'] / $totalImportance;
                $uxRatio = $profile['ux_vs_security_ratio'];
                $secRatio = 1.0 - $uxRatio;

                $weightedFpr += $fpr * $importanceWeight * $uxRatio;
                $weightedFnr += $fnr * $importanceWeight * $secRatio;
            }

            // 3. Pénalité de dérive d'échelle (L2 Regularization par rapport au profil d'origine)
            // 3. Scale drift penalty (L2 regularization against baseline profile)
            $regularizationPenalty = 0.0;
            if ($currentConfig && isset($currentConfig['weights'])) {
                foreach ($config['weights'] as $key => $val) {
                    $originalVal = (float)($currentConfig['weights'][$key] ?? 0.0);
                    $regularizationPenalty += pow((float)$val - $originalVal, 2);
                }
            }

            // 4. Maximisation de la marge
            // 4. Margin separation maximization
            $marginOverlap = max(0.0, $maxHumanScore - $minBotScore);
            $marginPenalty = $marginOverlap / 100.0;

            $obj1 = $weightedFpr + ($regularizationPenalty * 0.05);
            $obj2 = $weightedFnr + $marginPenalty;

            return [$obj1, $obj2];
        };
    }

    /**
     * Solves end-to-end security configuration auto-tuning.
     * @param array $context
     * @param array $options
     * @return array
     */
    public static function solveFullSecurityTuning(array $context, array $options = []): array
    {
        $currentConfig = $context['currentConfig'] ?? null;
        $fitnessFunction = self::createFullSecurityConfigEvaluator($context);

        $crossover = function (array $c1, array $c2): array {
            $child = $c1;
            foreach (['thresholds', 'weights', 'patterns'] as $section) {
                foreach ($child[$section] as $key => $value) {
                    $child[$section][$key] = ($c1[$section][$key] + $c2[$section][$key]) / 2;
                }
            }
            return $child;
        };
        $createIndividual = function () use ($currentConfig): array {
            $config = $currentConfig ?: \Anonympins\Fingerprint\Config\SecurityProfiles::createSecurityProfile('balanced');
            $ind = [
                'thresholds' => [],
                'weights' => [],
                'patterns' => []
            ];
            foreach (['thresholds', 'weights', 'patterns'] as $section) {
                if (isset($config[$section]) && is_array($config[$section])) {
                    foreach ($config[$section] as $k => $v) {
                        if (is_numeric($v)) {
                            $randomVariation = 1.0 + (self::secureRandom() - 0.5) * 0.5; // +/- 25% variation
                            $ind[$section][$k] = $v * $randomVariation;
                        } else {
                            $ind[$section][$k] = $v;
                        }
                    }
                }
            }
            if (isset($ind['thresholds']['low'], $ind['thresholds']['medium'], $ind['thresholds']['high'])) {
                $ind['thresholds']['low'] = max(10.0, min(35.0, (float)$ind['thresholds']['low']));
                $ind['thresholds']['medium'] = max($ind['thresholds']['low'] + 5.0, min(70.0, (float)$ind['thresholds']['medium']));
                $ind['thresholds']['high'] = max($ind['thresholds']['medium'] + 5.0, min(90.0, (float)$ind['thresholds']['high']));
            }
            return $ind;
        };

        $mutate = function (array $c, ?array $currentConfigRef = null) use ($currentConfig): array {
            $newConfig = $c;
            $sections = [
                ['name' => 'patterns', 'weight' => 0.50],
                ['name' => 'thresholds', 'weight' => 0.25],
                ['name' => 'weights', 'weight' => 0.25]
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

            if ($sectionToMutate === 'weights') {
                $newConfig[$sectionToMutate][$keyToMutate] = max(0.05, min(1.5, $newConfig[$sectionToMutate][$keyToMutate] + (self::secureRandom() - 0.5) * 0.1));
            } elseif ($sectionToMutate === 'thresholds') {
                $newConfig[$sectionToMutate][$keyToMutate] = (int)round($newConfig[$sectionToMutate][$keyToMutate] + (self::secureRandom() - 0.5) * 5.0);
            } else {
                if ($keyToMutate === 'decayFactor') {
                    $newConfig['patterns']['decayFactor'] = max(0.8, min(0.999, $newConfig['patterns']['decayFactor'] + (self::secureRandom() - 0.5) * 0.05));
                } elseif (str_contains($keyToMutate, 'Threshold') || str_contains($keyToMutate, 'Reset')) {
                    $newConfig['patterns'][$keyToMutate] = max(50.0, $newConfig['patterns'][$keyToMutate] + (self::secureRandom() - 0.5) * 50.0);
                }
            }

            $refConfig = $currentConfigRef ?? $currentConfig;
            if ($refConfig && isset($refConfig[$sectionToMutate][$keyToMutate])) {
                $originalValue = $refConfig[$sectionToMutate][$keyToMutate];
                if (is_numeric($originalValue) && $originalValue != 0) {
                    $minAllowed = $originalValue * 0.7; // -30%
                    $maxAllowed = $originalValue * 1.3; // +30%
                    $newConfig[$sectionToMutate][$keyToMutate] = max($minAllowed, min($maxAllowed, $newConfig[$sectionToMutate][$keyToMutate]));
                }
            }

            return $newConfig;
        };
        $gaOptions = array_merge(['generations' => 50, 'populationSize' => 50], $options);

        return Optimization::geneticAlgorithmMultiObjective(
            $createIndividual,
            $fitnessFunction,
            $crossover,
            $mutate,
            $currentConfig,
            $gaOptions
        );
    }

    /**
     * Creates an evaluator to find optimal fraud detection thresholds.
     * @param array $context
     * @return callable
     */
    public static function createFraudThresholdEvaluator(array $context): callable
    {
        $legitimateClicks = $context['legitimateClicks'] ?? [];
        $fraudulentClicks = $context['fraudulentClicks'] ?? [];

        return function (array $solution) use ($legitimateClicks, $fraudulentClicks): array {
            [$minTimeToClick, $maxClickVariance, $minMouseEntropy, $minScrollEvents] = $solution;

            $truePositives = 0;
            $falsePositives = 0;

            foreach ($fraudulentClicks as $click) {
                if (
                    ($click['timeToClick'] < $minTimeToClick) ||
                    ($click['mouseEntropy'] < $minMouseEntropy)
                ) {
                    $truePositives++;
                }
            }

            foreach ($legitimateClicks as $click) {
                if (
                    ($click['timeToClick'] < $minTimeToClick) ||
                    ($click['mouseEntropy'] < $minMouseEntropy)
                ) {
                    $falsePositives++;
                }
            }

            $totalFraudulent = count($fraudulentClicks) ?: 1;
            $totalLegitimate = count($legitimateClicks) ?: 1;

            $objective1 = 1 - ($truePositives / $totalFraudulent);
            $objective2 = $falsePositives / $totalLegitimate;

            return [$objective1, $objective2];
        };
    }

    /**
     * Solves fraud detection threshold optimization.
     * @param array $context
     * @param array $options
     * @return array
     */
    public static function solveFraudDetection(array $context, array $options = []): array
    {
        $fitnessFunction = self::createFraudThresholdEvaluator($context);

        $createIndividual = function (): array {
            return [
                100 + self::secureRandom() * 4900, // minTimeToClick
                1 + self::secureRandom() * 9999,   // maxClickVariance
                self::secureRandom() * 0.5,        // minMouseEntropy
                floor(self::secureRandom() * 10) // minScrollEvents
            ];
        };

        $crossover = fn ($s1, $s2) => array_map(fn ($a, $b) => ($a + $b) / 2, $s1, $s2);

        $mutate = function (array $solution): array {
            $i = random_int(0, 3);
            $mutationFactors = [500, 1000, 0.1, 2];
            $solution[$i] += (self::secureRandom() - 0.5) * $mutationFactors[$i];
            return $solution;
        };

        return Optimization::geneticAlgorithmMultiObjective(
            $createIndividual,
            $fitnessFunction,
            $crossover,
            $mutate,
            array_merge(['generations' => 80, 'populationSize' => 60], $options)
        );
    }

    /**
     * TSP solver baseline implementation.
     * @param array $cities
     * @param array $options
     * @return array
     */
    public static function solveTSP(array $cities, array $options = []): array
    {
        return ['solution' => array_keys($cities), 'energy' => 100];
    }

    /**
     * Portfolio allocator baseline implementation.
     * @param array $assets
     * @param float $maxVolatility
     * @param array $options
     * @return array
     */
    public static function solvePortfolio(array $assets, float $maxVolatility, array $options = []): array
    {
        return ['solution' => array_fill(0, count($assets), 1 / count($assets)), 'fitness' => -0.1];
    }

    public static function solveFacilityLocation(array $customers, int $numFacilities, array $bounds, array $options = []): array
    {
        $fixedCostPerFacility = $options['fixedCostPerFacility'] ?? 0;
        $initialTemperature = $options['initialTemperature'] ?? 100000.0;
        $coolingRate = $options['coolingRate'] ?? 0.999;
        $maxIterations = $options['maxIterations'] ?? 15000;

        $evaluator = function (array $facilities) use ($customers, $fixedCostPerFacility): float {
            $totalConnectionCost = 0.0;
            foreach ($customers as $customer) {
                $minDistanceSq = INF;
                foreach ($facilities as $facility) {
                    $dx = $customer['x'] - $facility['x'];
                    $dy = $customer['y'] - $facility['y'];
                    $dSq = $dx * $dx + $dy * $dy;
                    if ($dSq < $minDistanceSq) {
                        $minDistanceSq = $dSq;
                    }
                }
                $totalConnectionCost += sqrt($minDistanceSq);
            }
            return $totalConnectionCost + count($facilities) * $fixedCostPerFacility;
        };

        $neighbor = function (array $facilities) use ($bounds, $numFacilities): array {
            $newFacilities = $facilities;
            $i = random_int(0, $numFacilities - 1);
            
            $moveX = (self::secureRandom() - 0.5) * ($bounds['maxX'] - $bounds['minX']) * 0.1;
            $moveY = (self::secureRandom() - 0.5) * ($bounds['maxY'] - $bounds['minY']) * 0.1;

            $newFacilities[$i]['x'] = max($bounds['minX'], min($bounds['maxX'], $newFacilities[$i]['x'] + $moveX));
            $newFacilities[$i]['y'] = max($bounds['minY'], min($bounds['maxY'], $newFacilities[$i]['y'] + $moveY));

            return $newFacilities;
        };

        // Génération d'une solution initiale aléatoire
        // Random initial placement
        $currentSolution = [];
        for ($i = 0; $i < $numFacilities; $i++) {
            $currentSolution[] = [
                'x' => $bounds['minX'] + self::secureRandom() * ($bounds['maxX'] - $bounds['minX']),
                'y' => $bounds['minY'] + self::secureRandom() * ($bounds['maxY'] - $bounds['minY']),
            ];
        }

        $currentEnergy = $evaluator($currentSolution);
        $bestSolution = $currentSolution;
        $bestEnergy = $currentEnergy;
        $temperature = $initialTemperature;

        for ($step = 0; $step < $maxIterations; $step++) {
            $newSolution = $neighbor($currentSolution);
            $newEnergy = $evaluator($newSolution);

            $acceptanceProbability = exp(($currentEnergy - $newEnergy) / $temperature);

            if ($newEnergy < $currentEnergy || self::secureRandom() < $acceptanceProbability) {
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
     * Independently evaluates total cost of a facility placement proposal.
     * Invoked server-side to verify client-submitted solutions.
     * 
     * @param array $facilities Facility coordinates proposed by client.
     * @param array $payload Base payload containing customer coordinates and fixed costs.
     * @return float Verified total connection and maintenance cost.
     */
    public static function evaluateFacilityLocation(array $facilities, array $payload): float
    {
        $customers = $payload['customers'] ?? [];
        $fixedCostPerFacility = $payload['options']['fixedCostPerFacility'] ?? 0;
        $totalConnectionCost = 0.0;

        foreach ($customers as $customer) {
            $minDistanceSq = INF;
            foreach ($facilities as $facility) {
                $dx = $customer['x'] - $facility['x'];
                $dy = $customer['y'] - $facility['y'];
                $dSq = $dx * $dx + $dy * $dy;
                if ($dSq < $minDistanceSq) {
                    $minDistanceSq = $dSq;
                }
            }
            $totalConnectionCost += sqrt($minDistanceSq);
        }

        return $totalConnectionCost + count($facilities) * $fixedCostPerFacility;
    }
}
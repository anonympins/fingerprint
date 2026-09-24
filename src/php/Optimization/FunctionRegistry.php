<?php

declare(strict_types=1);

namespace Anonympins\Fingerprint\Optimization;

/**
 * Registry to safely expose optimization library routines to task runners.
 */
class FunctionRegistry
{
    /** @var array<string, callable> */
    private static array $functions = [];

    /**
     * Initializes registry with built-in solvers and evaluators.
     */
    private static function initialize(): void
    {
        if (empty(self::$functions)) {
            // Evaluators & Scoring Adapters
            self::$functions['tsp.calculateEnergy'] = [OptimizationUtils::class, 'evaluatePathDistance'];
            self::$functions['portfolio.calculateMetrics'] = [OptimizationOperators::class, 'calculatePortfolioMetrics'];
            self::$functions['facility.calculateEnergy'] = [OptimizationOperators::class, 'evaluateFacilityLocation'];

            // Full Optimization Solvers
            self::$functions['tsp.solve'] = [OptimizationOperators::class, 'solveTSP'];
            self::$functions['portfolio.solve'] = [OptimizationOperators::class, 'solvePortfolio'];
            self::$functions['fraud.solve'] = [OptimizationOperators::class, 'solveFraudDetection'];
            self::$functions['facility.solve'] = [OptimizationOperators::class, 'solveFacilityLocation'];
            self::$functions['security.tune'] = [OptimizationOperators::class, 'solveFullSecurityTuning'];
        }
    }

    /**
     * Retrieves a function from the registry.
     */
    public static function get(string $name): ?callable
    {
        self::initialize();
        return self::$functions[$name] ?? null;
    }
    /**
     * Registers a custom function. Primarily intended for testing.
     * @internal
     * @param string $name
     * @param callable $function
     * @return void
     */
    public static function register(string $name, callable $function): void
    {
        self::initialize();
        self::$functions[$name] = $function;
    }

    /**
     * Resets function registry. Intended for testing.
     * @internal
     */
    public static function __internal_resetRegistry(): void
    {
        self::$functions = [];
    }
}
<?php

declare(strict_types=1);

namespace Anonympins\Fingerprint\Optimization;

/**
 * Registre pour exposer de manière contrôlée les fonctions de la bibliothèque d'optimisation.
 */
class FunctionRegistry
{
    /** @var array<string, callable> */
    private static array $functions = [];

    /**
     * Initialise le registre avec les fonctions disponibles.
     */
    private static function initialize(): void
    {
        if (empty(self::$functions)) {
            // Fonctions de "Scoring"
            self::$functions['tsp.calculateEnergy'] = [OptimizationUtils::class, 'evaluatePathDistance'];
            self::$functions['portfolio.calculateMetrics'] = [OptimizationOperators::class, 'createPortfolioAllocator'];

            // Fonctions de "Résolution"
            self::$functions['tsp.solve'] = [OptimizationOperators::class, 'solveTSP'];
            self::$functions['portfolio.solve'] = [OptimizationOperators::class, 'solvePortfolio'];
            self::$functions['fraud.solve'] = [OptimizationOperators::class, 'solveFraudDetection'];
            self::$functions['facility.solve'] = [OptimizationOperators::class, 'solveFacilityLocation'];
            self::$functions['security.tune'] = [OptimizationOperators::class, 'solveFullSecurityTuning'];
        }
    }

    /**
     * Récupère une fonction depuis le registre.
     */
    public static function get(string $name): ?callable
    {
        self::initialize();
        return self::$functions[$name] ?? null;
    }
    /**
     * Enregistre une nouvelle fonction. Principalement pour les tests.
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
     * Réinitialise le registre. Uniquement pour les tests.
     * @internal
     */
    public static function __internal_resetRegistry(): void
    {
        self::$functions = [];
    }
}
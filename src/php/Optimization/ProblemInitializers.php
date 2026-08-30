<?php

declare(strict_types=1);

namespace Anonympins\Fingerprint\Optimization;

/**
 * Fonctions pour générer dynamiquement les données d'un problème.
 */
class ProblemInitializers
{
    /** @var array<string, callable> */
    private static array $initializers = [];

    private static function initialize(): void
    {
        if (empty(self::$initializers)) {
            self::$initializers['generate:randomPoints'] = function (array $params): array {
                $count = $params['count'] ?? 0;
                $bounds = $params['bounds'] ?? ['x' => 1000, 'y' => 1000];
                if (!is_numeric($count)) return [];
                $points = [];
                for ($i = 0; $i < $count; $i++) {
                    $points[] = [
                        'x' => mt_rand() / mt_getrandmax() * $bounds['x'],
                        'y' => mt_rand() / mt_getrandmax() * $bounds['y']
                    ];
                }
                return $points;
            };

            self::$initializers['generate:randomAssets'] = function (array $params): array {
                $count = $params['count'] ?? 0;
                if (!is_numeric($count)) return [];
                $assets = [];
                for ($i = 0; $i < $count; $i++) {
                    $assets[] = [
                        'name' => 'Asset ' . ($i + 1),
                        'expectedReturn' => mt_rand() / mt_getrandmax() * 0.2,
                        'volatility' => 0.1 + mt_rand() / mt_getrandmax() * 0.3
                    ];
                }
                return $assets;
            };
        }
    }

    public static function get(string $name): ?callable
    {
        self::initialize();
        return self::$initializers[$name] ?? null;
    }
}
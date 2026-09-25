<?php

declare(strict_types=1);

namespace Anonympins\Fingerprint\Optimization;

/**
 * Generators for dynamically seeding problem instance datasets.
 */
class ProblemInitializers
{
    /** @var array<string, callable> */
    private static array $initializers = [];

    private static function randomFloat(): float
    {
        try {
            return (float)random_int(0, PHP_INT_MAX - 1) / (float)PHP_INT_MAX;
        } catch (\Throwable $e) {
            if (function_exists('wp_rand')) {
                return (float)wp_rand(0, 1000000) / 1000000.0;
            }
            return 0.5;
        }
    }

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
                        'x' => self::randomFloat() * $bounds['x'],
                        'y' => self::randomFloat() * $bounds['y']
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
                        'expectedReturn' => self::randomFloat() * 0.2,
                        'volatility' => 0.1 + self::randomFloat() * 0.3
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
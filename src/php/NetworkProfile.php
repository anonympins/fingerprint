<?php

declare(strict_types=1);

namespace Anonympins\Fingerprint;

/**
 * Profils de connectivité réseau et paramètres de modulation pour le scoring analogique.
 */
class NetworkProfile
{
    public const RESIDENTIAL = 'RESIDENTIAL';
    public const CELLULAR = 'CELLULAR';
    public const SATELLITE = 'SATELLITE';
    public const HOSTING = 'HOSTING';
    public const ANONYMIZER = 'ANONYMIZER';

    private string $type;
    private float $baseScore;
    private float $inflectionPoint;
    private bool $toleranceRotation;
    private float $jitterTolerance;

    public function __construct(
        string $type,
        float $baseScore,
        float $inflectionPoint,
        bool $toleranceRotation,
        float $jitterTolerance
    ) {
        $this->type = $type;
        $this->baseScore = $baseScore;
        $this->inflectionPoint = $inflectionPoint;
        $this->toleranceRotation = $toleranceRotation;
        $this->jitterTolerance = $jitterTolerance;
    }

    public function getType(): string { return $this->type; }
    public function getBaseScore(): float { return $this->baseScore; }
    public function getInflectionPoint(): float { return $this->inflectionPoint; }
    public function isToleranceRotation(): bool { return $this->toleranceRotation; }
    public function getJitterTolerance(): float { return $this->jitterTolerance; }

    public static function residential(): self
    {
        return new self(self::RESIDENTIAL, 0.0, 0.72, false, 60.0);
    }

    public static function cellular(): self
    {
        return new self(self::CELLULAR, 10.0, 0.60, true, 80.0);
    }

    public static function satellite(): self
    {
        return new self(self::SATELLITE, 15.0, 0.68, false, 150.0);
    }

    public static function hosting(): self
    {
        return new self(self::HOSTING, 55.0, 0.85, false, 30.0);
    }

    public static function anonymizer(): self
    {
        return new self(self::ANONYMIZER, 85.0, 0.90, false, 40.0);
    }
}
<?php

declare(strict_types=1);

namespace Anonympins\Fingerprint\Utils;

/**
 * Classe d'émulation pour les opérations sur de grands entiers (BigInt),
 * similaire au BigInt de JavaScript. Utilise l'extension GMP.
 * @internal
 */
class BigInt
{
    /** @var \GMP */
    private \GMP $gmp;

    /**
     * @param \GMP|string|int $number
     */
    public function __construct($number)
    {
        if ($number instanceof \GMP) {
            $this->gmp = $number;
        } else {
            $this->gmp = gmp_init($number);
        }
    }

    /**
     * Crée une instance à partir d'une chaîne hexadécimale.
     */
    public static function fromHex(string $hex): self
    {
        return new self(gmp_init($hex, 16));
    }

    /**
     * Compare cette instance avec une autre.
     * @return int < 0 si this < other, 0 si this == other, > 0 si this > other.
     */
    public function compareTo(self $other): int
    {
        return gmp_cmp($this->gmp, $other->gmp);
    }

    /**
     * Effectue un décalage de bits vers la gauche (<<).
     */
    public function shiftLeft(int $bits): self
    {
        return new self(gmp_mul($this->gmp, gmp_pow(2, $bits)));
    }

    /**
     * Effectue un décalage de bits vers la droite (>>).
     */
    public function shiftRight(int $bits): self
    {
        return new self(gmp_div_q($this->gmp, gmp_pow(2, $bits)));
    }

    /**
     * Retourne la représentation en chaîne de caractères.
     */
    public function __toString(): string
    {
        return gmp_strval($this->gmp);
    }

    /**
     * Retourne la représentation hexadécimale.
     */
    public function toHex(): string
    {
        return gmp_strval($this->gmp, 16);
    }

    /**
     * Retourne la valeur GMP sous-jacente.
     * @return \GMP
     */
    public function getGmpValue(): \GMP
    {
        return $this->gmp;
    }

    /**
     * Crée une instance à partir d'une puissance de 2.
     */
    public static function pow(int $base, int $exp): self
    {
        return new self(gmp_pow($base, $exp));
    }

    /**
     * Soustrait un autre BigInt.
     */
    public function sub(self $other): self
    {
        return new self(gmp_sub($this->gmp, $other->gmp));
    }
}
<?php

declare(strict_types=1);

namespace Anonympins\Fingerprint\Utils;

class BigInt
{
    private static bool $useGmp;
    /** @var \GMP|string */
    private $value;

    /**
     * @param \GMP|string|int $number Le nombre initial.
     */
    public function __construct($number)
    {
        if (!isset(self::$useGmp)) {
            self::$useGmp = extension_loaded('gmp');
        }

        if (self::$useGmp) {
            if ($number instanceof \GMP) {
                $this->value = $number;
            } else {
                $this->value = gmp_init($number);
            }
        } else {
            if ($number instanceof BigInt) {
                $this->value = $number->value;
            } else {
                $this->value = (string)$number;
            }
        }
    }

    /**
     * Crée une instance à partir d'une chaîne hexadécimale.
     */
    public static function fromHex(string $hex): BigInt
    {
        if (self::$useGmp) {
            return new self(gmp_init($hex, 16));
        } else {
            $dec = '0';
            $len = strlen($hex);
            for ($i = 0; $i < $len; $i++) {
                $dec = bcadd(bcmul($dec, '16'), (string)hexdec($hex[$i]));
            }
            return new self($dec);
        }
    }

    /**
     * Compare cette instance avec une autre.
     * @return int < 0 si this < other, 0 si this == other, > 0 si this > other.
     */
    public function compareTo(BigInt $other): int
    {
        if (self::$useGmp) {
            return gmp_cmp($this->value, $other->value);
        } else {
            return bccomp($this->value, $other->value);
        }
    }

    /**
     * Effectue un décalage de bits vers la gauche (<<).
     */
    public function shiftLeft(int $bits): BigInt
    {
        if (self::$useGmp) {
            return new self(gmp_mul($this->value, gmp_pow("2", $bits)));
        } else {
            return new self(bcmul($this->value, bcpow("2", (string)$bits)));
        }
    }

    /**
     * Effectue un décalage de bits vers la droite (>>).
     */
    public function shiftRight(int $bits): BigInt
    {
        if (self::$useGmp) {
            return new self(gmp_div_q($this->value, gmp_pow("2", $bits)));
        } else {
            return new self(bcdiv($this->value, bcpow("2", (string)$bits)));
        }
    }

    /**
     * Retourne la représentation en chaîne de caractères.
     */
    public function __toString(): string
    {
        if (self::$useGmp) {
            return gmp_strval($this->value);
        } else {
            return $this->value;
        }
    }

    /**
     * Retourne la représentation hexadécimale.
     */
    public function toHex(): string
    {
        if (self::$useGmp) {
            return gmp_strval($this->value, 16);
        } else {
            $hex = '';
            $dec = $this->value;
            while (bccomp($dec, '0') > 0) {
                $rem = bcmod($dec, '16');
                $hex = dechex((int)$rem) . $hex;
                $dec = bcdiv($dec, '16');
            }
            return $hex ?: '0';
        }
    }

    /**
     * Crée une instance à partir d'une puissance de 2.
     */
    public static function pow(int $base, int $exp): BigInt
    {
        if (self::$useGgmp) {
            return new self(gmp_pow((string)$base, $exp));
        } else {
            return new self(bcpow((string)$base, (string)$exp));
        }
    }

    /**
     * Soustrait un autre BigInt.
     */
    public function sub(BigInt $other): BigInt
    {
        if (self::$useGmp) {
            return new self(gmp_sub($this->value, $other->value));
        } else {
            return new self(bcsub($this->value, $other->value));
        }
    }
}
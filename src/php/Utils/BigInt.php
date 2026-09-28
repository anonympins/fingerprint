<?php

declare(strict_types=1);

namespace Anonympins\Fingerprint\Utils;

class BigInt
{
    private static ?bool $useGmp = null;
    /** @var \GMP|string */
    private $value;

    private static function useGmp(): bool
    {
        if (self::$useGmp === null) {
            self::$useGmp = extension_loaded('gmp');
        }
        return self::$useGmp;
    }

    /**
     * @param \GMP|string|int $number Initial number.
     */
    public function __construct($number)
    {
        if (self::useGmp()) {
            if ($number instanceof \GMP) {
                $this->value = $number;
            } else {
                $str = (string)$number;
                if (($dot = strpos($str, '.')) !== false) {
                    $str = substr($str, 0, $dot);
                }
                $this->value = gmp_init($str);
            }
        } else {
            if ($number instanceof BigInt) {
                $this->value = $number->value;
            } else {
                $str = (string)$number;
                if (($dot = strpos($str, '.')) !== false) {
                    $str = substr($str, 0, $dot);
                }
                $this->value = $str;
            }
        }
    }

    /**
     * Creates an instance from a hexadecimal string.
     */
    public static function fromHex(string $hex): BigInt
    {
        $hex = trim(strtolower($hex));
        if (substr($hex, 0, 2) === '0x') {
            $hex = substr($hex, 2);
        }
        if (self::useGmp()) {
            return new self(gmp_init($hex, 16));
        } else {
            $dec = '0';
            $len = strlen($hex);
            for ($i = 0; $i < $len; $i++) {
                $dec = bcadd(bcmul($dec, '16', 0), (string)hexdec($hex[$i]), 0);
            }
            return new self($dec);
        }
    }

    /**
     * Compares this instance with another.
     * @return int < 0 if this < other, 0 if this == other, > 0 if this > other.
     */
    public function compareTo(BigInt $other): int
    {
        if (self::useGmp()) {
            return gmp_cmp($this->value, $other->value);
        } else {
            return bccomp($this->value, $other->value, 0);
        }
    }

    /**
     * Performs bitwise left shift (<<).
     */
    public function shiftLeft(int $bits): BigInt
    {
        if (self::useGmp()) {
            return new self(gmp_mul($this->value, gmp_pow("2", $bits)));
        } else {
            return new self(bcmul($this->value, bcpow("2", (string)$bits, 0), 0));
        }
    }

    /**
     * Performs bitwise right shift (>>).
     */
    public function shiftRight(int $bits): BigInt
    {
        if (self::useGmp()) {
            return new self(gmp_div_q($this->value, gmp_pow("2", $bits)));
        } else {
            return new self(bcdiv($this->value, bcpow("2", (string)$bits, 0), 0));
        }
    }

    /**
     * Returns the string representation.
     */
    public function __toString(): string
    {
        if (self::useGmp()) {
            return gmp_strval($this->value);
        } else {
            return $this->value;
        }
    }

    /**
     * Returns the hexadecimal representation.
     */
    public function toHex(): string
    {
        if (self::useGmp()) {
            return gmp_strval($this->value, 16);
        } else {
            $hex = '';
            $dec = $this->value;
            while (bccomp($dec, '0', 0) > 0) {
                $rem = bcmod($dec, '16', 0);
                $hex = dechex((int)$rem) . $hex;
                $dec = bcdiv($dec, '16', 0);
            }
            return $hex ?: '0';
        }
    }

    /**
     * Creates an instance from a power of two.
     */
    public static function pow(int $base, int $exp): BigInt
    {
        if (self::useGmp()) {
            return new self(gmp_pow((string)$base, $exp));
        } else {
            return new self(bcpow((string)$base, (string)$exp, 0));
        }
    }

    /**
     * Subtracts another BigInt.
     */
    public function sub(BigInt $other): BigInt
    {
        if (self::useGmp()) {
            return new self(gmp_sub($this->value, $other->value));
        } else {
            return new self(bcsub($this->value, $other->value, 0));
        }
    }

    /**
     * Computes ($this ^ $exponent) % $modulus
     */
    public function modPow(BigInt $exponent, BigInt $modulus): BigInt
    {
        if (self::useGmp()) {
            return new self(gmp_powm($this->value, $exponent->value, $modulus->value));
        } else {
            return new self(bcpowmod((string)$this->value, (string)$exponent->value, (string)$modulus->value, 0));
        }
    }

    /**
     * Computes $this % $modulus
     */
    public function mod(BigInt $modulus): BigInt
    {
        if (self::useGmp()) {
            return new self(gmp_mod($this->value, $modulus->value));
        } else {
            return new self(bcmod((string)$this->value, (string)$modulus->value, 0));
        }
    }

    public function add(BigInt $other): BigInt
    {
        if (self::useGmp()) {
            return new self(gmp_add($this->value, $other->value));
        } else {
            return new self(bcadd((string)$this->value, (string)$other->value, 0));
        }
    }

    public function mul(BigInt $other): BigInt
    {
        if (self::useGmp()) {
            return new self(gmp_mul($this->value, $other->value));
        } else {
            return new self(bcmul((string)$this->value, (string)$other->value, 0));
        }
    }
}
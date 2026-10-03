<?php

declare(strict_types=1);

namespace Anonympins\Fingerprint\Crdt;

/**
 * Filtre de Bloom à double hachage SHA-256 avec compression Zlib.
 * Assure une interopérabilité binaire stricte avec Node.js, Java et Python.
 */
class BloomFilterSync
{
    private int $bitSize;
    private int $numHashFunctions;
    private string $buffer;

    public function __construct(int $bitSize, int $numHashFunctions, ?string $rawBuffer = null)
    {
        $this->bitSize = max(64, $bitSize);
        $this->numHashFunctions = max(1, $numHashFunctions);
        $byteLen = (int)ceil($this->bitSize / 8);
        $this->buffer = $rawBuffer !== null ? $rawBuffer : str_repeat("\x00", $byteLen);
    }

    public static function create(int $expectedElements = 1000, float $fpRate = 0.01): self
    {
        $n = max(10, $expectedElements);
        $bitSize = (int)max(64, ceil(-$n * log($fpRate) / (M_LN2 ** 2)));
        $numHashes = (int)max(1, round(($bitSize / $n) * M_LN2));
        return new self($bitSize, $numHashes);
    }

    /**
     * @return array<int>
     */
    private function hashItem(string $item): array
    {
        $digest = hash('sha256', $item, true);
        if (extension_loaded('gmp')) {
            $h1Hex = bin2hex(substr($digest, 0, 8));
            $h2Hex = bin2hex(substr($digest, 8, 8));
            $h1 = gmp_init('0x' . $h1Hex);
            $h2 = gmp_init('0x' . $h2Hex);
            if (gmp_testbit($h1, 63)) {
                $h1 = gmp_sub($h1, gmp_pow('2', 64));
            }
            if (gmp_testbit($h2, 63)) {
                $h2 = gmp_sub($h2, gmp_pow('2', 64));
            }
            $bitSizeGmp = gmp_init($this->bitSize);
            $indices = [];
            for ($i = 0; $i < $this->numHashFunctions; $i++) {
                $combined = gmp_add($h1, gmp_mul((string)$i, $h2));
                $mod = gmp_mod($combined, $bitSizeGmp);
                if (gmp_sign($mod) < 0) {
                    $mod = gmp_add($mod, $bitSizeGmp);
                }
                $indices[] = (int)gmp_strval($mod);
            }
            return $indices;
        }

        // Alternative 64-bit entier natif
        $u1 = unpack('J', substr($digest, 0, 8))[1];
        $u2 = unpack('J', substr($digest, 8, 8))[1];
        $h1 = ($u1 > 0x7FFFFFFFFFFFFFFF) ? $u1 - 0x10000000000000000 : $u1;
        $h2 = ($u2 > 0x7FFFFFFFFFFFFFFF) ? $u2 - 0x10000000000000000 : $u2;

        $indices = [];
        for ($i = 0; $i < $this->numHashFunctions; $i++) {
            $combined = (int)fmod((float)$h1 + (float)$i * (float)$h2, (float)$this->bitSize);
            if ($combined < 0) {
                $combined += $this->bitSize;
            }
            $indices[] = $combined;
        }
        return $indices;
    }

    public function put(string $item): void
    {
        foreach ($this->hashItem($item) as $idx) {
            $byteIdx = (int)floor($idx / 8);
            $bit = $idx % 8;
            $ord = ord($this->buffer[$byteIdx]);
            $this->buffer[$byteIdx] = chr($ord | (1 << $bit));
        }
    }

    public function mightContain(string $item): bool
    {
        foreach ($this->hashItem($item) as $idx) {
            $byteIdx = (int)floor($idx / 8);
            $bit = $idx % 8;
            $ord = ord($this->buffer[$byteIdx]);
            if (($ord & (1 << $bit)) === 0) {
                return false;
            }
        }
        return true;
    }

    public function exportCompressedBase64(): string
    {
        $compressed = gzcompress($this->buffer, 9);
        return rtrim(strtr(base64_encode($compressed ?: ''), '+/', '-_'), '=');
    }

    public static function fromCompressedBase64(string $b64Str, int $bitSize, int $numHashFunctions): self
    {
        $pad = strlen($b64Str) % 4;
        if ($pad > 0) {
            $b64Str .= str_repeat('=', 4 - $pad);
        }
        $compressed = base64_decode(strtr($b64Str, '-_', '+/'), true);
        $decompressed = $compressed !== false ? @gzuncompress($compressed) : false;
        if ($decompressed === false) {
            throw new \RuntimeException("Failed to decompress Bloom filter payload");
        }
        return new self($bitSize, $numHashFunctions, $decompressed);
    }

    public function getBitSize(): int
    {
        return $this->bitSize;
    }

    public function getNumHashFunctions(): int
    {
        return $this->numHashFunctions;
    }

    /**
     * @return array<int, array{key: string, addTs: int, remTs: int, ttlMs: int}>
     */
    public function computeMissingDelta(LwwElementSet $localSet, ?int $now = null): array
    {
        $delta = $localSet->exportDelta();
        $missing = [];
        foreach ($delta as $entry) {
            if (!empty($entry['key']) && !$this->mightContain($entry['key'])) {
                $missing[] = $entry;
            }
        }
        return $missing;
    }
}
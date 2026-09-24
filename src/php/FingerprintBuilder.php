<?php

declare(strict_types=1);

namespace Anonympins\Fingerprint;

/**
 * Class to build a composite fingerprint (Multi-Hash).
 * Output format: "grp1:hash1|grp2:hash2|grp3:hash3"
 */
class FingerprintBuilder
{
    /**
     * @var array<string, string|int>
     */
    private array $components = [];

    /**
     * Adds a component to the fingerprint.
     *
     * @param string $group Group name (e.g. 'hw', 'screen', 'geo').
     * @param string|int|bool|null $value Raw value to hash.
     * @return self
     */
    public function add(string $group, $value): self
    {
        if ($value === null || $value === '') {
            return $this;
        }
        // Hash the value individually
        $this->components[$group] = self::cyrb53((string)$value);
        return $this;
    }

    /**
     * Adds a raw component without hashing it.
     * Useful for metrics that need to be read as-is on the server.
     *
     * @param string $group Group name.
     * @param string|int|null $value Raw value.
     * @return self
     */
    public function addRaw(string $group, $value): self
    {
        if ($value === null) {
            return $this;
        }
        $this->components[$group] = $value;
        return $this;
    }

    /**
     * Generates the final fingerprint string.
     * Components are sorted by key to guarantee deterministic ordering.
     *
     * @return string
     */
    public function __toString(): string
    {
        // Sort array by key
        ksort($this->components);

        $parts = [];
        foreach ($this->components as $key => $hash) {
            $parts[] = "{$key}:{$hash}";
        }

        return implode('|', $parts);
    }

    /**
     * Compares two fingerprints and returns a similarity score (0 to 1).
     * Uses weights to emphasize strong invariants (Canvas, GPU, JA3).
     *
     * @param string|null $fpString1 Fingerprint A.
     * @param string|null $fpString2 Fingerprint B.
     * @return float
     */
    public static function compare(?string $fpString1, ?string $fpString2): float
    {
        if (empty($fpString1) || empty($fpString2)) {
            return 0.0;
        }

        $parse = function (string $str): array {
            $map = [];
            foreach (explode('|', $str) as $part) {
                $pair = explode(':', $part, 2);
                if (count($pair) === 2 && !empty($pair[0]) && !empty($pair[1])) {
                    $map[$pair[0]] = $pair[1];
                }
            }
            return $map;
        };

        $map1 = $parse($fpString1);
        $map2 = $parse($fpString2);

        $volatileKeys = [
            'ch_ua', 'ch_platform', 'ch_mobile', 'ch_model', 'ch_arch', 'ch_bitness',
            'cookie_keys', 'upgrade', 'network', 'http_ver',
            'x_forwarded_for', 'x_real_ip', 'cf_connecting_ip'
        ];

        $weights = [
            'cvs' => 5.0, 'gpu' => 4.0, 'ja3' => 3.5, 'ja4' => 4.0, 'ja4s' => 4.0, 'ja4h' => 3.8,
            'h2_settings' => 3.0, 'tcp_fp' => 2.5, 'ua' => 2.0,
            'client_fp_hash' => 3.0, 'browser' => 1.5, 'os_version' => 1.5,
            'device_type' => 1.0, 'hw' => 1.5, 'scr' => 1.0, 'os' => 0.8, 'geo' => 0.5,
        ];

        $weightedMatches = 0.0;
        $totalWeight = 0.0;

        $allKeys = array_unique(array_merge(array_keys($map1), array_keys($map2)));

        foreach ($allKeys as $key) {
            // Ignore volatile keys for this comparison
            if (in_array($key, $volatileKeys, true)) { // @phpstan-ignore-line
                continue;
            }

            // Only compare keys that have an assigned weight
            $weight = $weights[$key] ?? null;
            if ($weight === null) continue;

            $totalWeight += $weight;
            if (isset($map1[$key]) && isset($map2[$key])) {
                if ($map1[$key] === $map2[$key]) {
                    $weightedMatches += $weight;
                }
            }
        }

        return $totalWeight === 0.0 ? 0.0 : $weightedMatches / $totalWeight;
    }

    /**
     * cyrb53 hashing algorithm (fast and low collision rate).
     * Ported from the JavaScript version.
     *
     * @param string $str String to hash.
     * @param int $seed Optional seed.
     * @return string Hash as string.
     */
    public static function cyrb53(string $str, int $seed = 0): string
    {
        $h1 = 0xdeadbeef ^ $seed;
        $h2 = 0x41c6ce57 ^ $seed;

        for ($i = 0, $l = strlen($str); $i < $l; $i++) {
            $ch = ord($str[$i]);
            $h1 = self::imul($h1 ^ $ch, 2654435761);
            $h2 = self::imul($h2 ^ $ch, 1597334677);
        }

        $h1 = self::imul($h1 ^ ($h1 >> 16), 2246822507) ^ self::imul($h2 ^ ($h2 >> 13), 3266489909);
        $h2 = self::imul($h2 ^ ($h2 >> 16), 2246822507) ^ self::imul($h1 ^ ($h1 >> 13), 3266489909);

        // On 64-bit platforms, PHP handles 64-bit signed ints natively.
        // Use native shifts instead of bcmath for better performance.
        if (PHP_INT_SIZE === 8) {
            $h1_u = $h1 & 0xffffffff;
            $h2_u = $h2 & 0xffffffff;
            $val_h2 = ((2097151 & $h2_u) << 32) | $h1_u;
            return (string)$val_h2;
        }

        // Fallback to bcmath on 32-bit platforms
        $val_h2 = bcadd(bcmul((string)(2097151 & $h2), '4294967296'), (string)($h1 >= 0 ? $h1 : $h1 + 4294967296));
        return $val_h2;
    }

    /**
     * Emulates JavaScript's 32-bit `Math.imul` multiplication.
     *
     * @param int $a
     * @param int $b
     * @return int Signed 32-bit integer.
     */
    private static function imul(int $a, int $b): int
    {
        // Emulation of JavaScript's Math.imul for signed 32-bit integer multiplication.
        // This version correctly handles overflows on 64-bit systems.
        $ah = ($a >> 16) & 0xffff;
        $al = $a & 0xffff;
        $bh = ($b >> 16) & 0xffff;
        $bl = $b & 0xffff;
        $lo = $al * $bl;
        $hi = (($lo >> 16) + ($al * $bh) + ($ah * $bl)) & 0xffff;
        return (($hi << 16) | ($lo & 0xffff)) | 0;
    }
}
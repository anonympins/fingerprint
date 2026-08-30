<?php

declare(strict_types=1);

namespace Anonympins\Fingerprint;

/**
 * Classe pour construire une empreinte composite (Multi-Hash).
 * Format de sortie : "grp1:hash1|grp2:hash2|grp3:hash3"
 */
class FingerprintBuilder
{
    /**
     * @var array<string, string|int>
     */
    private array $components = [];

    /**
     * Ajoute un composant à l'empreinte.
     * La valeur est hachée pour l'anonymiser et réduire sa taille.
     *
     * @param string $group Le nom du groupe (ex: 'hw', 'screen', 'geo').
     * @param string|int|bool|null $value La valeur brute à hacher.
     * @return self
     */
    public function add(string $group, $value): self
    {
        if ($value === null || $value === '') {
            return $this;
        }
        // On hache la valeur individuellement.
        $this->components[$group] = self::cyrb53((string)$value);
        return $this;
    }

    /**
     * Ajoute un composant brut sans le hacher.
     * Utile pour les métriques qui doivent être lues telles quelles par le serveur.
     *
     * @param string $group Le nom du groupe.
     * @param string|int|null $value La valeur brute.
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
     * Génère la chaîne de l'empreinte finale.
     * Les composants sont triés par clé pour garantir un ordre déterministe.
     *
     * @return string
     */
    public function __toString(): string
    {
        // ksort trie le tableau par clé.
        ksort($this->components);

        $parts = [];
        foreach ($this->components as $key => $hash) {
            $parts[] = "{$key}:{$hash}";
        }

        return implode('|', $parts);
    }

    /**
     * Compare deux empreintes et retourne un score de similarité (de 0 à 1).
     * Utilise une pondération pour donner plus d'importance aux invariants forts (Canvas, GPU, JA3).
     *
     * @param string|null $fpString1 Empreinte A.
     * @param string|null $fpString2 Empreinte B.
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
            'cvs' => 5.0, 'gpu' => 4.0, 'ja3' => 3.5, 'ja4' => 4.0,
            'h2_settings' => 3.0, 'tcp_fp' => 2.5, 'ua' => 2.0,
            'client_fp_hash' => 3.0, 'browser' => 1.5, 'os_version' => 1.5,
            'device_type' => 1.0, 'hw' => 1.5, 'scr' => 1.0, 'os' => 0.8, 'geo' => 0.5,
        ];

        $weightedMatches = 0.0;
        $totalWeight = 0.0;

        $allKeys = array_unique(array_merge(array_keys($map1), array_keys($map2)));

        foreach ($allKeys as $key) {
            if (in_array($key, $volatileKeys, true)) {
                continue;
            }

            if (isset($weights[$key])) {
                $weight = $weights[$key];
                $totalWeight += $weight;
                if (isset($map1[$key]) && isset($map2[$key]) && $map1[$key] === $map2[$key]) {
                    $weightedMatches += $weight;
                }
            }
        }

        return $totalWeight === 0.0 ? 0.0 : $weightedMatches / $totalWeight;
    }

    /**
     * Algorithme de hachage cyrb53 (rapide et faible taux de collision).
     * Porté depuis la version JavaScript.
     *
     * @param string $str La chaîne à hacher.
     * @param int $seed Une graine optionnelle.
     * @return string Le hash sous forme de chaîne de caractères.
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

        // En PHP, les opérations sur les grands nombres peuvent être délicates.
        // On utilise bcmath pour une arithmétique de précision arbitraire, garantissant le même résultat que JS.
        $val_h2 = bcadd(bcmul((string)(2097151 & $h2), '4294967296'), (string)($h1 >= 0 ? $h1 : $h1 + 4294967296));
        return $val_h2;
    }

    /**
     * Émule la multiplication 32-bit `Math.imul` de JavaScript.
     *
     * @param int $a
     * @param int $b
     * @return int Un entier signé 32-bit.
     */
    private static function imul(int $a, int $b): int
    {
        $ah = ($a >> 16) & 0xffff;
        $al = $a & 0xffff;
        $bh = ($b >> 16) & 0xffff;
        $bl = $b & 0xffff;
        // Le résultat est tronqué à 32 bits en utilisant des opérations de bas niveau.
        $result = ($al * $bl) + ((($ah * $bl + $al * $bh) << 16) & 0xffffffff);
        // Forcer le résultat à être un entier signé 32-bit
        if ($result & 0x80000000) {
            return $result | 0xffffffff00000000;
        }
        return $result;
    }
}
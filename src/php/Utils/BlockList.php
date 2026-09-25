<?php

declare(strict_types=1);

namespace Anonympins\Fingerprint\Utils;

/**
 * Implémentation PHP d'une liste de blocage IP/CIDR, similaire à Node.js `net.BlockList`.
 */
class BlockList
{
    /**
     * @var array<string> Liste des IPs ou CIDR à bloquer.
     */
    private array $entries = [];

    /**
     * Ajoute une adresse IP ou une plage CIDR à la liste.
     * @param string $entry Une adresse IP (ex: '192.168.1.1') ou une plage CIDR (ex: '192.168.1.0/24').
     * @return void
     */
    public function add(string $entry): void
    {
        $this->entries[] = $entry;
    }

    /**
     * Vérifie si une adresse IP est présente dans la liste de blocage.
     * @param string $ip L'adresse IP à vérifier.
     * @return bool True si l'IP est bloquée, false sinon.
     */
    public function check(string $ip): bool
    {
        foreach ($this->entries as $entry) {
            if (str_contains($entry, '/')) {
                // C'est une plage CIDR
                if ($this->ipInCidr($ip, $entry)) {
                    return true;
                }
            } else {
                // C'est une IP directe
                if ($ip === $entry) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Vérifie si une adresse IP se trouve dans une plage CIDR donnée.
     * @param string $ip L'adresse IP à vérifier.
     * @param string $cidr La plage CIDR (ex: '192.168.1.0/24').
     * @return bool True si l'IP est dans la plage, false sinon.
     */
    private function ipInCidr(string $ip, string $cidr): bool
    {
        // Handle IPv4-mapped IPv6 addresses by converting them to IPv4
        if (str_starts_with(strtolower($ip), '::ffff:') && filter_var(substr($ip, 7), FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            $ip = substr($ip, 7);
        }

        [$network, $mask] = explode('/', $cidr, 2);
        $mask = (int)$mask;

        // Now, both $ip and $network should be in the same family for a valid comparison
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) && filter_var($network, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            if ($mask < 0 || $mask > 32) { return false; }
            $ipLong = ip2long($ip);
            $networkLong = ip2long($network);
            if ($ipLong === false || $networkLong === false) return false;
            $netmask = -1 << (32 - $mask);
            return ($ipLong & $netmask) === ($networkLong & $netmask);
        } elseif (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) && filter_var($network, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            // IPv6 vs IPv6 CIDR
            if ($mask < 0 || $mask > 128) { return false; }
            $ipBinary = inet_pton($ip);
            $networkBinary = inet_pton($network);
            if ($ipBinary === false || $networkBinary === false) return false;

            $bytesToCompare = (int)floor($mask / 8);
            if (strncmp($ipBinary, $networkBinary, $bytesToCompare) !== 0) {
                return false;
            }

            $bitsToCompare = $mask % 8;
            if ($bitsToCompare > 0) {
                $byteIndex = $bytesToCompare;
                $bitmask = (0xFF << (8 - $bitsToCompare)) & 0xFF;
                if ((ord($ipBinary[$byteIndex]) & $bitmask) !== (ord($networkBinary[$byteIndex]) & $bitmask)) {
                    return false;
                }
            }

            return true;
        }

        return false;
    }
}
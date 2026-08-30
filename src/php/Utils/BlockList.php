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
        [$network, $mask] = explode('/', $cidr);
        $mask = (int)$mask;

        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) && filter_var($network, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            // IPv6
            $ipBinary = inet_pton($ip);
            $networkBinary = inet_pton($network);

            if ($ipBinary === false || $networkBinary === false) {
                return false;
            }

            $ipHex = bin2hex($ipBinary);
            $networkHex = bin2hex($networkBinary);

            $numBytes = (int)ceil($mask / 8);
            $compareLength = $numBytes * 2;

            if (substr($ipHex, 0, $compareLength) !== substr($networkHex, 0, $compareLength)) {
                return false;
            }

            if ($mask % 8 !== 0) {
                $bitMask = (0xFF << (8 - ($mask % 8))) & 0xFF;
                $ipByte = hexdec(substr($ipHex, $numBytes * 2 - 2, 2));
                $networkByte = hexdec(substr($networkHex, $numBytes * 2 - 2, 2));
                return ($ipByte & $bitMask) === ($networkByte & $bitMask);
            }

            return true;

        } elseif (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) && filter_var($network, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            // IPv4
            $ipLong = ip2long($ip);
            $networkLong = ip2long($network);
            $wildcard = pow(2, (32 - $mask)) - 1;
            $netmask = ~$wildcard;
            return (($ipLong & $netmask) === ($networkLong & $netmask));
        }

        return false;
    }
}
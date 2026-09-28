<?php

declare(strict_types=1);

namespace Anonympins\Fingerprint\Utils;

/**
 * PHP implementation of an IP/CIDR blocklist, similar to Node.js `net.BlockList`.
 */
class BlockList
{
    /**
     * @var array<string> List of IPs or CIDR blocks to filter.
     */
    private array $entries = [];

    /**
     * Adds an IP address or CIDR range to the list.
     * @param string $entry An IP address (e.g. '192.168.1.1') or CIDR range (e.g. '192.168.1.0/24').
     * @return void
     */
    public function add(string $entry): void
    {
        $this->entries[] = $entry;
    }

    /**
     * Checks if an IP address exists in the blocklist.
     * @param string $ip The IP address to verify.
     * @return bool True if the IP matches, false otherwise.
     */
    public function check(string $ip): bool
    {
        foreach ($this->entries as $entry) {
            if (str_contains($entry, '/')) {
                // CIDR range
                if ($this->ipInCidr($ip, $entry)) {
                    return true;
                }
            } else {
                // Direct IP match
                if ($ip === $entry) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Checks if an IP address belongs to a given CIDR range.
     * @param string $ip The IP address to verify.
     * @param string $cidr The CIDR range (e.g. '192.168.1.0/24').
     * @return bool True if the IP is within the range, false otherwise.
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
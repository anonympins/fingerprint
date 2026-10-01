<?php

declare(strict_types=1);

namespace Anonympins\Fingerprint;

class AsnTrieNode
{
    /** @var array<?AsnTrieNode> */
    public array $children = [null, null];
    public ?NetworkProfile $profile = null;
}

/**
 * Patricia Trie / Radix Trie en mémoire vive pour résolution ultra-rapide (< 50ns)
 * sans appel réseau bloquant.
 */
class AsnLookupEngine
{
    private static ?self $instance = null;
    private AsnTrieNode $rootV4;
    private AsnTrieNode $rootV6;

    public function __construct()
    {
        $this->rootV4 = new AsnTrieNode();
        $this->rootV6 = new AsnTrieNode();
        $this->loadDefaultPrefixes();
    }

    public static function getInstance(): self
    {
        if (self::$instance === null) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    public function insert(string $cidr, NetworkProfile $profile): void
    {
        $parts = explode('/', trim($cidr), 2);
        $ip = $parts[0];
        $isV4 = filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false;
        $isV6 = filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false;
        if (!$isV4 && !$isV6) {
            return;
        }

        $maxBits = $isV4 ? 32 : 128;
        $prefixLen = isset($parts[1]) ? (int)$parts[1] : $maxBits;
        if ($prefixLen < 0 || $prefixLen > $maxBits) {
            return;
        }

        $bytes = inet_pton($ip);
        if ($bytes === false) {
            return;
        }

        $current = $isV4 ? $this->rootV4 : $this->rootV6;
        for ($i = 0; $i < $prefixLen; $i++) {
            $byteIdx = (int)($i / 8);
            $bitIdx = 7 - ($i % 8);
            $bit = (ord($bytes[$byteIdx]) >> $bitIdx) & 1;

            if ($current->children[$bit] === null) {
                $current->children[$bit] = new AsnTrieNode();
            }
            $current = $current->children[$bit];
        }

        $current->profile = $profile;
    }

    public function lookup(?string $ip): NetworkProfile
    {
        if (empty($ip)) {
            return NetworkProfile::residential();
        }

        $cleanIp = trim($ip);
        if (str_starts_with(strtolower($cleanIp), '::ffff:')) {
            $cleanIp = substr($cleanIp, 7);
        }

        $isV4 = filter_var($cleanIp, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false;
        $isV6 = filter_var($cleanIp, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false;
        if (!$isV4 && !$isV6) {
            return NetworkProfile::residential();
        }

        $bytes = inet_pton($cleanIp);
        if ($bytes === false) {
            return NetworkProfile::residential();
        }

        $current = $isV4 ? $this->rootV4 : $this->rootV6;
        $matchedProfile = null;
        $totalBits = $isV4 ? 32 : 128;

        for ($i = 0; $i < $totalBits; $i++) {
            if ($current->profile !== null) {
                $matchedProfile = $current->profile; // Longest Prefix Match
            }

            $byteIdx = (int)($i / 8);
            $bitIdx = 7 - ($i % 8);
            $bit = (ord($bytes[$byteIdx]) >> $bitIdx) & 1;

            $current = $current->children[$bit];
            if ($current === null) {
                break;
            }
        }

        if ($current !== null && $current->profile !== null) {
            $matchedProfile = $current->profile;
        }

        return $matchedProfile ?? NetworkProfile::residential();
    }

    public function loadDefaultPrefixes(): void
    {
        // Mobile CGNAT (RFC 6598)
        $this->insert('100.64.0.0/10', NetworkProfile::cellular());

        // Datacenters & Cloud majeurs (AWS, Hetzner, OVH, DigitalOcean)
        $datacenterRanges = [
            // AWS
            '3.0.0.0/9', '3.128.0.0/9', '18.192.0.0/11', '34.192.0.0/10',
            '35.156.0.0/14', '52.0.0.0/11', '54.0.0.0/8',
            // Hetzner
            '78.46.0.0/15', '88.198.0.0/16', '94.130.0.0/16', '95.216.0.0/15',
            '116.202.0.0/15', '135.181.0.0/16', '136.243.0.0/16', '138.201.0.0/16',
            '142.132.0.0/16', '144.76.0.0/16', '148.251.0.0/16', '159.69.0.0/16',
            '168.119.0.0/16', '178.63.0.0/16', '188.40.0.0/16', '195.201.0.0/16',
            // OVH
            '51.68.0.0/14', '51.75.0.0/15', '51.77.0.0/16', '51.79.0.0/16',
            '51.81.0.0/16', '51.83.0.0/16', '51.89.0.0/16', '51.91.0.0/16',
            '137.74.0.0/16', '141.94.0.0/15', '145.239.0.0/16', '147.135.0.0/16',
            '176.31.0.0/16', '178.32.0.0/15', '188.165.0.0/16', '198.27.64.0/18',
            // DigitalOcean
            '64.225.0.0/16', '68.183.0.0/16', '104.248.0.0/16', '128.199.0.0/16',
            '134.209.0.0/16', '138.68.0.0/16', '138.197.0.0/16', '139.59.0.0/16',
            '142.93.0.0/16', '143.198.0.0/16', '146.190.0.0/16', '157.230.0.0/16',
            '159.65.0.0/16', '159.89.0.0/16', '161.35.0.0/16', '164.90.128.0/17',
            '165.22.0.0/16', '165.227.0.0/16', '167.99.0.0/16', '174.138.0.0/16',
            '178.62.0.0/16', '178.128.0.0/16', '188.166.0.0/16', '206.189.0.0/16',
        ];
        foreach ($datacenterRanges as $range) {
            $this->insert($range, NetworkProfile::hosting());
        }

        // Satellite (Starlink Space-X)
        $satelliteRanges = [
            '98.97.0.0/16', '129.222.0.0/16', '143.130.0.0/16',
            '143.244.0.0/16', '206.214.224.0/19'
        ];
        foreach ($satelliteRanges as $range) {
            $this->insert($range, NetworkProfile::satellite());
        }

        // Tor Exit Relays / Proxies anonymiseurs
        $anonymizerRanges = [
            '185.220.101.0/24', '185.220.102.0/24', '185.220.103.0/24',
            '185.100.86.128/25', '198.98.56.0/24', '199.249.230.0/24'
        ];
        foreach ($anonymizerRanges as $range) {
            $this->insert($range, NetworkProfile::anonymizer());
        }
    }
}
<?php

declare(strict_types=1);

namespace Anonympins\Fingerprint\Challenge;

use Anonympins\Fingerprint\Store\StoreManager;
use Anonympins\Fingerprint\FingerprintBuilder;
use Anonympins\Fingerprint\Utils\BigInt;
use Anonympins\Fingerprint\Utils\RequestUtils;
use Anonympins\Fingerprint\Utils\Env;
use Anonympins\Fingerprint\Crdt\LwwElementSet;
use Anonympins\Fingerprint\Crdt\BloomFilterSync;

/**
 * Utility class for generating and verifying Proof-of-Work challenges.
 */
class ChallengeUtils
{
    /** @var array<string, float> Local cache of converted floats to avoid repeated pack/unpack system calls */
    private static array $froundCache = [];
    private static ?LwwElementSet $threatIntelCrdt = null;
    private static ?LwwElementSet $whitelistCrdt = null;

    public static function getThreatIntelCrdt(): LwwElementSet
    {
        return self::$threatIntelCrdt ?? (self::$threatIntelCrdt = new LwwElementSet());
    }
    public static function getWhitelistCrdt(): LwwElementSet
    {
        return self::$whitelistCrdt ?? (self::$whitelistCrdt = new LwwElementSet());
    }

    /**
     * Emulates JavaScript's Math.fround: rounds a float to the nearest 32-bit
     * single-precision float. Uses a local cache to avoid repeated pack/unpack calls.
     *
     * @param float $value The float value to round.
     * @return float The value rounded to single precision.
     */
    private static function fround(float $value): float
    {
        $key = (string)$value;
        return self::$froundCache[$key] ?? (self::$froundCache[$key] = unpack('f', pack('f', $value))[1]);
    }

    /**
     * Hashes a string seed into a normalized float between 0 and 1
     * using a simple 32-bit rolling hash (similar to Java's String.hashCode).
     *
     * @param string $seed The seed string to hash.
     * @return float A pseudo-random float in the range [0, 1).
     */
    public static function hashSeedToFloat(string $seed): float
    {
        $hash = 0;
        for ($i = 0; $i < strlen($seed); $i++) {
            $hash = (($hash << 5) - $hash + ord($seed[$i])) & 0xffffffff;
            if ($hash & 0x80000000) {
                $hash = $hash - 0x100000000;
            }
        }
        return abs($hash % 1000000) / 1000000;
    }

    /**
     * Derives a set of 4 unique sample indices from the client IP and a secret,
     * using an HMAC-SHA256 over the client IP and a 5-minute time window.
     * This makes the indices deterministic but rotating over time.
     *
     * @param string $clientIp The client IP address.
     * @param string $secret The shared secret used for the HMAC.
     * @return array<int> An array of 4 unique indices in the range [0, 63].
     */
    public static function deriveSampleIndices(string $clientIp, string $secret): array
    {
        $timeWindow = (int)floor(time() / (60 * 5));
        $message = "{$clientIp}:{$timeWindow}";
        $hmacHex = hash_hmac('sha256', $message, $secret ?: 'gpu-pow-salt');
        $hmacBytes = array_values(unpack('C*', hex2bin($hmacHex)));

        $indices = [];
        for ($i = 0; $i < 4; $i++) {
            $offset = ($i * 2) % count($hmacBytes);
            $value = ($hmacBytes[$offset] << 8) | $hmacBytes[($offset + 1) % count($hmacBytes)];
            $idx = $value % 64;
            while (in_array($idx, $indices, true)) {
                $idx = ($idx + 1) % 64;
            }
            $indices[] = $idx;
        }
        return $indices;
    }

    /**
     * Verifies a GPU Proof-of-Work solution based on the logistic map
     * (chaotic iteration x_{n+1} = r * x_n * (1 - x_n) with r = 3.9999).
     * Only a subset of the 64 values is recomputed, using indices derived
     * from the client IP and a shared secret.
     *
     * @param string $seed The challenge seed.
     * @param int $iterations The number of logistic map iterations per value.
     * @param string $solution A comma-separated string of 64 float values.
     * @param string $clientIp The client IP used to derive the sample indices.
     * @param string $secret The secret used to derive the sample indices.
     * @return bool True if the sampled values match, false otherwise.
     */
    public static function verifyGpuPow(string $seed, int $iterations, string $solution, string $clientIp = '127.0.0.1', string $secret = 'gpu-pow-salt'): bool
    {
        $values = explode(',', $solution);
        if (count($values) !== 64) {
            return false;
        }
        $sampleIndices = self::deriveSampleIndices($clientIp, $secret);
        $numericSeed = self::hashSeedToFloat($seed);
        $r = 3.9999;
        foreach ($sampleIndices as $idx) {
            if ($idx < 0 || $idx >= 64) {
                return false;
            }
            $x = self::fround(fmod($numericSeed + $idx * 0.015, 1.0));
            $rFloat = self::fround($r);
            for ($i = 0; $i < $iterations; $i++) {
                $x = self::fround($rFloat * $x * self::fround(1.0 - $x));
            }
            $clientVal = (float)$values[$idx];
            if (abs($clientVal - $x) > 1e-4) {
                return false;
            }
        }
        return true;
    }

    /** Templates used to generate signed trap URLs that lure malicious crawlers. */
    private const TRAP_URL_TEMPLATES = [
        '/includes/config-{RANDOM}.php',
        '/.env.{RANDOM}',
        '/backups/db_backup_{RANDOM}.sql.gz',
        '/api/v1/internal/status?trace={RANDOM}',
        '/_private/deploy_key_{RANDOM}.pem',
        '/logs/app_error_{RANDOM}.log',
        '/.git/config_{RANDOM}'
    ];

    /**
     * Emulates a 32-bit signed integer multiplication (like Math.imul in JS),
     * handling overflow correctly.
     *
     * @param int $a The first operand.
     * @param int $b The second operand.
     * @return int The 32-bit signed result of a * b.
     */
    private static function imul(int $a, int $b): int
    {
        $ah = ($a >> 16) & 0xffff;
        $al = $a & 0xffff;
        $bh = ($b >> 16) & 0xffff;
        $bl = $b & 0xffff;
        $lo = $al * $bl;
        $hi = (($lo >> 16) + ($al * $bh) + ($ah * $bl)) & 0xffff;
        return (($hi << 16) | ($lo & 0xffff)) | 0;
    }

    /**
     * Deterministically generates a 1024-byte block of pseudo-random data
     * from a seed and a block index, using a rolling hash (cyrb53-based).
     * This is the building block for the proof-of-space challenge.
     *
     * @param string $seed The seed string.
     * @param int $blockIndex The index of the block to generate.
     * @param int $blockSize The size of the block in bytes (default 1024).
     * @return string The raw binary block content.
     */
    private static function generateBlock(string $seed, int $blockIndex, int $blockSize = 1024): string
    {
        $block = str_repeat("\x00", $blockSize);
        $h = FingerprintBuilder::cyrb53($seed . ":" . $blockIndex);

        $h_int = (int)bcmod($h, '4294967296');
        for ($i = 0; $i < $blockSize; $i++) {
            $h_int = self::imul($h_int ^ $i, 1597334677);
            $block[$i] = chr($h_int & 0xff);
        }
        return $block;
    }

    /**
     * Registers a cooperative node in the store, keyed by its IP subnet.
     * Entries older than 2 minutes are pruned before adding the new node.
     *
     * @param string $clientIp The client IP (used to compute the subnet).
     * @param string $nodeId The unique node identifier.
     * @param string $seed The node's seed.
     * @return void
     */
    public static function registerCooperativeNode(string $clientIp, string $nodeId, string $seed): void
    {
        $subnet = RequestUtils::getIpSubnet($clientIp);
        if ($subnet === null) {
            return;
        }
        $store = StoreManager::getStore();
        $key = "coop-pospace:subnet:{$subnet}";
        $nodes = $store->get($key) ?? [];

        $now = time();
        // Clean up expired nodes (older than 2 minutes)
        $nodes = array_filter($nodes, fn($n) => ($now - $n['timestamp']) < 120);

        $nodes[$nodeId] = [
            'nodeId' => $nodeId,
            'seed' => $seed,
            'timestamp' => $now
        ];

        $store->set($key, $nodes, 120);
    }

    /**
     * Finds a random active peer node in the same subnet as the client,
     * excluding a given node ID.
     *
     * @param string $clientIp The client IP (used to compute the subnet).
     * @param string $excludeNodeId The node ID to exclude from the results.
     * @return array|null The peer node data, or null if none is found.
     */
    public static function findPeerInSubnet(string $clientIp, string $excludeNodeId): ?array
    {
        $subnet = RequestUtils::getIpSubnet($clientIp);
        if ($subnet === null) {
            return null;
        }
        $store = StoreManager::getStore();
        $key = "coop-pospace:subnet:{$subnet}";
        $nodes = $store->get($key) ?? [];

        $now = time();
        $activePeers = [];
        foreach ($nodes as $id => $node) {
            if ($id !== $excludeNodeId && ($now - $node['timestamp']) < 120) {
                $activePeers[] = $node;
            }
        }

        if (empty($activePeers)) {
            return null;
        }

        return $activePeers[array_rand($activePeers)];
    }

    public static function verifyEd25519Signature(string $message, string $signatureHex, array $config = []): bool
    {
        if (empty($message) || empty($signatureHex)) {
            return false;
        }
        $publicKey = $config['ed25519_public_key'] ?? Env::get('ED25519_PUBLIC_KEY');
        if (empty($publicKey)) {
            return false;
        }
        try {
            $cleanKey = str_replace('\n', "\n", $publicKey);
            $pubKeyObj = openssl_pkey_get_public($cleanKey);
            if (!$pubKeyObj) {
                return false;
            }
            $sigBytes = hex2bin($signatureHex);
            if ($sigBytes === false) {
                return false;
            }
            return openssl_verify($message, $sigBytes, $pubKeyObj, null) === 1;
        } catch (\Throwable $e) {
            return false;
        }
    }

    /**
     * Handles cooperative peer-to-peer operations (federation threat intel sharing,
     * node registration, peer discovery, WebRTC signaling, block requests/responses).
     * Enforces cooperative signature verification for every operation except
     * the federation threat intel sharing path.
     *
     * @param array $params The request parameters (includes `coop_op`).
     * @param string $clientIp The client IP address.
     * @param array $config Additional configuration (federated peers, thresholds, keys).
     * @return array|null The response payload, or null if `coop_op` is missing.
     */
    public static function handleCooperativeRequest(array $params, string $clientIp = '127.0.0.1', array $config = []): ?array
    {
        $op = $params['coop_op'] ?? null;
        if (!$op) {
            return null;
        }

        $store = StoreManager::getStore();


        if ($op === 'share_threat_intel') {
            $peers = $config['federatedPeers'] ?? [];
            if (!empty($peers)) {
                $allowedHosts = array_map(function ($url) {
                    // phpcs:ignore WordPress.WP.AlternativeFunctions.parse_url_parse_url -- Fallback for standalone PHP environments
                    $host = function_exists('wp_parse_url') ? wp_parse_url($url, PHP_URL_HOST) : parse_url($url, PHP_URL_HOST);
                    return !empty($host) ? $host : $url;
                }, $peers);

                if (!in_array($clientIp, $allowedHosts, true)) {
                    return ['error' => 'Unauthorized federation sender IP'];
                }
            }
            $zkpY = $params['zkpY'] ?? '';
            $action = $params['action'] ?? 'add';
            $headers = function_exists('getallheaders') ? array_change_key_case(getallheaders(), CASE_LOWER) : [];
            $sigEd25519 = $params['signature_ed25519'] ?? $headers['x-federation-signature-ed25519'] ?? self::getSanitizedServerVar('HTTP_X_FEDERATION_SIGNATURE_ED25519', '');
            $sigHmac = $params['signature'] ?? $headers['x-federation-signature'] ?? self::getSanitizedServerVar('HTTP_X_FEDERATION_SIGNATURE', '');
            $timestamp = (int)($params['timestamp'] ?? $headers['x-federation-timestamp'] ?? self::getSanitizedServerVar('HTTP_X_FEDERATION_TIMESTAMP', 0));

            if (empty($zkpY) || empty($timestamp)) {
                return ['error' => 'Missing threat intel parameters'];
            }

            // Time window check (5 minutes anti-replay)
            $now = (int)(microtime(true) * 1000);
            if (abs($now - $timestamp) > 300000) {
                return ['error' => 'Message expired or clock skew too high'];
            }

            $msg = "{$timestamp}:{$zkpY}";

            if (!empty($sigEd25519)) {
                if (!self::verifyEd25519Signature($msg, $sigEd25519, $config)) {
                    return ['error' => 'Invalid asymmetric federation signature'];
                }
            } elseif (!empty($sigHmac)) {
                $secret = $params['federationSecret'] ?? $config['federationSecret'] ?? self::getPowSecret();
                $expectedSig = hash_hmac('sha256', $msg, $secret);
                if (!hash_equals($expectedSig, $sigHmac)) {
                    return ['error' => 'Invalid federation signature'];
                }
            } else {
                return ['error' => 'Missing signature'];
            }

            $peersKey = "fed-peers:{$zkpY}";
            $reportedPeers = $store->get($peersKey) ?: [];
            if (!is_array($reportedPeers)) {
                $reportedPeers = [];
            }
            if (!in_array($clientIp, $reportedPeers, true)) {
                $reportedPeers[] = $clientIp;
                $store->set($peersKey, $reportedPeers, 86400 * 30);
            }

            $crdt = self::getThreatIntelCrdt();
            $durationMs = 86400 * 30 * 1000;
            if ($action === 'remove') {
                $crdt->remove($zkpY, $timestamp);
            } else {
                $crdt->add($zkpY, $timestamp, $durationMs);
            }

            $threshold = $config['federationConsensusThreshold'] ?? 3;
            if (count($reportedPeers) >= $threshold) {
                $store->set("banned-zkp-y:{$zkpY}", true, 86400 * 30);
                return ['status' => 'synchronized', 'banned' => true];
            }
            return ['status' => 'synchronized', 'banned' => false, 'reportsCount' => count($reportedPeers)];
        }

        if ($op === 'share_whitelist') {
            $peers = $config['federatedPeers'] ?? [];
            if (!empty($peers)) {
                $allowedHosts = array_map(function ($url) {
                    // phpcs:ignore WordPress.WP.AlternativeFunctions.parse_url_parse_url -- Fallback for standalone PHP environments
                    $host = function_exists('wp_parse_url') ? wp_parse_url($url, PHP_URL_HOST) : parse_url($url, PHP_URL_HOST);
                    return !empty($host) ? $host : $url;
                }, $peers);

                if (!in_array($clientIp, $allowedHosts, true)) {
                    return ['error' => 'Unauthorized federation sender IP'];
                }
            }

            $entry = $params['entry'] ?? '';
            $entryType = $params['entry_type'] ?? 'ip';
            $action = $params['action'] ?? 'add';
            $headers = function_exists('getallheaders') ? array_change_key_case(getallheaders(), CASE_LOWER) : [];
            $sigEd25519 = $params['signature_ed25519'] ?? $headers['x-federation-signature-ed25519'] ?? self::getSanitizedServerVar('HTTP_X_FEDERATION_SIGNATURE_ED25519', '');
            $timestamp = (int)($params['timestamp'] ?? $headers['x-federation-timestamp'] ?? self::getSanitizedServerVar('HTTP_X_FEDERATION_TIMESTAMP', 0));
            $ttl = (int)($params['ttl'] ?? 86400);

            $cleanEntry = trim($entry);
            if ($cleanEntry === '' || empty($sigEd25519) || empty($timestamp)) {
                return ['error' => 'Missing required parameters for share_whitelist'];
            }

            if ($cleanEntry === '*' || $cleanEntry === '0.0.0.0/0' || $cleanEntry === '::/0') {
                return ['error' => 'Permissive wildcard entries are prohibited'];
            }

            $now = (int)(microtime(true) * 1000);
            if (abs($now - $timestamp) > 300000) {
                return ['error' => 'Timestamp expired or clock skew too high'];
            }

            $msg = "{$timestamp}:whitelist:{$entryType}:{$cleanEntry}";
            if (!self::verifyEd25519Signature($msg, $sigEd25519, $config)) {
                return ['error' => 'Invalid Ed25519 signature for whitelist synchronization'];
            }

            $boundedTtl = min(604800, max(60, $ttl));
            $crdt = self::getWhitelistCrdt();
            $crdtKey = "{$entryType}:{$cleanEntry}";
            if ($action === 'remove') {
                $crdt->remove($crdtKey, $timestamp);
            } else {
                $crdt->add($crdtKey, $timestamp, $boundedTtl * 1000);
            }

            $store->set("federated-whitelist:{$entryType}:{$cleanEntry}", true, $boundedTtl);
            return ['status' => 'whitelist_synchronized', 'entry' => $cleanEntry, 'entryType' => $entryType, 'ttl' => $boundedTtl];
        }

        // --- RÉCONCILIATION ANTI-ENTROPIE PAR FILTRES DE BLOOM COMPRESSÉS ---
        if ($op === 'sync_threat_intel' || $op === 'sync_whitelist') {
            $isThreat = $op === 'sync_threat_intel';
            $targetSet = $isThreat ? self::getThreatIntelCrdt() : self::getWhitelistCrdt();
            $now = (int)(microtime(true) * 1000);
            $targetSet->pruneExpired($now);

            $filterB64 = $params['bloom_filter'] ?? null;
            $bitSizeStr = $params['bit_size'] ?? null;
            $hashCountStr = $params['hash_count'] ?? null;

            if ($filterB64 && $bitSizeStr && $hashCountStr) {
                $remoteFilter = BloomFilterSync::fromCompressedBase64($filterB64, (int)$bitSizeStr, (int)$hashCountStr);
                $delta = $remoteFilter->computeMissingDelta($targetSet, $now);
                return [
                    'status' => 'delta_ready',
                    'delta_count' => count($delta),
                    'delta' => $delta
                ];
            } else {
                $active = $targetSet->getActiveElements($now);
                $localFilter = BloomFilterSync::create(max(100, count($active) * 2), 0.01);
                foreach ($active as $item) {
                    $localFilter->put($item);
                }
                return [
                    'status' => 'bloom_filter_ready',
                    'bloom_filter' => $localFilter->exportCompressedBase64(),
                    'bit_size' => $localFilter->getBitSize(),
                    'hash_count' => $localFilter->getNumHashFunctions(),
                    'element_count' => $targetSet->count()
                ];
            }
        }

        if ($op === 'merge_threat_intel' || $op === 'merge_whitelist') {
            $isThreat = $op === 'merge_threat_intel';
            $targetSet = $isThreat ? self::getThreatIntelCrdt() : self::getWhitelistCrdt();
            $delta = $params['delta'] ?? [];
            if (is_string($delta)) {
                $delta = json_decode($delta, true) ?: [];
            }
            if (is_array($delta)) {
                $targetSet->mergeDelta($delta);
                return ['status' => 'merged', 'total_elements' => $targetSet->count()];
            }
            return ['error' => 'Invalid delta payload'];
        }

        $nodeId = $params['node_id'] ?? '';
        if (empty($nodeId)) {
            return ['error' => 'Missing node_id'];
        }

        // --- COOPERATIVE SIGNATURE VERIFICATION ---
        $challengeContext = $store->get("secret:{$nodeId}");
        if (!$challengeContext || empty($challengeContext['clientSecret'])) {
            return ['error' => 'Invalid or expired node_id'];
        }

        $clientSecret = $challengeContext['clientSecret'];
        $coopSig = $params['coop_sig'] ?? '';

        $expectedMsg = '';
        switch ($op) {
            case 'register':
                $expectedMsg = "{$clientSecret}:register:{$nodeId}:" . ($params['seed'] ?? '');
                break;
            case 'find_peer':
                $expectedMsg = "{$clientSecret}:find_peer:{$nodeId}";
                break;
            case 'webrtc_signal':
                $expectedMsg = "{$clientSecret}:webrtc_signal:{$nodeId}:" . (isset($params['target_peer_id']) ? self::sanitizeString($params['target_peer_id']) : '') . ":" . (isset($params['signal_type']) ? self::sanitizeString($params['signal_type']) : '') . ":" . (isset($params['signal_data']) ? self::sanitizeString($params['signal_data']) : '');
                break;
            case 'poll_signals':
                $expectedMsg = "{$clientSecret}:poll_signals:{$nodeId}";
                break;
            case 'request_peer_block':
                $expectedMsg = "{$clientSecret}:request_peer_block:{$nodeId}:" . (isset($params['peer_id']) ? self::sanitizeString($params['peer_id']) : '') . ":" . ($params['block_idx'] ?? '0') . ":" . (isset($params['req_id']) ? self::sanitizeString($params['req_id']) : '');
                break;
            case 'poll_requests':
                $expectedMsg = "{$clientSecret}:poll_requests:{$nodeId}";
                break;
            case 'respond_block':
                $expectedMsg = "{$clientSecret}:respond_block:{$nodeId}:" . (isset($params['requester_id']) ? self::sanitizeString($params['requester_id']) : '') . ":" . (isset($params['req_id']) ? self::sanitizeString($params['req_id']) : '') . ":" . (isset($params['block_data']) ? self::sanitizeString($params['block_data']) : '');
                break;
            case 'poll_response':
                $expectedMsg = "{$clientSecret}:poll_response:{$nodeId}:" . ($params['req_id'] ?? '');
                break;
            default:
                return ['error' => 'Invalid cooperative operation'];
        }

        $expectedSig = hash('sha256', $expectedMsg);
        if (!hash_equals($expectedSig, $coopSig)) {
            return ['error' => 'Invalid cooperative signature'];
        }
        // --- END OF VERIFICATION ---

        switch ($op) {
            case 'register':
                $clientIp = self::getSanitizedServerVar('REMOTE_ADDR', '127.0.0.1');
                $seed = isset($params['seed']) ? self::sanitizeString($params['seed']) : '';
                self::registerCooperativeNode($clientIp, $nodeId, $seed);
                return ['status' => 'registered'];

            case 'find_peer':
                $peer = self::findPeerInSubnet($clientIp, $nodeId);
                if ($peer !== null) {
                    return ['status' => 'peer_found', 'peer_id' => $peer['nodeId'], 'seed' => $peer['seed']];
                }
                return ['status' => 'no_peers'];

            case 'webrtc_signal':
                $targetPeerId = isset($params['target_peer_id']) ? self::sanitizeString($params['target_peer_id']) : '';
                $signalType = isset($params['signal_type']) ? self::sanitizeString($params['signal_type']) : '';
                $signalData = isset($params['signal_data']) ? self::sanitizeString($params['signal_data']) : '';
                if (empty($targetPeerId) || empty($signalType) || empty($signalData)) {
                    return ['error' => 'Invalid parameters'];
                }
                $signalQueueKey = "coop-webrtc:signals:{$targetPeerId}";
                $signals = $store->get($signalQueueKey) ?? [];
                $signals[] = [
                    'from_peer_id' => $nodeId,
                    'signal_type' => $signalType,
                    'signal_data' => $signalData
                ];
                $store->set($signalQueueKey, $signals, 30);
                return ['status' => 'signal_queued'];

            case 'poll_signals':
                $pollSignalKey = "coop-webrtc:signals:{$nodeId}";
                $signals = $store->get($pollSignalKey) ?? [];
                if (!empty($signals)) {
                    $store->delete($pollSignalKey);
                }
                return ['status' => 'ok', 'signals' => $signals];

            case 'request_peer_block':
                $peerId = isset($params['peer_id']) ? self::sanitizeString($params['peer_id']) : '';
                $blockIdx = (int)($params['block_idx'] ?? 0);
                $requestId = isset($params['req_id']) ? self::sanitizeString($params['req_id']) : '';
                if (empty($peerId) || empty($requestId)) {
                    return ['error' => 'Invalid parameters'];
                }

                $queueKey = "coop-mailbox:queue:{$peerId}";
                $requests = $store->get($queueKey) ?? [];
                $requests[] = [
                    'req_id' => $requestId,
                    'requester_id' => $nodeId,
                    'block_idx' => $blockIdx
                ];
                $store->set($queueKey, $requests, 30);
                return ['status' => 'queued'];

            case 'poll_requests':
                $queueKey = "coop-mailbox:queue:{$nodeId}";
                $requests = $store->get($queueKey) ?? [];
                $store->delete($queueKey);
                return ['requests' => $requests];

            case 'respond_block':
                $requesterId = isset($params['requester_id']) ? self::sanitizeString($params['requester_id']) : '';
                $requestId = isset($params['req_id']) ? self::sanitizeString($params['req_id']) : '';
                $blockData = isset($params['block_data']) ? self::sanitizeString($params['block_data']) : '';
                if (empty($requesterId) || empty($requestId)) {
                    return ['error' => 'Invalid parameters'];
                }

                $responseKey = "coop-mailbox:res:{$requesterId}:{$requestId}";
                $store->set($responseKey, ['block_data' => $blockData], 30);
                return ['status' => 'delivered'];

            case 'poll_response':
                $requestId = isset($params['req_id']) ? self::sanitizeString($params['req_id']) : '';
                $responseKey = "coop-mailbox:res:{$nodeId}:{$requestId}";
                $data = $store->get($responseKey);
                if ($data) {
                    $store->delete($responseKey);
                    return ['status' => 'ready', 'block_data' => $data['block_data']];
                }
                return ['status' => 'pending'];
        }
        return null;
    }

    /**
     * Generates a proof-of-space challenge for a client, including random block
     * queries. If a peer is found in the same subnet, a cooperative component is
     * added to the challenge (peer ID and a random block index).
     *
     * @param string $clientIp The client IP address.
     * @param string $nonce The challenge nonce.
     * @param float $suspicionFactor The suspicion factor for the request.
     * @param string $originalUrl The original requested URL (used as redirect path).
     * @param array $securityConfig The security configuration array.
     * @return array The challenge details.
     */
    public static function generateSpaceChallenge(string $clientIp, string $nonce, float $suspicionFactor, string $originalUrl, array $securityConfig): array
    {
        $pospaceConfig = $securityConfig['pospace'] ?? [];
        $sizeMb = $pospaceConfig['sizeMb'] ?? 100;
        $numQueries = $pospaceConfig['numQueries'] ?? 10;

        $queries = [];
        $maxBlocks = $sizeMb * 1024;
        while (count($queries) < $numQueries) {
            $idx = random_int(0, $maxBlocks - 1);
            if (!in_array($idx, $queries, true)) {
                $queries[] = $idx;
            }
        }

        $challenge = [
            'type' => 'pospace',
            'nonce' => $nonce,
            'sizeMb' => $sizeMb,
            'queries' => $queries,
            'path' => $originalUrl
        ];

        // Attempt cooperative coupling with a peer node in the same subnet
        $peer = self::findPeerInSubnet($clientIp, $nonce);
        if ($peer !== null) {
            $challenge['peerId'] = $peer['nodeId'];
            $challenge['peerBlockIdx'] = random_int(0, $maxBlocks - 1);

            $store = StoreManager::getStore();
            $store->set("coop-assoc:{$nonce}", [
                'peerNodeId' => $peer['nodeId'],
                'peerSeed' => $peer['seed'],
                'peerBlockIdx' => $challenge['peerBlockIdx']
            ], 120);
        }

        return $challenge;
    }

    /**
     * Verifies a proof-of-space solution by reconstructing the expected hash
     * from the queried blocks. If a cooperative association exists for the nonce,
     * the peer block is also appended to the combined data.
     *
     * @param string $nonce The challenge nonce.
     * @param string $solution The client-provided solution hash.
     * @param array $queries The list of queried block indices.
     * @param string $seed The seed used to generate the blocks.
     * @param string $clientSecret The client secret.
     * @return bool True if the solution matches, false otherwise.
     */
    public static function verifySpacePoW(string $nonce, string $solution, array $queries, string $seed, string $clientSecret): bool
    {
        $combined = '';
        foreach ($queries as $idx) {
            $combined .= self::generateBlock($seed, (int)$idx);
        }

        // Cooperative proof verification
        $store = StoreManager::getStore();
        $assoc = $store->get("coop-assoc:{$nonce}");
        if ($assoc !== null) {
            $peerSeed = $assoc['peerSeed'] ?? null;
            $peerBlockIdx = $assoc['peerBlockIdx'] ?? null;
            if ($peerSeed !== null && $peerBlockIdx !== null) {
                $combined .= self::generateBlock($peerSeed, (int)$peerBlockIdx);
            }
            $store->delete("coop-assoc:{$nonce}");
        }

        $finalBlock = $combined . $nonce . ":" . $clientSecret;
        $hash = hash('sha256', $finalBlock);
        return hash_equals($hash, $solution);
    }

    /**
     * Verifies a Schnorr-style Zero-Knowledge Proof using the secp256k1 prime.
     * Checks that g^s ≡ t * y^c (mod p), where c = SHA-256(g, y, t) mod p.
     *
     * @param string $yStr The public key y (hex).
     * @param string $tStr The commitment t (hex).
     * @param string $sStr The response s (hex).
     * @return bool True if the proof is valid, false otherwise.
     */
    public static function verifyZkpProof(string $yStr, string $tStr, string $sStr): bool
    {
        try {
            $p = BigInt::fromHex('fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f'); // secp256k1 prime
            $g = new BigInt(2);

            $y = BigInt::fromHex($yStr);
            $t = BigInt::fromHex($tStr);
            $s = BigInt::fromHex($sStr);

            $cStr = (string)$g . (string)$y . (string)$t;
            $cHex = hash('sha256', $cStr);
            $c = BigInt::fromHex($cHex)->mod($p);

            $left = $g->modPow($s, $p);
            $y_c = $y->modPow($c, $p);
            $right = $t->mul($y_c)->mod($p);

            return $left->compareTo($right) === 0;
        } catch (\Throwable $e) {
            return false;
        }
    }

    /**
     * Retrieves the secret key for PoW tasks from environment variables.
     * Throws an exception in production if the secret is missing.
     *
     * @return string The PoW secret.
     * @throws \RuntimeException If missing in production.
     */
    public static function getPowSecret(): string
    {
        $secret = Env::get('POW_SECRET');
        $appEnv = Env::get('APP_ENV');
        if (!$secret && $appEnv === 'production') {
            throw new \RuntimeException('POW_SECRET environment variable is not set. This is required for production.');
        }
        return $secret ?: "fallback-dev-secret-32-chars-minimum";
    }

    /**
     * Programmatically generates an Ed25519 key pair in PEM format
     * matching OpenSSL CLI:
     * `openssl genpkey -algorithm ed25519 -out issuer-private.pem`
     * `openssl pkey -in issuer-private.pem -pubout -out issuer-public.pem`
     *
     * @param string $outDir Target directory to store the PEM files.
     * @param array $options Options including custom file names.
     * @return array{privateKeyPath: string, publicKeyPath: string, privateKey: string, publicKey: string}
     * @throws \RuntimeException If OpenSSL or Ed25519 is not supported or key generation fails.
     */
    public static function generateIssuerPemKeys(string $outDir = '', array $options = []): array
    {
        if (!defined('OPENSSL_KEYTYPE_ED25519')) {
            throw new \RuntimeException("Ed25519 is not supported in this OpenSSL environment.");
        }

        $pkey = @openssl_pkey_new(["private_key_type" => constant('OPENSSL_KEYTYPE_ED25519')]);
        if (!$pkey || !@openssl_pkey_export($pkey, $privateKeyPem)) {
            throw new \RuntimeException("Failed to generate Ed25519 private key.");
        }

        $details = openssl_pkey_get_details($pkey);
        $publicKeyPem = $details['key'] ?? '';
        if (empty($publicKeyPem)) {
            throw new \RuntimeException("Failed to extract Ed25519 public key.");
        }

        $privName = $options['privateKeyName'] ?? 'issuer-private.pem';
        $pubName = $options['publicKeyName'] ?? 'issuer-public.pem';

        $privateKeyPath = '';
        $publicKeyPath = '';

        if ($outDir !== '') {
            if (!is_dir($outDir)) {
                if (function_exists('wp_mkdir_p')) {
                    wp_mkdir_p($outDir);
                } else {
                    // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_mkdir -- Standalone filesystem fallback
                    mkdir($outDir, 0755, true);
                }
            }
            $privateKeyPath = rtrim($outDir, '/\\') . '/' . $privName;
            $publicKeyPath = rtrim($outDir, '/\\') . '/' . $pubName;

            global $wp_filesystem;
            if (empty($wp_filesystem) && defined('ABSPATH')) {
                require_once ABSPATH . 'wp-admin/includes/file.php';
                WP_Filesystem();
            }

            if (!empty($wp_filesystem) && is_object($wp_filesystem)) {
                $wp_filesystem->put_contents($privateKeyPath, $privateKeyPem, 0600);
                $wp_filesystem->put_contents($publicKeyPath, $publicKeyPem, 0644);
            } else {
                // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- Standalone filesystem fallback
                file_put_contents($privateKeyPath, $privateKeyPem);
                // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_chmod -- Standalone filesystem fallback
                @chmod($privateKeyPath, 0600);
                // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- Standalone filesystem fallback
                file_put_contents($publicKeyPath, $publicKeyPem);
                // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_chmod -- Standalone filesystem fallback
                @chmod($publicKeyPath, 0644);
            }
        }

        return [
            'privateKeyPath' => $privateKeyPath,
            'publicKeyPath'  => $publicKeyPath,
            'privateKey'     => $privateKeyPem,
            'publicKey'      => $publicKeyPem,
        ];
    }

    /**
     * Generates an encrypted and signed stateless ticket containing the
     * authorization context. Uses Ed25519 if a private key is available,
     * otherwise falls back to AES-256-CBC + HMAC-SHA256.
     *
     * @param array $payload The authorization context to embed.
     * @return string The encoded ticket.
     */
    public static function generateStatelessTicket(array $payload): string
    {
        $ed25519Key = Env::get('ED25519_PRIVATE_KEY');
        if ($ed25519Key) {
            try {
                $serialized = json_encode($payload);
                $privateKey = openssl_pkey_get_private($ed25519Key);
                if ($privateKey && openssl_sign($serialized, $signature, $privateKey, null)) {
                    $base64UrlEncode = function ($input) {
                        return rtrim(strtr(base64_encode($input), '+/', '-_'), '=');
                    };
                    return 'ed25519.' . $base64UrlEncode($serialized) . '.' . $base64UrlEncode($signature);
                }
            } catch (\Throwable $e) {
                self::logError("[ChallengeUtils] Ed25519 signing failed: " . $e->getMessage());
            }
        }

        $key = hash('sha256', self::getPowSecret(), true);
        $iv = random_bytes(16);
        $encrypted = openssl_encrypt(json_encode($payload), 'aes-256-cbc', $key, OPENSSL_RAW_DATA, $iv);
        $signature = hash_hmac('sha256', $iv . $encrypted, $key, true);

        return rtrim(strtr(base64_encode($iv), '+/', '-_'), '=') . '.' .
            rtrim(strtr(base64_encode($encrypted), '+/', '-_'), '=') . '.' .
            rtrim(strtr(base64_encode($signature), '+/', '-_'), '=');
    }

    /**
     * Decodes and validates an encrypted and signed stateless ticket.
     * Supports both Ed25519 and AES-256-CBC + HMAC-SHA256 formats.
     *
     * @param string $ticket The ticket to decode.
     * @param string $secret Optional secret for HMAC verification.
     * @return array|null The decoded payload, or null if invalid.
     */
    public static function parseStatelessTicket(string $ticket, string $secret = ''): ?array
    {
        try {
            if (str_starts_with($ticket, 'ed25519.')) {
                $parts = explode('.', $ticket);
                if (count($parts) !== 3) {
                    return null;
                }
                $base64UrlDecode = function ($input) {
                    return base64_decode(strtr($input, '-_', '+/'));
                };
                $payloadJson = $base64UrlDecode($parts[1]);
                $signature = $base64UrlDecode($parts[2]);

                $ed25519PubKey = Env::get('ED25519_PUBLIC_KEY');
                if (!$ed25519PubKey) {
                    self::logError("[ChallengeUtils] ED25519_PUBLIC_KEY is not defined in environment.");
                    return null;
                }

                $publicKey = openssl_pkey_get_public($ed25519PubKey);
                if ($publicKey && openssl_verify($payloadJson, $signature, $publicKey, null) === 1) {
                    return json_decode($payloadJson, true);
                }
                return null;
            }
        } catch (\Throwable $e) {
            self::logError("[ChallengeUtils] Ed25519 verification failed: " . $e->getMessage());
            return null;
        }

        $parts = explode('.', $ticket);
        if (count($parts) !== 3) {
            return null;
        }
        $base64UrlDecode = function ($input) {
            return base64_decode(strtr($input, '-_', '+/'));
        };
        $iv = $base64UrlDecode($parts[0]);
        $encrypted = $base64UrlDecode($parts[1]);
        $signature = $base64UrlDecode($parts[2]);
        if (!$iv || !$encrypted || !$signature || strlen($iv) !== 16) {
            return null;
        }
        $key = hash('sha256', !empty($secret) ? $secret : self::getPowSecret(), true);
        $expectedSignature = hash_hmac('sha256', $iv . $encrypted, $key, true);
        if (!hash_equals($expectedSignature, $signature)) {
            return null;
        }
        $decrypted = openssl_decrypt($encrypted, 'aes-256-cbc', $key, OPENSSL_RAW_DATA, $iv);
        return $decrypted !== false ? json_decode($decrypted, true) : null;
    }

    /**
     * Checks whether a pass ticket is valid. Supports opaque tickets (via the store)
     * and the legacy stateless fallback. Handles greenlist, ZKP, same-IP, same-subnet,
     * and cross-network roaming validations.
     *
     * @param string|null $ip The client IP.
     * @param string|null $ticket The ticket to validate.
     * @param string $deviceId The client device ID.
     * @param string $deviceHash The client device hash.
     * @param bool $allowCrossNetworkRoaming Whether to allow roaming across networks.
     * @param string $secret Optional secret for legacy ticket validation.
     * @param string $zkpProof Optional ZKP proof in the format "y:t:s".
     * @return bool True if the ticket is valid, false otherwise.
     */
    public static function isTicketValid(
        ?string $ip,
        ?string $ticket,
        string $deviceId = '',
        string $deviceHash = '',
        bool $allowCrossNetworkRoaming = false,
        string $secret = '',
        string $zkpProof = ''
    ): bool {
        if (empty($ip) || empty($ticket)) {
            return false;
        }

        // Try stateless validation first
        $ticketData = self::parseStatelessTicket($ticket, $secret);
        if ($ticketData !== null) {
            $expiry = $ticketData['expiry'] ?? null;
            $originalIp = $ticketData['originalIp'] ?? null;
            $storedDeviceId = $ticketData['deviceId'] ?? '';
            $storedDeviceHash = $ticketData['deviceHash'] ?? '';

            if (!$expiry || (int)floor(microtime(true) * 1000) > (int)$expiry) {
                return false;
            }
            if (!empty($ticketData['greenlist']) || str_starts_with((string)$storedDeviceHash, 'webauthn:greenlist:')) {
                if (empty($deviceId) || $deviceId === $storedDeviceId) {
                    return true;
                }
            }
            if ($storedDeviceHash && str_starts_with($storedDeviceHash, 'zkp:')) {
                $expectedY = explode(':', $storedDeviceHash, 2)[1] ?? '';
                if (!empty($zkpProof)) {
                    $zkpParts = explode(':', $zkpProof);
                    if (count($zkpParts) === 3 && $zkpParts[0] === $expectedY) {
                        if (self::verifyZkpProof($zkpParts[0], $zkpParts[1], $zkpParts[2])) {
                            return true;
                        }
                    }
                }
                return false;
            }
            if ($ip === $originalIp) {
                return true;
            }
            $currentSubnet = RequestUtils::getIpSubnet($ip);
            $originalSubnet = RequestUtils::getIpSubnet($originalIp);
            if ($currentSubnet !== null && $originalSubnet !== null && $currentSubnet === $originalSubnet) {
                return true;
            }
            if (!$allowCrossNetworkRoaming) {
                return false;
            }
            return !empty($deviceId) && $deviceId === $storedDeviceId && !empty($deviceHash) && $deviceHash === $storedDeviceHash;
        }

        $store = StoreManager::getStore();
        $ticketData = $store->get("ticket:{$ticket}");

        if ($ticketData !== null) {
            $expiry = $ticketData['expiry'] ?? null;
            $originalIp = $ticketData['originalIp'] ?? null;
            $storedDeviceId = $ticketData['deviceId'] ?? '';
            $storedDeviceHash = $ticketData['deviceHash'] ?? '';

            if (!$expiry || (int)floor(microtime(true) * 1000) > (int)$expiry) {
                $store->delete("ticket:{$ticket}");
                return false;
            }
            if (!empty($ticketData['greenlist']) || str_starts_with((string)$storedDeviceHash, 'webauthn:greenlist:')) {
                if (empty($deviceId) || $deviceId === $storedDeviceId) {
                    return true;
                }
            }
            if ($storedDeviceHash && str_starts_with($storedDeviceHash, 'zkp:')) {
                $expectedY = explode(':', $storedDeviceHash, 2)[1] ?? '';
                if (!empty($zkpProof)) {
                    $zkpParts = explode(':', $zkpProof);
                    if (count($zkpParts) === 3 && $zkpParts[0] === $expectedY) {
                        if (self::verifyZkpProof($zkpParts[0], $zkpParts[1], $zkpParts[2])) {
                            return true;
                        }
                    }
                }
                return false;
            }

            if ($ip === $originalIp) {
                return true;
            }

            $currentSubnet = RequestUtils::getIpSubnet($ip);
            $originalSubnet = RequestUtils::getIpSubnet($originalIp);
            if ($currentSubnet !== null && $originalSubnet !== null && $currentSubnet === $originalSubnet) {
                return true;
            }

            if (!$allowCrossNetworkRoaming) {
                return false;
            }

            return !empty($deviceId) && $deviceId === $storedDeviceId && !empty($deviceHash) && $deviceHash === $storedDeviceHash;
        }

        // Backward-compatible fallback for legacy signed tickets (stateless)
        if (!str_contains($ticket, ':')) {
            return false;
        }

        [$expiry, $sig] = explode(':', $ticket, 2);
        if (empty($expiry) || empty($sig) || (int)floor((float)$expiry) < (int)floor(microtime(true) * 1000)) {
            return false;
        }

        $expectedSig = hash_hmac('sha256', "{$ip}:{$expiry}", !empty($secret) ? $secret : self::getPowSecret());

        return hash_equals($expectedSig, $sig);
    }

    /**
     * Computes the difficulty target for a CPU challenge based on the
     * suspicion factor. Higher suspicion yields a harder (smaller) target.
     *
     * @param float $suspicionFactor The suspicion factor (0.0 to 1.0).
     * @param array $securityConfig The security configuration.
     * @return string The target as a hex string.
     */
    public static function calculateCpuTarget(float $suspicionFactor, array $securityConfig): string
    {
        $cpuConfig = $securityConfig['cpu'] ?? [];
        $minDifficultyBits = (float)($cpuConfig['minDifficultyBits'] ?? 4);
        $maxDifficultyBits = (float)($cpuConfig['maxDifficultyBits'] ?? 22);

        $totalDifficultyBits = $minDifficultyBits + $suspicionFactor * ($maxDifficultyBits - $minDifficultyBits);

        if ($totalDifficultyBits <= 0) {
            // Maximum target (trivial challenge)
            return (BigInt::pow(2, 256)->sub(new BigInt(1)))->toHex();
        }

        $shift = 256 - (int)floor($totalDifficultyBits);
        return (new BigInt(1))->shiftLeft($shift)->toHex();
    }

    /**
     * Creates the base data block used by the CPU challenge. The fingerprint
     * parts are sorted to ensure deterministic ordering.
     *
     * @param string $nonce The challenge nonce.
     * @param string $clientSecret The client secret.
     * @param string $fingerprint The client fingerprint (pipe-separated).
     * @param string $clientIp The client IP.
     * @param string $tlsSessionId The TLS session ID.
     * @return string The concatenated base block.
     */
    public static function createCpuChallengeBaseBlock(string $nonce, string $clientSecret, string $fingerprint, string $clientIp = '', string $tlsSessionId = ''): string
    {
        $parts = explode('|', $fingerprint);
        $filteredParts = array_filter($parts);
        sort($filteredParts);
        $sortedFingerprint = implode('|', $filteredParts);

        return "{$nonce}:{$clientSecret}:{$sortedFingerprint}:{$clientIp}:{$tlsSessionId}:";
    }

    /**
     * Verifies a CPU Proof-of-Work solution and, on success, generates a
     * stateless ticket. In HTTP (insecure) mode, no SHA-256 computation is
     * required and a ticket is issued directly.
     *
     * @param string $clientIp The client IP.
     * @param int $ticketTtl The ticket time-to-live in milliseconds.
     * @param string $nonce The challenge nonce.
     * @param string $solution The client-provided solution.
     * @param array $challengeContext The challenge context (cpuTarget, baseBlock, isHttp).
     * @param string $deviceId The client device ID.
     * @param string $deviceHash The client device hash.
     * @return string|null The opaque ticket on success, or null on failure.
     */
    public static function verifyCpuTargetPoWAndGenerateTicket(
        string $clientIp,
        int $ticketTtl,
        string $nonce,
        string $solution,
        array $challengeContext,
        string $deviceId = '',
        string $deviceHash = ''
    ): ?string {
        // In HTTP (insecure) mode, no SHA-256 computation is required
        if (!empty($challengeContext['isHttp'])) {
            self::logError('[FP Server Verify] HTTP mode detected (insecure policy): validation without SHA-256 accepted.');
            $expiry = (int)floor(microtime(true) * 1000) + $ticketTtl;
            return self::generateStatelessTicket([
                'expiry' => $expiry,
                'originalIp' => $clientIp,
                'deviceId' => $deviceId,
                'deviceHash' => $deviceHash
            ]);
        }

        $cpuTargetHex = $challengeContext['cpuTarget'] ?? null;
        $baseBlock = $challengeContext['baseBlock'] ?? null;

        if ($cpuTargetHex === null || $baseBlock === null) {
            self::logError('[FP Server Verify] Invalid challenge context. Missing cpuTarget or baseBlock.');
            return null;
        }

        $finalBlock = $baseBlock . $solution;
        $hash = hash('sha256', $finalBlock);

        // Pad target to 64 hex characters to allow direct O(1) lexicographical comparison
        $paddedTarget = str_pad($cpuTargetHex, 64, '0', STR_PAD_LEFT);
        $isValid = strcmp($hash, $paddedTarget) < 0;

        if ($isValid) {
            self::logError('[FP Server Verify] CPU PoW verification PASSED.');

            $expiry = (int)floor(microtime(true) * 1000) + $ticketTtl;
            $payload = [
                'expiry' => $expiry,
                'originalIp' => $clientIp,
                'deviceId' => $deviceId,
                'deviceHash' => $deviceHash
            ];
            return self::generateStatelessTicket($payload);
        }

        // Log details on failure
        self::logError(sprintf(
            '[FP Server Verify] CPU PoW verification FAILED. Details: hashCalculated=0x%s, target=0x%s',
            $hash,
            $cpuTargetHex
        ));

        return null;
    }

    /**
     * Checks the Token Bucket rate limiter for challenge requests from a subnet.
     * Tokens are refilled at a constant rate up to a maximum capacity.
     *
     * @param string $clientIp The client IP (subnet is used as the rate-limit key).
     * @param float $capacity The bucket capacity (max tokens).
     * @param float $refillRate The token refill rate (tokens per second).
     * @return bool True if the request is allowed, false if rate-limited.
     */
    public static function checkChallengeRateLimit(string $clientIp, float $capacity = 5.0, float $refillRate = 0.1): bool
    {
        $subnet = RequestUtils::getIpSubnet($clientIp) ?? $clientIp;

        $store = StoreManager::getStore();
        $key = "rate-limit:{$subnet}";
        $now = microtime(true);

        $rateLimitData = $store->get($key);
        if (!is_array($rateLimitData) || !isset($rateLimitData['tokens'], $rateLimitData['lastRefill'])) {
            $rateLimitData = [
                'tokens' => $capacity,
                'lastRefill' => $now
            ];
        }

        $elapsed = max(0.0, $now - (float)$rateLimitData['lastRefill']);
        $tokens = min($capacity, (float)$rateLimitData['tokens'] + $elapsed * $refillRate);
        $ttl = (int)max(60, ceil($capacity / max(0.1, $refillRate)));

        if ($tokens < 1.0) {
            $store->set($key, [
                'tokens' => $tokens,
                'lastRefill' => $now
            ], $ttl);
            return false;
        }

        $store->set($key, [
            'tokens' => $tokens - 1.0,
            'lastRefill' => $now
        ], $ttl);

        return true;
    }

    /**
     * Derives the set of challenged block indices for a memory PoW solution,
     * based on the seed, the solution, and the number of blocks.
     *
     * @param string $seed The challenge seed.
     * @param int $solution The client solution (used as a salt in the hash).
     * @param int $numBlocks The total number of blocks.
     * @param int $k The number of challenged indices to derive (default 4).
     * @return array<int> The list of challenged block indices.
     */
    private static function getChallengedIndices(string $seed, int $solution, int $numBlocks, int $k = 4): array
    {
        $indices = [];
        $h = (int)bcmod(\Anonympins\Fingerprint\FingerprintBuilder::cyrb53($seed . ":" . $solution), '4294967296');
        for ($i = 0; $i < $k; $i++) {
            $h = self::gmp_imul($h ^ $i, 1597334677);
            $indices[] = abs($h) % $numBlocks;
        }
        return $indices;
    }

    /**
     * Verifies a Merkle proof for a given leaf hash, index, and expected root.
     * Recomputes the root by hashing pairs of siblings along the path.
     *
     * @param string $leafHash The hex hash of the leaf.
     * @param int $index The leaf index in the tree.
     * @param array $proof The list of sibling hashes (hex).
     * @param string $root The expected Merkle root (hex).
     * @return bool True if the proof is valid, false otherwise.
     */
    private static function verifyMerkleProof(string $leafHash, int $index, array $proof, string $root): bool
    {
        $currentHash = $leafHash;
        $idx = $index;
        foreach ($proof as $sibling) {
            $combined = ($idx % 2 === 0) ? $currentHash . $sibling : $sibling . $currentHash;
            $currentHash = hash('sha256', hex2bin($combined));
            $idx = (int)floor($idx / 2);
        }
        return $currentHash === $root;
    }

    /**
     * Legacy memory PoW verification, used for low-difficulty challenges with
     * a simple numeric solution. Rebuilds the whole buffer and replays the
     * random walk to compare with the provided solution.
     *
     * @param string $nonce The challenge nonce.
     * @param int $solution The client-provided solution.
     * @param int $difficulty The difficulty (in MB).
     * @param string $clientSecret The client secret.
     * @return bool True if the solution matches, false otherwise.
     */
    private static function verifyMemoryPoWLegacy(string $nonce, int $solution, int $difficulty, string $clientSecret): bool
    {
        $size = $difficulty * 1024 * 1024;
        $iterations = (int)floor($size / 16);
        $buffer = new \SplFixedArray((int)floor($size / 4));

        $seed = ":{$nonce}:{$clientSecret}";
        $h = 0;
        foreach (unpack('C*', $seed) as $byte) {
            $h += $byte;
        }

        for ($i = 0; $i < count($buffer); $i++) {
            $buffer[$i] = $h = self::gmp_imul($h ^ $i, 1597334677);
        }

        $finalHash = 0;
        $addr = count($buffer) > 0 ? $buffer[0] % count($buffer) : 0;
        for ($i = 0; $i < $iterations; $i++) {
            $addr = $buffer[$addr] % count($buffer);
            $finalHash ^= $addr;
        }

        return $finalHash === $solution;
    }

    /**
     * Verifies a memory PoW solution. Supports both the modern JSON format
     * (with Merkle proofs) and the legacy numeric format for low difficulties.
     * Enforces a maximum allowed difficulty to prevent DoS.
     *
     * @param string $nonce The challenge nonce.
     * @param string $solution The client-provided solution (JSON or numeric string).
     * @param int $difficulty The difficulty (in MB). 0 means the challenge is skipped.
     * @param string $clientSecret The client secret.
     * @return bool True if the solution is valid, false otherwise.
     */
    public static function verifyMemoryPoW(
        string $nonce,
        string $solution,
        int $difficulty,
        string $clientSecret
    ): bool {
        if ($difficulty === 0) {
            return true;
        }
        $maxAllowedMemDifficulty = 128; // 128MB
        if ($difficulty > $maxAllowedMemDifficulty) {
            self::logError("[Security] Memory PoW verification attempt with excessive difficulty: {$difficulty}MB. Denied.");
            return false;
        }

        if ($solution === '') {
            return false;
        }

        $data = json_decode($solution, true);
        if (json_last_error() !== JSON_ERROR_NONE || !isset($data['solution']) || !isset($data['merkleRoot']) || !isset($data['proofs'])) {
            if ($difficulty <= 4 && preg_match('/^\d+$/', $solution)) {
                return self::verifyMemoryPoWLegacy($nonce, (int)$solution, $difficulty, $clientSecret);
            }
            return false;
        }

        $sol = $data['solution'];
        $merkleRoot = $data['merkleRoot'];
        $proofs = $data['proofs'];

        $numBlocks = $difficulty * 256;
        $seed = ":{$nonce}:{$clientSecret}";

        $challengedIndices = self::getChallengedIndices($seed, (int)$sol, $numBlocks, 4);

        foreach ($challengedIndices as $b) {
            $proof = $proofs[$b] ?? $proofs[(string)$b] ?? null;
            if ($proof === null) return false;

            $blockBytes = '';
            $h = (int)bcmod(\Anonympins\Fingerprint\FingerprintBuilder::cyrb53($seed . ":" . $b), '4294967296');
            for ($i = 0; $i < 1024; $i++) {
                $h = self::gmp_imul($h ^ $i, 1597334677);
                $blockBytes .= pack('V', $h);
            }

            $expectedLeaf = hash('sha256', $blockBytes);

            if (!self::verifyMerkleProof($expectedLeaf, $b, $proof, $merkleRoot)) {
                return false;
            }
        }

        $blockCache = [];
        $getBlockElement = function (int $blockIdx, int $elementIdx) use (&$blockCache, $seed): int {
            if (!isset($blockCache[$blockIdx])) {
                $block = [];
                $h = (int)bcmod(\Anonympins\Fingerprint\FingerprintBuilder::cyrb53($seed . ":" . $blockIdx), '4294967296');
                for ($i = 0; $i < 1024; $i++) {
                    $h = self::gmp_imul($h ^ $i, 1597334677);
                    $block[$i] = $h;
                }
                $blockCache[$blockIdx] = $block;
            }
            return $blockCache[$blockIdx][$elementIdx];
        };

        $totalElements = $numBlocks * 1024;
        $addr = $totalElements > 0 ? $getBlockElement(0, 0) % $totalElements : 0;
        $addr = $addr & 0xffffffff;
        $expectedSolution = 0;
        $iterations = 1024;
        for ($i = 0; $i < $iterations; $i++) {
            $blockIdx = (int)floor($addr / 1024);
            $elementIdx = $addr % 1024;
            $addr = $getBlockElement($blockIdx, $elementIdx) % $totalElements;
            $addr = $addr & 0xffffffff;
            $expectedSolution ^= $addr;
        }

        return $expectedSolution === (int)$sol;
    }

    /**
     * Emulates JavaScript's 32-bit signed integer multiplication (Math.imul),
     * handling overflow correctly.
     *
     * @param int $a The first operand.
     * @param int $b The second operand.
     * @return int The 32-bit signed result of a * b.
     */
    private static function gmp_imul(int $a, int $b): int
    {
        $a_lo = $a & 0xffff;
        $a_hi = $a >> 16;
        $b_lo = $b & 0xffff;
        $b_hi = $b >> 16;
        return (($a_lo * $b_lo) + ((($a_hi * $b_lo + $a_lo * $b_hi) << 16) & 0xffffffff)) | 0;
    }

    /**
     * Generates a signed trap URL. The URL is picked from a template and a
     * signature is appended as a query parameter.
     *
     * @param string $nonce The nonce used to sign the URL.
     * @return string The trap URL.
     */
    public static function generateTrapUrl(string $nonce): string
    {
        $template = self::TRAP_URL_TEMPLATES[array_rand(self::TRAP_URL_TEMPLATES)];
        $randomPart = bin2hex(random_bytes(8));
        $path = str_replace('{RANDOM}', $randomPart, $template);

        $signature = substr(hash_hmac('sha256', $nonce . $path, self::getPowSecret()), 0, 16);
        return "{$path}?sig={$signature}";
    }

    /**
     * Verifies whether a given path and signature form a valid trap URL for
     * the given nonce. Uses hash_equals for timing-safe comparison.
     *
     * @param string $path The request path.
     * @param string $signature The signature from the query string.
     * @param string $nonce The nonce to verify against.
     * @return bool True if the trap URL is valid, false otherwise.
     */
    public static function verifyTrapUrl(string $path, string $signature, string $nonce): bool
    {
        if (empty($signature)) {
            return false;
        }
        $expectedSignature = substr(hash_hmac('sha256', $nonce . $path, self::getPowSecret()), 0, 16);
        // Use hash_equals for timing-safe comparison.
        return hash_equals($expectedSignature, $signature);
    }

    /**
     * Loads the JavaScript solver code for inline injection into challenge pages.
     * Searches several candidate paths, including WordPress plugin directories.
     *
     * @return string The JavaScript solver code, or an empty string if not found.
     */
    private static function getPowSolverCode(): string
    {
        if (defined('ANONYMPINS_BOT_MITIGATION_DIR')) {
            $wpPluginSolver = rtrim(ANONYMPINS_BOT_MITIGATION_DIR, '/\\') . '/assets/pow.solver.inline.js';
            if (file_exists($wpPluginSolver)) {
                return (string)RequestUtils::readFileContent($wpPluginSolver);
            }
        }

        $candidates = [
            __DIR__ . '/../../js/pow.solver.inline.js',
            __DIR__ . '/../assets/pow.solver.inline.js',
            __DIR__ . '/../js/pow.solver.inline.js',
            dirname(__DIR__) . '/assets/pow.solver.inline.js',
            dirname(__DIR__) . '/js/pow.solver.inline.js',
        ];
        foreach ($candidates as $solverPath) {
            if (file_exists($solverPath)) {
                return RequestUtils::readFileContent($solverPath) ?: '';
            }
        }
        self::logError("[ChallengeUtils] Error: The pow.solver.inline.js file was not found at the expected location.");
        return '';
    }

    /**
     * Safely renders an inline script tag, using WordPress native function if available.
     *
     * @param string $code
     * @param array<string, mixed> $attributes
     * @return string
     */
    public static function renderScriptTag(string $code, array $attributes = []): string
    {
        if (function_exists('wp_get_inline_script_tag')) {
            return wp_get_inline_script_tag($code, $attributes);
        }
        $tag = 'script';
        return "<{$tag}>{$code}</{$tag}>";
    }

    /**
     * Generates the HTML page for a proof-of-space challenge, embedding the
     * solver code and the challenge script. The page initializes local storage,
     * runs the proof-of-space solver, and redirects with the solution.
     *
     * @param array $challengeDetails The challenge details (nonce, sizeMb, queries, path, peerId, peerBlockIdx).
     * @param string $clientSecret The client secret.
     * @param array $securityConfig The security configuration.
     * @return string The generated HTML page.
     */
    public static function generateSpaceChallengePage(array $challengeDetails, string $clientSecret, array $securityConfig): string
    {
        $nonce = $challengeDetails['nonce'];
        $sizeMb = $challengeDetails['sizeMb'];
        $queries = $challengeDetails['queries'];
        $path = $challengeDetails['path'];
        $peerId = $challengeDetails['peerId'] ?? '';
        $peerBlockIdx = $challengeDetails['peerBlockIdx'] ?? -1;
        $nodeId = $nonce;

        $solverCode = self::getPowSolverCode();
        $queriesJson = json_encode($queries);
        $coopTimeout = $securityConfig['pospace']['coopTimeout'] ?? 15;

        $safePath = json_encode($path, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_UNESCAPED_SLASHES);
        $safeNonce = json_encode($nonce, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_UNESCAPED_SLASHES);
        $safeClientSecret = json_encode($clientSecret, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_UNESCAPED_SLASHES);

        $challengeScript = 'async function solve() {' . "\n"
            . '  const nonce = ' . $safeNonce . ";\n"
            . '  const path = ' . $safePath . ";\n"
            . '  const clientSecret = ' . $safeClientSecret . ";\n"
            . '  const queries = ' . $queriesJson . ";\n"
            . '  const sizeMb = ' . $sizeMb . ";\n"
            . '  const nodeId = "' . $nodeId . "\";\n"
            . '  const peerId = "' . $peerId . "\";\n"
            . '  const peerBlockIdx = ' . $peerBlockIdx . ";\n"
            . '  const coopTimeout = ' . $coopTimeout . ";\n"
            . '  document.getElementById("loader").innerText = "⚙️ Checking persistent local storage...";' . "\n"
            . '  await new Promise(r => setTimeout(r, 10));' . "\n"
            . '  try {' . "\n"
            . '      await window.initializeSpace(nonce + ":" + clientSecret, sizeMb);' . "\n"
            . '      document.getElementById("loader").innerText = "⚙️ Proof of Space generation...";' . "\n"
            . '      const hash = await window.solveSpaceChallenge(nonce + ":" + clientSecret, queries, nonce, clientSecret, "");' . "\n"
            . '      window.location.href = path + "?pow_type=pospace&pow_nonce=" + nonce + "&pow_solution_space=" + hash;' . "\n"
            . '  } catch(e) {' . "\n"
            . '      document.getElementById("loader").innerText = "Error initializing local storage: " + e.message;' . "\n"
            . '  }' . "\n"
            . '}' . "\n"
            . 'solve();';

        return "<html><head><title>Security check</title></head><body style=\"font-family:sans-serif; text-align:center; padding-top:50px;\"><h1>Security check (level 2)</h1><p>We are verifying your storage allocation. This may take a few seconds on first load.</p><div id=\"loader\" style=\"margin:20px;\">⚙️ Initializing storage space...</div>"
            . self::renderScriptTag($solverCode)
            . self::renderScriptTag($challengeScript)
            . "</body></html>";
    }

    /**
     * Generates the HTML page for a combined CPU + Memory proof-of-work challenge.
     * The page embeds the solver code, the challenge script, and hidden trap links
     * (rendered in random tags/positions) to lure malicious crawlers.
     *
     * @param array $cpuChallengeDetails The CPU challenge details (nonce, target, path).
     * @param int $memoryDifficulty The memory difficulty in MB (0 to skip).
     * @param string $clientSecret The client secret.
     * @param array $securityConfig The security configuration.
     * @param array $trapUrls The list of trap URLs to embed.
     * @param string $originalFingerprint The original client fingerprint.
     * @param string $clientIp The client IP.
     * @param string $tlsSessionId The TLS session ID.
     * @param string|null $baseBlock Optional pre-computed base block.
     * @param bool $isHttps Whether the request is over HTTPS.
     * @return string The generated HTML page.
     */
    public static function generateCombinedPoWChallengePage(
        array $cpuChallengeDetails,
        int $memoryDifficulty,
        string $clientSecret,
        array $securityConfig,
        array $trapUrls,
        string $originalFingerprint,
        string $clientIp = '',
        string $tlsSessionId = '',
        ?string $baseBlock = null,
        bool $isHttps = true
    ): string {
        $nonce = $cpuChallengeDetails['nonce'];
        $target = $cpuChallengeDetails['target']; // @phpstan-ignore-line
        $path = $cpuChallengeDetails['path'];
        $isHttp = !$isHttps;

        $solverCode = self::getPowSolverCode();
        if ($baseBlock === null || $baseBlock === '') {
            $baseBlock = self::createCpuChallengeBaseBlock($nonce, $clientSecret, $originalFingerprint, $clientIp, $tlsSessionId);
        }
        $baseBlockBytes = '[' . implode(',', array_values(unpack('C*', $baseBlock))) . ']';

        $trapTags = ['div', 'span', 'p', 'section'];
        $selectedTrapTag = $trapTags[array_rand($trapTags)];
        $layoutProps = [
            'position:absolute;left:-9999px;top:-9999px;transform:scale(0);pointer-events:none;',
            'position:fixed;left:-8888px;top:-8888px;opacity:0;pointer-events:none;width:0;height:0;overflow:hidden;',
            'display:none;visibility:hidden;pointer-events:none;'
        ];
        $selectedLayout = $layoutProps[array_rand($layoutProps)];

        $trapLinks = [];
        foreach ($trapUrls as $index => $url) {
            $nestingType = function_exists('wp_rand') ? wp_rand(0, 2) : random_int(0, 2);
            $innerHtml = ($nestingType === 1) ? "<b>&gt; " . ($index + 1) . "</b>" : (($nestingType === 2) ? "<i>&gt; " . ($index + 1) . "</i>" : "<span>&gt; " . ($index + 1) . "</span>");
            $trapLinks[] = "<a href=\"{$url}\" tabindex=\"-1\">{$innerHtml}</a>";
        }
        $trapLinksHtml = implode(' ', $trapLinks);
        $trapContainerHtml = "<{$selectedTrapTag} style=\"{$selectedLayout}\" aria-hidden=\"true\">{$trapLinksHtml}</{$selectedTrapTag}>";

        $safePath = json_encode($path, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_UNESCAPED_SLASHES);
        $safeNonce = json_encode($nonce, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_UNESCAPED_SLASHES);
        $safeClientSecret = json_encode($clientSecret, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_UNESCAPED_SLASHES);
        $isHttpJs = $isHttp ? 'true' : 'false';

        $challengeScript = 'async function solve() {' . "\n"
            . '  const nonce = ' . $safeNonce . ";\n"
            . '  const path = ' . $safePath . ";\n"
            . '  const clientSecret = ' . $safeClientSecret . ";\n"
            . '  const isHttp = ' . $isHttpJs . ";\n"
            . '  const cpuTarget = BigInt("0x" + "' . $target . "\");\n"
            . '  const memDifficulty = ' . $memoryDifficulty . ";\n"
            . '  const baseBlock = new Uint8Array(' . $baseBlockBytes . ");\n"
            . '  if (isHttp) {' . "\n"
            . '      document.getElementById("loader").innerText = "HTTP connection: quick acknowledgment...";' . "\n"
            . '      await new Promise(r => setTimeout(r, 150));' . "\n"
            . '      window.location.href = path + "?pow_type=cpu_mem&pow_nonce=" + nonce + "&pow_solution_cpu=http_simulacre_ack&pow_solution_mem=0";' . "\n"
            . '      return;' . "\n"
            . '  }' . "\n"
            . '  document.getElementById("loader").innerText = "⚙️ Performing CPU security calculation...";' . "\n"
            . '  const cpuSolution = await window.solveCpuChallengeInline(baseBlock, cpuTarget, (progress) => {});' . "\n"
            . '  if (memDifficulty > 0) {' . "\n"
            . '      document.getElementById("loader").innerText = "⚙️ Performing memory allocation and calculation... (" + memDifficulty + " MB)";' . "\n"
            . '      await new Promise(r => setTimeout(r, 10));' . "\n"
            . '  }' . "\n"
            . '  let memSolution = 0;' . "\n"
            . '  try {' . "\n"
            . '      const memSeed = ":" + nonce + ":" + clientSecret;' . "\n"
            . '      memSolution = await window.solveMemoryChallenge(memSeed, memDifficulty);' . "\n"
            . '  } catch(e) {' . "\n"
            . '      document.getElementById("loader").innerText = "Error: Insufficient memory. Please refresh.";' . "\n"
            . '      return;' . "\n"
            . '  }' . "\n"
            . '  const finalUrl = path + "?pow_type=cpu_mem&pow_nonce=" + nonce + "&pow_solution_cpu=" + cpuSolution + "&pow_solution_mem=" + encodeURIComponent(JSON.stringify(memSolution));' . "\n"
            . '  window.location.href = finalUrl;' . "\n"
            . '}' . "\n"
            . 'solve();';

        $solverTag = self::renderScriptTag($solverCode);
        $challengeTag = self::renderScriptTag($challengeScript);
        $htmlTemplate = '<html><head><title>Advanced security check</title></head><body style="font-family:sans-serif; text-align:center; padding-top:50px;"><h1>Enhanced verification... (level 2)</h1><p>Your activity requires an additional security check. This may take a few moments.</p><div id="loader" style="margin:20px;">⚙️ Initializing combined verification...</div><!-- FINGERPRINT_SOLVER_SCRIPT --><!-- FINGERPRINT_CHALLENGE_SCRIPT --><!-- FINGERPRINT_TRAPS --></body></html>';
        $customTemplatePath = $securityConfig['challengePagePath'] ?? null;

        if ($customTemplatePath && file_exists($customTemplatePath)) {
            $htmlTemplate = RequestUtils::readFileContent($customTemplatePath) ?: $htmlTemplate;
        }

        return str_replace(
            ['<!-- FINGERPRINT_SOLVER_SCRIPT -->', '<!-- FINGERPRINT_CHALLENGE_SCRIPT -->', '<!-- FINGERPRINT_TRAPS -->', '<script><!-- FINGERPRINT_SOLVER_SCRIPT --></script>', '<script><!-- FINGERPRINT_CHALLENGE_SCRIPT --></script>'],
            [$solverTag, $challengeTag, $trapContainerHtml, $solverTag, $challengeTag],
            $htmlTemplate
        );
    }

    /**
     * Logs an error message using the PHP error log.
     *
     * @param string $message The message to log.
     * @return void
     */
    private static function logError(string $message): void
    {
        // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- Challenge diagnostic logging
        error_log($message);
    }

    /**
     * Safely sanitizes a string input using WordPress functions if available, or fallback PHP functions.
     *
     * @param mixed $value
     * @return string
     */
    private static function sanitizeString($value): string
    {
        if (!is_scalar($value)) {
            return '';
        }
        $val = (string)$value;
        if (function_exists('wp_unslash')) {
            $val = wp_unslash($val);
        }
        if (function_exists('sanitize_text_field')) {
            return sanitize_text_field($val);
        }
        if (function_exists('wp_strip_all_tags')) {
            return trim(wp_strip_all_tags($val));
        }
        // phpcs:ignore WordPress.WP.AlternativeFunctions.strip_tags_strip_tags -- Standalone fallback when running outside WordPress
        return trim(strip_tags($val));
    }

    /**
     * Safely retrieves and sanitizes a value from the $_SERVER superglobal.
     * Uses WordPress functions if available, otherwise falls back to basic PHP sanitization.
     *
     * @param string $key The key to retrieve from $_SERVER.
     * @param mixed $default The default value to return if the key is not found.
     * @return mixed The sanitized value.
     */
    private static function getSanitizedServerVar(string $key, $default = '')
    {
        if (!isset($_SERVER[$key])) {
            return $default;
        }

        // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized,WordPress.Security.ValidatedSanitizedInput.MissingUnslash -- Unslashed and sanitized immediately below
        $value = $_SERVER[$key];
        return self::sanitizeString($value);
    }
}
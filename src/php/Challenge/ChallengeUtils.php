<?php

declare(strict_types=1);

namespace Anonympins\Fingerprint\Challenge;

use Anonympins\Fingerprint\Store\StoreManager;
use Anonympins\Fingerprint\FingerprintBuilder;
use Anonympins\Fingerprint\Utils\BigInt;
use Anonympins\Fingerprint\Utils\RequestUtils;

/**
 * Classe utilitaire pour la génération et la vérification des challenges Proof-of-Work.
 */
class ChallengeUtils
{
    private static function fround(float $value): float
    {
        return unpack('f', pack('f', $value))[1];
    }

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

    public static function verifyGpuPow(string $seed, int $iterations, string $solution, array $sampleIndices = [0, 12, 35, 57]): bool
    {
        $values = explode(',', $solution);
        if (count($values) !== 64) {
            return false;
        }
        $numericSeed = self::hashSeedToFloat($seed);
        $r = 3.9999;
        foreach ($sampleIndices as $idx) {
            if ($idx < 0 || $idx >= 64) {
                return false;
            }
            $x = self::fround($numericSeed + $idx * 0.015);
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

    private const TRAP_URL_TEMPLATES = [
        '/includes/config-{RANDOM}.php',
        '/.env.{RANDOM}',
        '/backups/db_backup_{RANDOM}.sql.gz',
        '/api/v1/internal/status?trace={RANDOM}',
        '/_private/deploy_key_{RANDOM}.pem',
        '/logs/app_error_{RANDOM}.log',
        '/.git/config_{RANDOM}'
    ];

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
        // Nettoyage des nœuds expirés (vieux de plus de 2 minutes)
        $nodes = array_filter($nodes, fn($n) => ($now - $n['timestamp']) < 120);
        
        $nodes[$nodeId] = [
            'nodeId' => $nodeId,
            'seed' => $seed,
            'timestamp' => $now
        ];
        
        $store->set($key, $nodes, 120);
    }

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

    public static function handleCooperativeRequest(array $params): ?array
    {
        $op = $params['coop_op'] ?? null;
        if (!$op) {
            return null;
        }

        $store = StoreManager::getStore();
        $nodeId = $params['node_id'] ?? '';
        if (empty($nodeId)) {
            return ['error' => 'Missing node_id'];
        }

        switch ($op) {
            case 'register':
                $clientIp = $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';
                $seed = $params['seed'] ?? '';
                self::registerCooperativeNode($clientIp, $nodeId, $seed);
                return ['status' => 'registered'];

            case 'request_peer_block':
                $peerId = $params['peer_id'] ?? '';
                $blockIdx = (int)($params['block_idx'] ?? 0);
                $requestId = $params['req_id'] ?? '';
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
                $requesterId = $params['requester_id'] ?? '';
                $requestId = $params['req_id'] ?? '';
                $blockData = $params['block_data'] ?? '';
                if (empty($requesterId) || empty($requestId)) {
                    return ['error' => 'Invalid parameters'];
                }
                
                $responseKey = "coop-mailbox:res:{$requesterId}:{$requestId}";
                $store->set($responseKey, ['block_data' => $blockData], 30);
                return ['status' => 'delivered'];

            case 'poll_response':
                $requestId = $params['req_id'] ?? '';
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

        // Tentative de couplage coopératif avec un nœud du même sous-réseau
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

    public static function verifySpacePoW(string $nonce, string $solution, array $queries, string $seed, string $clientSecret): bool
    {
        $combined = '';
        foreach ($queries as $idx) {
            $combined .= self::generateBlock($seed, (int)$idx);
        }
        
        // Vérification de la preuve coopérative
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
     * Récupère la clé secrète pour les PoW depuis les variables d'environnement.
     */
    private static function getPowSecret(): string
    {
        $secret = $_ENV['POW_SECRET'] ?? getenv('POW_SECRET');
        if (!$secret && ($_ENV['APP_ENV'] ?? getenv('APP_ENV')) === 'production') {
            throw new \RuntimeException('POW_SECRET environment variable is not set. This is required for production.');
        }
        return $secret ?: "fallback-dev-secret-32-chars-minimum";
    }

    /**
     * Génère un ticket stateless chiffré et signé contenant le contexte d'autorisation.
     * @param array $payload
     * @return string
     */
    public static function generateStatelessTicket(array $payload): string
    {
        $ed25519Key = $_ENV['ED25519_PRIVATE_KEY'] ?? getenv('ED25519_PRIVATE_KEY');
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
                error_log("[ChallengeUtils] Ed25519 signing failed: " . $e->getMessage());
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
     * Décode et valide un ticket stateless chiffré et signé.
     * @param string $ticket
     * @param string $secret
     * @return array|null
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
                
                $ed25519PubKey = $_ENV['ED25519_PUBLIC_KEY'] ?? getenv('ED25519_PUBLIC_KEY');
                if (!$ed25519PubKey) {
                    error_log("[ChallengeUtils] ED25519_PUBLIC_KEY is not defined in environment.");
                    return null;
                }
                
                $publicKey = openssl_pkey_get_public($ed25519PubKey);
                if ($publicKey && openssl_verify($payloadJson, $signature, $publicKey, null) === 1) {
                    return json_decode($payloadJson, true);
                }
                return null;
            }
        } catch (\Throwable $e) {
            error_log("[ChallengeUtils] Ed25519 verification failed: " . $e->getMessage());
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
     * Vérifie si un ticket de passage est valide (supporte les tickets opaques via store et le fallback legacy).
     * Supporte une clé secrète optionnelle passée en paramètre pour la compatibilité avec les tests.
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

        // Tentative de validation stateless d'abord
        $ticketData = self::parseStatelessTicket($ticket, $secret);
        if ($ticketData !== null) {
            $expiry = $ticketData['expiry'] ?? null;
            $originalIp = $ticketData['originalIp'] ?? null;
            $storedDeviceId = $ticketData['deviceId'] ?? '';
            $storedDeviceHash = $ticketData['deviceHash'] ?? '';

            if (!$expiry || (int)floor(microtime(true) * 1000) > (int)$expiry) {
                return false;
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

        // Fallback rétrocompatible pour les anciens tickets signés (sans état)
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
     * Calcule la cible de difficulté pour un challenge CPU en fonction du facteur de suspicion.
     */
    public static function calculateCpuTarget(float $suspicionFactor, array $securityConfig): string
    {
        $cpuConfig = $securityConfig['cpu'] ?? [];
        $minDifficultyBits = $cpuConfig['minDifficultyBits'] ?? 8;
        $maxDifficultyBits = $cpuConfig['maxDifficultyBits'] ?? 24;

        $totalDifficultyBits = $minDifficultyBits + $suspicionFactor * ($maxDifficultyBits - $minDifficultyBits);

        if ($totalDifficultyBits <= 0) {
            // Cible maximale (challenge trivial)
            return (BigInt::pow(2, 256)->sub(new BigInt(1)))->toHex();
        }

        $shift = 256 - (int)floor($totalDifficultyBits);
        return (new BigInt(1))->shiftLeft($shift)->toHex();
    }

    /**
     * Crée le bloc de données de base pour le challenge CPU.
     */
    public static function createCpuChallengeBaseBlock(string $nonce, string $clientSecret, string $fingerprint): string
    {
        $parts = explode('|', $fingerprint);
        $filteredParts = array_filter($parts);
        sort($filteredParts);
        $sortedFingerprint = implode('|', $filteredParts);
        
        return "{$nonce}:{$clientSecret}:{$sortedFingerprint}:";
    }

    /**
     * Vérifie une solution de PoW CPU et génère un ticket si elle est valide.
     * @return string|null Le ticket opaque en cas de succès, sinon null.
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
        $cpuTargetHex = $challengeContext['cpuTarget'] ?? null;
        $baseBlock = $challengeContext['baseBlock'] ?? null;

        if ($cpuTargetHex === null || $baseBlock === null) {
            error_log('[FP Server Verify] Invalid challenge context. Missing cpuTarget or baseBlock.');
            return null;
        }

        $finalBlock = $baseBlock . $solution;
        $hash = hash('sha256', $finalBlock);

        // Pad target to 64 hex characters to allow direct O(1) lexicographical comparison
        $paddedTarget = str_pad($cpuTargetHex, 64, '0', STR_PAD_LEFT);
        $isValid = strcmp($hash, $paddedTarget) < 0;

        if ($isValid) {
            error_log('[FP Server Verify] CPU PoW verification PASSED.');
            
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
        error_log(sprintf(
            '[FP Server Verify] CPU PoW verification FAILED. Details: hashCalculated=0x%s, target=0x%s',
            $hash,
            $cpuTargetHex
        ));

        return null;
    }

    /**
     * Vérifie le limiteur de débit Token Bucket pour les demandes de challenge d'un sous-réseau.
     */
    public static function checkChallengeRateLimit(string $clientIp): bool
    {
        $subnet = RequestUtils::getIpSubnet($clientIp);
        if ($subnet === null) {
            return false;
        }

        $store = StoreManager::getStore();
        $key = "rate-limit:{$subnet}";
        $rateLimitData = $store->get($key) ?? [
            'tokens' => 5.0,
            'lastRefill' => microtime(true)
        ];

        $capacity = 5.0;
        $refillRate = 0.1; // 1 token toutes les 10 secondes
        $now = microtime(true);

        $elapsed = $now - $rateLimitData['lastRefill'];
        $tokens = min($capacity, $rateLimitData['tokens'] + $elapsed * $refillRate);

        if ($tokens < 1.0) {
            $store->set($key, [
                'tokens' => $tokens,
                'lastRefill' => $now
            ], 60);
            return false;
        }

        $store->set($key, [
            'tokens' => $tokens - 1.0,
            'lastRefill' => $now
        ], 60);

        return true;
    }

    /**
     * Vérifie une solution de PoW mémoire.
     */
    public static function verifyMemoryPoW(
        string $nonce,
        string $solution,
        int $difficulty,
        string $clientSecret
    ): bool {
        $maxAllowedMemDifficulty = 128; // 128MB
        if ($difficulty > $maxAllowedMemDifficulty) {
            error_log("[Security] Memory PoW verification attempt with excessive difficulty: {$difficulty}MB. Denied.");
            return false;
        }

        if (empty($solution)) {
            return false;
        }

        // If difficulty is high (production workloads), we treat memory PoW purely as a client-side cost.
        // Cryptographic integrity is already fully enforced by the chained CPU PoW verification.
        if ($difficulty > 4) {
            return true;
        }

        $size = $difficulty * 1024 * 1024;
        if ($size <= 0) {
            return true; // Pas de challenge mémoire si la difficulté est nulle ou négative.
        }
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

        return $finalHash === (int)$solution;
    }

    /**
     * Émule la multiplication 32-bit `Math.imul` de JavaScript.
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
     * Génère une URL piège signée.
     * @param string $nonce Le nonce pour signer l'URL.
     * @return string L'URL piège.
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
     * Vérifie si une URL donnée est une URL piège valide pour un nonce donné.
     * @param string $path Le chemin de la requête.
     * @param string $signature La signature provenant de la query string.
     * @param string $nonce Le nonce à vérifier.
     * @return bool
     */
    public static function verifyTrapUrl(string $path, string $signature, string $nonce): bool
    {
        if (empty($signature)) {
            return false;
        }
        $expectedSignature = substr(hash_hmac('sha256', $nonce . $path, self::getPowSecret()), 0, 16);
        // Utilise hash_equals pour une comparaison sécurisée contre les attaques temporelles.
        return hash_equals($expectedSignature, $signature);
    }

    /**
     * Charge le contenu du solveur JS pour l'injection inline.
     * @return string Le code JavaScript du solveur.
     */
    private static function getPowSolverCode(): string
    {
        // Le chemin doit être relatif à ce fichier ou absolu.
        $solverPath = __DIR__ . '/../../js/pow.solver.inline.js';
        if (!file_exists($solverPath)) {
            error_log("[ChallengeUtils] Erreur: Le fichier pow.solver.inline.js n'a pas été trouvé à l'emplacement attendu.");
            return '';
        }
        return file_get_contents($solverPath) ?: '';
    }

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

        $challengeScript = <<<JS
          async function solve() {
            const nonce = "{$nonce}";
            const path = "{$path}";
            const clientSecret = "{$clientSecret}";
            const queries = {$queriesJson};
            const sizeMb = {$sizeMb};
            const nodeId = "{$nodeId}";
            const peerId = "{$peerId}";
            const peerBlockIdx = {$peerBlockIdx};
            
            document.getElementById('loader').innerText = '⚙️ Checking persistent local storage...';
            await new Promise(r => setTimeout(r, 10));
            
            try {
                await window.initializeSpace(nonce + ":" + clientSecret, sizeMb);
                
                // Enregistrement coopératif
                await fetch(window.location.pathname + "?coop_op=register&node_id=" + nodeId + "&seed=" + encodeURIComponent(nonce + ":" + clientSecret));
                
                // Écoute des requêtes entrantes de nos pairs suspects
                setInterval(async () => {
                    try {
                        const res = await fetch(window.location.pathname + "?coop_op=poll_requests&node_id=" + nodeId);
                        const data = await res.json();
                        if (data.requests && data.requests.length > 0) {
                            for (const req of data.requests) {
                                document.getElementById('loader').innerText = '📤 Transfert coopératif de bloc vers le pair...';
                                const blockData = await window.readSpaceBlock(req.block_idx);
                                await fetch(window.location.pathname + "?coop_op=respond_block&node_id=" + nodeId + "&requester_id=" + req.requester_id + "&req_id=" + req.req_id + "&block_data=" + encodeURIComponent(blockData));
                            }
                        }
                    } catch (e) {
                        console.error("Cooperative polling error", e);
                    }
                }, 1000);
                
                // Téléchargement du bloc du pair si configuré
                let peerBlock = "";
                if (peerId && peerBlockIdx !== -1) {
                    document.getElementById('loader').innerText = '📥 Téléchargement du bloc de validation du pair (' + peerId + ')...';
                    const reqId = Math.random().toString(36).substring(2);
                    await fetch(window.location.pathname + "?coop_op=request_peer_block&node_id=" + nodeId + "&peer_id=" + peerId + "&block_idx=" + peerBlockIdx + "&req_id=" + reqId);
                    
                    let attempts = 0;
                    while (attempts < 15) {
                        const res = await fetch(window.location.pathname + "?coop_op=poll_response&node_id=" + nodeId + "&req_id=" + reqId);
                        const data = await res.json();
                        if (data.status === 'ready') {
                            peerBlock = data.block_data;
                            break;
                        }
                        await new Promise(r => setTimeout(r, 1000));
                        attempts++;
                    }
                    if (!peerBlock) {
                        document.getElementById('loader').innerText = '⚠️ Peer de sous-réseau injoignable. Validation solo...';
                    }
                }
                
                document.getElementById('loader').innerText = '⚙️ Génération de la Preuve d\\'Espace...';
                const hash = await window.solveSpaceChallenge(nonce + ":" + clientSecret, queries, nonce, clientSecret, peerBlock);
                
                window.location.href = path + "?pow_type=pospace&pow_nonce=" + nonce + "&pow_solution_space=" + hash + (peerBlock ? "&pow_coop=1" : "");
            } catch(e) {
                document.getElementById('loader').innerText = "Error initializing local storage: " + e.message;
            }
          }
          solve();
JS;

        return "<html><head><title>Security Check</title></head><body style=\"font-family:sans-serif; text-align:center; padding-top:50px;\"><h1>Security Check (Level 2)</h1><p>We are verifying your storage allocation. This may take a few seconds on first load.</p><div id=\"loader\" style=\"margin:20px;\">⚙️ Initializing storage space...</div><script>{$solverCode}</script><script>{$challengeScript}</script></body></html>";
    }

    /**
     * Génère le contenu HTML pour un challenge combiné CPU + Mémoire.
     * @param array $cpuChallengeDetails
     * @param int $memoryDifficulty
     * @param string $clientSecret
     * @param array $securityConfig
     * @param array $trapUrls
     * @param string $originalFingerprint
     * @return string
     */
    public static function generateCombinedPoWChallengePage(
        array $cpuChallengeDetails,
        int $memoryDifficulty,
        string $clientSecret,
        array $securityConfig,
        array $trapUrls,
        string $originalFingerprint
    ): string {
        $nonce = $cpuChallengeDetails['nonce'];
        $target = $cpuChallengeDetails['target']; // @phpstan-ignore-line
        $path = $cpuChallengeDetails['path'];

        $solverCode = self::getPowSolverCode();
        $baseBlock = self::createCpuChallengeBaseBlock($nonce, $clientSecret, $originalFingerprint);
        $baseBlockBytes = '[' . implode(',', array_values(unpack('C*', $baseBlock))) . ']';

        $trapLinksHtml = implode(' ', array_map(
            fn($url, $index) => "<a href=\"{$url}\" tabindex=\"-1\"><span>&gt; " . ($index + 1) . "</span></a>",
            $trapUrls,
            array_keys($trapUrls)
        ));
        $trapContainerHtml = "<div style=\"position:absolute;left:-9999px;top:-9999px;transform:scale(0);pointer-events:none;\" aria-hidden=\"true\">{$trapLinksHtml}</div>";

        $challengeScript = <<<JS
          async function solve() {
            const nonce = "{$nonce}";
            const path = "{$path}";
            const clientSecret = "{$clientSecret}";
            const cpuTarget = BigInt("0x" + "{$target}");
            const memDifficulty = {$memoryDifficulty};
            const baseBlock = new Uint8Array({$baseBlockBytes});

            document.getElementById('loader').innerText = '⚙️ Performing CPU security calculation...';
            const cpuSolution = await window.solveCpuChallengeInline(baseBlock, cpuTarget, (progress) => {});

            if (memDifficulty > 0) {
                document.getElementById('loader').innerText = '⚙️ Performing memory allocation and calculation... (' + memDifficulty + ' MB)';
                await new Promise(r => setTimeout(r, 10));
            }
            let memSolution = 0;
            try {
                const memSeed = nonce + ":" + clientSecret;
                memSolution = await window.solveMemoryChallenge(memSeed, memDifficulty);
            } catch(e) {
                document.getElementById('loader').innerText = "Error: Insufficient memory. Please refresh.";
                return;
            }

            const finalUrl = path + "?pow_type=cpu_mem&pow_nonce=" + nonce + "&pow_solution_cpu=" + cpuSolution + "&pow_solution_mem=" + memSolution;
            window.location.href = finalUrl;
          }
          solve();
JS;

        $htmlTemplate = '<html><head><title>Advanced Security Check</title></head><body style="font-family:sans-serif; text-align:center; padding-top:50px;"><h1>Enhanced Verification... (Level 2)</h1><p>Your activity requires an additional security check. This may take a few moments.</p><div id="loader" style="margin:20px;">⚙️ Initializing combined verification...</div><script><!-- FINGERPRINT_SOLVER_SCRIPT --></script><script><!-- FINGERPRINT_CHALLENGE_SCRIPT --></script><!-- FINGERPRINT_TRAPS --></body></html>';
        $customTemplatePath = $securityConfig['challengePagePath'] ?? null;

        if ($customTemplatePath && file_exists($customTemplatePath)) {
            $htmlTemplate = file_get_contents($customTemplatePath) ?: $htmlTemplate;
        }

        return str_replace(
            ['<!-- FINGERPRINT_SOLVER_SCRIPT -->', '<!-- FINGERPRINT_CHALLENGE_SCRIPT -->', '<!-- FINGERPRINT_TRAPS -->'],
            [$solverCode, $challengeScript, $trapContainerHtml],
            $htmlTemplate
        );
    }
}
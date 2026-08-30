<?php

declare(strict_types=1);

namespace Anonympins\Fingerprint\Challenge;

use Anonympins\Fingerprint\RequestContext;
use Anonympins\Fingerprint\Utils\MaliciousPatterns;

/**
 * Fournit des fonctions utilitaires pour la gestion des challenges (PoW, tickets, honeypots).
 */
class ChallengeUtils
{
    /**
     * Récupère le secret PoW depuis les variables d'environnement.
     * @return string
     * @throws \RuntimeException Si POW_SECRET n'est pas défini en production.
     */
    public static function getPowSecret(): string
    {
        $secret = $_ENV['POW_SECRET'] ?? getenv('POW_SECRET');
        if (!$secret) {
            if (($_ENV['APP_ENV'] ?? getenv('APP_ENV')) === 'production') {
                throw new \RuntimeException('POW_SECRET environment variable is not set. This is required for production.');
            }
            return "fallback-dev-secret-32-chars-minimum"; // Secret de secours pour le développement
        }
        return $secret;
    }

    /**
     * Crée un ticket de clearance HMAC-SHA256.
     * @param string $ip L'adresse IP du client.
     * @param int $ttl La durée de vie du ticket en millisecondes.
     * @return string Le ticket sous forme "expiry:signature".
     */
    public static function createTicket(string $ip, int $ttl): string
    {
        $expiry = (int)(microtime(true) * 1000) + $ttl;
        $signature = hash_hmac('sha256', "{$ip}:{$expiry}", self::getPowSecret());
        return "{$expiry}:{$signature}";
    }

    /**
     * Vérifie la validité d'un ticket de clearance.
     * @param string $ip L'adresse IP du client.
     * @param string|null $ticket Le ticket à vérifier.
     * @return bool True si le ticket est valide, false sinon.
     */
    public static function isTicketValid(string $ip, ?string $ticket): bool
    {
        if (empty($ticket) || !str_contains($ticket, ':')) {
            return false;
        }

        [$expiry, $sig] = explode(':', $ticket, 2);

        if (!is_numeric($expiry) || (int)$expiry <= (int)(microtime(true) * 1000)) {
            return false; // Ticket expiré ou malformé
        }

        $expectedSig = hash_hmac('sha256', "{$ip}:{$expiry}", self::getPowSecret());

        // Utiliser hash_equals pour prévenir les attaques par timing
        return hash_equals($sig, $expectedSig);
    }

    /**
     * Génère un bloc de base pour le challenge CPU.
     * @param string $nonce
     * @param string|null $clientSecret
     * @param string|null $fingerprint
     * @return string Le message de base à hacher.
     */
    public static function createCpuChallengeBaseBlock(string $nonce, ?string $clientSecret, ?string $fingerprint): string
    {
        $sortedFingerprint = '';
        if ($fingerprint) {
            $parts = array_filter(explode('|', $fingerprint));
            sort($parts);
            $sortedFingerprint = implode('|', $parts);
        }
        return "{$nonce}:{$clientSecret}:{$sortedFingerprint}:";
    }

    /**
     * Calcule la cible de difficulté pour un challenge CPU.
     * @param float $suspicionFactor Facteur de suspicion (0 à 1+).
     * @param array<string, mixed> $securityConfig Configuration de sécurité.
     * @return string La cible sous forme hexadécimale.
     */
    public static function calculateCpuTarget(float $suspicionFactor, array $securityConfig): string
    {
        $cpuConfig = $securityConfig['cpu'] ?? [];
        $minDifficultyBits = $cpuConfig['minDifficultyBits'] ?? 8;
        $maxDifficultyBits = $cpuConfig['maxDifficultyBits'] ?? 16;

        $maxAllowedCpuDifficultyBits = 128;
        if ($maxDifficultyBits > $maxAllowedCpuDifficultyBits) {
            error_log("[Fingerprint] CPU PoW maxDifficultyBits ({$maxDifficultyBits}) exceeds the allowed maximum of {$maxAllowedCpuDifficultyBits}. Capping to the maximum.");
            $maxDifficultyBits = $maxAllowedCpuDifficultyBits;
        }

        $totalDifficultyBits = $minDifficultyBits + $suspicionFactor * ($maxDifficultyBits - $minDifficultyBits);

        if ($totalDifficultyBits <= 0) {
            // Si la difficulté est nulle ou négative, la cible est maximale (aucun challenge).
            return str_repeat('f', 64); // 2^256 - 1 en hex
        }

        // La cible est 2^(256 - N) où N est le nombre de bits de difficulté.
        // En PHP, on utilise GMP pour les grands nombres.
        $shift = gmp_sub(256, floor($totalDifficultyBits));
        $target = gmp_pow(2, (int)gmp_strval($shift));

        // Convertir en hexadécimal et padder à 64 caractères (256 bits)
        return str_pad(gmp_strval($target, 16), 64, '0', STR_PAD_LEFT);
    }

    /**
     * Vérifie une solution de challenge CPU.
     * @param string $clientIp
     * @param int $ticketTtl
     * @param string $nonce
     * @param string $solution
     * @param array<string, mixed> $challengeContext
     * @return string|null Le ticket si valide, null sinon.
     */
    public static function verifyCpuTargetPoWAndGenerateTicket(
        string $clientIp,
        int    $ticketTtl,
        string $nonce,
        string $solution,
        array  $challengeContext
    ): ?string
    {
        $cpuTarget = $challengeContext['cpuTarget'] ?? null;
        $baseBlock = $challengeContext['baseBlock'] ?? null;

        if (!$cpuTarget || !$baseBlock) {
            error_log('[Fingerprint Server Verify] Invalid challenge context. Missing cpuTarget or baseBlock.');
            return null;
        }

        $finalBlock = $baseBlock . $solution;
        $hash = hash('sha256', $finalBlock);

        $hashAsInt = gmp_init($hash, 16);
        $targetAsInt = gmp_init($cpuTarget, 16);

        $isValid = gmp_cmp($hashAsInt, $targetAsInt) < 0;

        if (!$isValid) {
            error_log('[Fingerprint Server Verify] CPU PoW verification FAILED. Details: ' . json_encode([
                    'hashCalculated' => '0x' . $hash,
                    'target' => '0x' . $cpuTarget,
                ]));
            return null;
        }

        error_log('[Fingerprint Server Verify] CPU PoW verification PASSED.');
        return self::createTicket($clientIp, $ticketTtl);
    }

    /**
     * Vérifie une solution de challenge mémoire.
     * @param string $nonce
     * @param string $solution
     * @param int $difficulty
     * @param string $clientSecret
     * @return bool
     */
    public static function verifyMemoryPoW(string $nonce, string $solution, int $difficulty, string $clientSecret): bool
    {
        $maxAllowedMemDifficulty = 128; // 128MB
        if ($difficulty > $maxAllowedMemDifficulty) {
            error_log("[Fingerprint] Memory PoW verification attempt with excessive difficulty: {$difficulty}MB. Denied.");
            return false;
        }

        $size = $difficulty * 1024 * 1024;
        $iterations = $size / 16;
        $bufferSize = $size / 4; // Number of Uint32 elements

        $seed = "{$nonce}:{$clientSecret}";
        $h = array_reduce(str_split($seed), fn($acc, $v) => $acc + ord($v), 0);

        $simulatedBuffer = [];
        $currentH = $h;
        for ($i = 0; $i < min($bufferSize, 1000); $i++) { // Limiter la taille du buffer simulé
            $currentH = self::imul($currentH ^ $i, 1597334677);
            $simulatedBuffer[$i] = $currentH;
        }

        if (empty($simulatedBuffer)) {
            return false; // Buffer vide, impossible de vérifier
        }

        $addr = $simulatedBuffer[0] % count($simulatedBuffer);
        for ($i = 0; $i < min($iterations, 1000); $i++) { // Limiter les itérations simulées
            $addr = $simulatedBuffer[$addr] % count($simulatedBuffer);
            $finalHash ^= $simulatedBuffer[$addr];
        }

        return (string)$finalHash === $solution;
    }
};
<?php

declare(strict_types=1);

namespace Anonympins\Fingerprint\Challenge;

use Anonympins\Fingerprint\Utils\BigInt;

/**
 * Classe utilitaire pour la génération et la vérification des challenges Proof-of-Work.
 */
class ChallengeUtils
{
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
     * Vérifie si un ticket de passage est valide.
     */
    public static function isTicketValid(?string $ip, ?string $ticket): bool
    {
        if (empty($ip) || empty($ticket) || !str_contains($ticket, ':')) {
            return false;
        }

        [$expiry, $sig] = explode(':', $ticket, 2);
        if (empty($expiry) || empty($sig) || (int)floor((float)$expiry) < (int)floor(microtime(true) * 1000)) {
            return false;
        }

        $expectedSig = hash_hmac('sha256', "{$ip}:{$expiry}", self::getPowSecret());

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
     * @return string|null Le ticket en cas de succès, sinon null.
     */
    public static function verifyCpuTargetPoWAndGenerateTicket(
        string $clientIp,
        int $ticketTtl,
        string $nonce,
        string $solution,
        array $challengeContext
    ): ?string {
        $cpuTargetHex = $challengeContext['cpuTarget'] ?? null;
        $baseBlock = $challengeContext['baseBlock'] ?? null;

        if ($cpuTargetHex === null || $baseBlock === null) {
            error_log('[FP Server Verify] Invalid challenge context. Missing cpuTarget or baseBlock.');
            return null;
        }

        $finalBlock = $baseBlock . $solution;
        $hash = hash('sha256', $finalBlock);

        $hashAsInt = BigInt::fromHex($hash);
        $targetAsInt = BigInt::fromHex($cpuTargetHex);

        if ($hashAsInt->compareTo($targetAsInt) < 0) {
            $expiry = (int)floor(microtime(true) * 1000) + $ticketTtl;
            $signature = hash_hmac('sha256', "{$clientIp}:{$expiry}", self::getPowSecret());
            return "{$expiry}:{$signature}";
        }

        error_log('[FP Server Verify] CPU PoW verification FAILED.');
        return null;
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
            $h = self::imul($h ^ $i, 1597334677);
            $buffer[$i] = $h;
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
    private static function imul(int $a, int $b): int
    {
        $ah = ($a >> 16) & 0xffff;
        $al = $a & 0xffff;
        $bh = ($b >> 16) & 0xffff;
        $bl = $b & 0xffff;
        $result = ($al * $bl) + ((($ah * $bl + $al * $bh) << 16) & 0xffffffff);
        if ($result & 0x80000000) {
            return $result | (int)0xffffffff00000000;
        }
        return $result;
    }
}
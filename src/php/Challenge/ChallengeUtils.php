<?php

declare(strict_types=1);

namespace Anonympins\Fingerprint\Challenge;

use Anonympins\Fingerprint\Utils\BigInt;

/**
 * Classe utilitaire pour la génération et la vérification des challenges Proof-of-Work.
 */
class ChallengeUtils
{
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

        if ($hashAsInt->compareTo($targetAsInt) < 0) { // @phpstan-ignore-line
            $expiry = (int)floor(microtime(true) * 1000) + $ticketTtl;
            $signature = hash_hmac('sha256', "{$clientIp}:{$expiry}", self::getPowSecret());
            return "{$expiry}:{$signature}";
        }

        error_log('[FP Server Verify] CPU PoW verification FAILED.');
        return null;
    }

    /**
     * Régénère un ticket avec un nouveau TTL sans re-vérifier le PoW.
     * Utile pour appliquer un TTL probatoire après une vérification réussie.
     * @param string|null $validTicket Le ticket original déjà validé.
     * @param string $clientIp L'IP du client.
     * @param int $newTtlMs Le nouveau TTL en millisecondes.
     * @return string|null Le nouveau ticket.
     */
    public static function regenerateTicketWithTtl(?string $validTicket, string $clientIp, int $newTtlMs): ?string
    {
        if ($validTicket === null) {
            return null;
        }
        $newExpiry = (int)floor(microtime(true) * 1000) + $newTtlMs;
        $newSignature = hash_hmac('sha256', "{$clientIp}:{$newExpiry}", self::getPowSecret());
        return "{$newExpiry}:{$newSignature}";
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
        $solverPath = __DIR__ . '/../../../../../pow.solver.inline.js';
        if (!file_exists($solverPath)) {
            error_log("[ChallengeUtils] Erreur: Le fichier pow.solver.inline.js n'a pas été trouvé à l'emplacement attendu.");
            return '';
        }
        return file_get_contents($solverPath) ?: '';
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
        $target = $cpuChallengeDetails['target'];
        $path = $cpuChallengeDetails['path'];

        $solverCode = self::getPowSolverCode();
        $baseBlock = self::createCpuChallengeBaseBlock($nonce, $clientSecret, $originalFingerprint);
        $baseBlockBytes = '[' . implode(',', array_values(unpack('C*', $baseBlock))) . ']';

        $trapLinksHtml = implode(' ', array_map(fn($url) => "<a href=\"{$url}\" tabindex=\"-1\">config</a>", $trapUrls));
        $trapContainerHtml = "<div style=\"position:absolute;left:-9999px;top:-9999px;\" aria-hidden=\"true\">{$trapLinksHtml}</div>";

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
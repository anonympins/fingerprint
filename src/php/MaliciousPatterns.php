<?php

declare(strict_types=1);

namespace Anonympins\Fingerprint\Utils;

/**
 * Fournit des fonctions pour détecter les patterns d'injection malveillants.
 */
class MaliciousPatterns
{
    /**
     * @var array<string, string> Map des patterns malveillants regroupés par type.
     */
    private const INJECTION_PATTERNS = [
        // SQL/NoSQL injections, including time-based attacks
        'sql' => '/(\$ne|\' *OR *\'1\'=\'1|[\'";]\s*--|; ?(DROP|TRUNCATE|DELETE)|UNION SELECT|SLEEP\(|BENCHMARK\(|WAITFOR DELAY)/i',
        // Log4Shell (JNDI injection)
        'log4shell' => '/\$\{jndi:(ldap|rmi|dns):/i',
        // Server-Side Template Injection (SSTI) for engines like Jinja2, Twig, etc.
        'ssti' => '/\{\{.*\}\}|\{%.*%\}/',
        // XML External Entity (XXE) injection
        'xxe' => '/<!ENTITY\s+.*SYSTEM/i',
        // Path Traversal
        'traversal' => '/(\.\.\/|\.\.\\)/',
        // Remote Command Execution (RCE)
        'rce' => '/`.*`|(^|[\n;&|]\s*)(ping|ls|whoami|cat|rm|ncat|nc|bash|sh|powershell|cmd)\b/i',
    ];

    /**
     * Vérifie si une chaîne de caractères contient des patterns d'injection connus.
     * @param string $str La chaîne à vérifier.
     * @param array<string> $typesToDetect Les types d'injections à détecter (par défaut, tous).
     * @return bool True si un pattern malveillant est détecté, false sinon.
     */
    public static function isMalicious(string $str, array $typesToDetect = []): bool
    {
        if (empty($typesToDetect)) {
            $typesToDetect = array_keys(self::INJECTION_PATTERNS);
        }

        foreach ($typesToDetect as $type) {
            if (isset(self::INJECTION_PATTERNS[$type])) {
                if (preg_match(self::INJECTION_PATTERNS[$type], $str)) {
                    return true;
                }
            }
        }

        return false;
    }
}
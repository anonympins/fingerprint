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
        'sql' => '/(\$ne|\' *OR *\'1\'=\'1|[\'";]\s*--|; ?(DROP|TRUNCATE|DELETE)|UNION SELECT|(?:SLEEP|BENCHMARK)\s*\(|WAITFOR DELAY)/i',
        // Log4Shell (JNDI injection)
        'log4shell' => '/\$\{jndi:(ldap|rmi|dns):/i',
        // Server-Side Template Injection (SSTI) for engines like Jinja2, Twig, etc.
        'ssti' => '/\{\{.*\}\}|\{%.*%\}/',
        // XML External Entity (XXE) injection
        'xxe' => '/<!ENTITY\s+.*SYSTEM/i',
        // Path Traversal
        'traversal' => '/(\.\.\/|\.\.)/',
        // Remote Command Execution (RCE)
        // The original regex had an issue with `|cmd` being interpreted as a modifier in some PCRE versions.
        // Using a non-capturing group (?:...) makes it more robust and fixes the compilation error.
        'rce' => '/`.*`|(?:^|[\n;&|]\s*)(?:ping|ls|whoami|cat|rm|ncat|nc|bash|sh|powershell|cmd)\b/i',
            // Server-Side Request Forgery (SSRF)
            'ssrf' => '/(?:https?:\/\/)?(?:127\.\d+\.\d+\.\d+|169\.254\.169\.254|10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+|localhost|0\.0\.0\.0|\[[0:]+1\])\b/i',
            // Carriage Return Line Feed (CRLF) Injection
            'crlf' => '/[\r\n]|%0[ad]/i',
            // Cross-Site Scripting (XSS)
            'xss' => '/(<script|javascript:|on\w+\s*=|alert\s*\(|confirm\s*\(|prompt\s*\(|<img\s+src[^>]+onerror|<iframe)/i',
            // Open Redirect
            'openRedirect' => '/^(https?:)?\/\/(?![^\/]*?(localhost|127\.0\.0\.1))[^\s\/]+/i',
            // Local/Remote File Inclusion (LFI/RFI)
            'lfi' => '/(?:etc\/passwd|win\.ini|boot\.ini|php:\/\/filter|data:\/\/|zip:\/\/)/i',
            // Shellshock (CVE-2014-6271)
            'shellshock' => '/\(\)\s*\{\s*:\s*;\s*\}\s*/i',
            // NoSQL Injection (MongoDB query operators)
            'nosql' => '/\$(?:eq|ne|gt|gte|lt|lte|in|nin|and|or|nor|not|expr|jsonSchema|mod|regex|text|where|elemMatch)/i',
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
            $typesToDetect = array_filter(array_keys(self::INJECTION_PATTERNS), function ($key) {
                return $key !== 'openRedirect';
            });
        }

        foreach ($typesToDetect as $type) {
            if (isset(self::INJECTION_PATTERNS[$type])) {
               try {
                   if (preg_match(self::INJECTION_PATTERNS[$type], $str)) {
                       return true;
                   }
               }catch (\Exception $e){
                   error_log($type);
                   error_log($e->getMessage());
                }
            }
        }

        return false;
    }
}
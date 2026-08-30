<?php

declare(strict_types=1);

namespace Anonympins\Fingerprint\Tests;

use PHPUnit\Framework\TestCase;
use Anonympins\Fingerprint\FingerprintEngine;
use Anonympins\Fingerprint\RequestContext;
use Anonympins\Fingerprint\Store\StoreManager;
use Anonympins\Fingerprint\Store\InMemoryStore;
use Anonympins\Fingerprint\Config\SecurityProfiles;

class FingerprintEngineTest extends TestCase
{
    private FingerprintEngine $engine;
    private array $securityConfig;

    /**
     * Cette méthode est appelée avant chaque test.
     * Elle garantit que chaque test s'exécute dans un environnement propre.
     */
    protected function setUp(): void
    {
        // 1. Utiliser un store en mémoire propre pour chaque test
        $store = new InMemoryStore();
        StoreManager::configureStore($store);

        // 2. Charger une configuration de sécurité de base pour les tests
        $this->securityConfig = SecurityProfiles::createSecurityProfile('balanced', [
            'verbose' => false, // Désactiver les logs pour ne pas polluer la sortie des tests
            'challengeNewDevices' => false, // Simplifie les tests de base
        ]);

        // 3. Créer une nouvelle instance du moteur pour chaque test
        $this->engine = new FingerprintEngine($this->securityConfig);
    }

    /**
     * Crée un contexte de requête de base pour les tests.
     *
     * @param array<string, mixed> $overrides
     * @return RequestContext
     */
    private function createRequestContext(array $overrides = []): RequestContext
    {
        $defaults = [
            'clientIp' => '192.168.1.10',
            'path' => '/',
            'headers' => [
                'user-agent' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36',
                'accept-language' => 'en-US,en;q=0.9',
            ],
            'query' => [],
            'body' => null,
            'cookies' => [],
            'httpVersion' => '1.1',
        ];

        $params = array_merge($defaults, $overrides);

        return new RequestContext(
            $params['clientIp'],
            $params['path'],
            $params['headers'],
            $params['query'],
            $params['body'],
            $params['cookies'],
            $params['httpVersion']
        );
    }

    public function testAllowsLegitimateRequest(): void
    {
        $context = $this->createRequestContext();

        // Simule une première visite
        $firstDecision = $this->engine->processRequest($context);
        $this->assertArrayHasKey('newCookieForResponse', $firstDecision, "Un nouveau cookie aurait dû être généré.");
        $deviceIdCookie = $firstDecision['newCookieForResponse'];

        // Simule une deuxième visite avec le cookie reçu
        $nextContext = $this->createRequestContext([
            'cookies' => [$deviceIdCookie['name'] => $deviceIdCookie['value']]
        ]);
        $secondDecision = $this->engine->processRequest($nextContext);

        $this->assertEquals('next', $secondDecision['action']);
        $this->assertLessThan($this->securityConfig['thresholds']['low'], $secondDecision['score']);
    }

    public function testIssuesChallengeForSuspiciousRequest(): void
    {
        // 1. First, establish a device identity to avoid the cookie-dropping penalty
        $firstContext = $this->createRequestContext();
        $firstDecision = $this->engine->processRequest($firstContext);
        $this->assertArrayHasKey('newCookieForResponse', $firstDecision, "A device ID cookie should have been generated.");
        $deviceIdCookie = $firstDecision['newCookieForResponse'];

        // 2. Now, simulate a suspicious request from that same device (e.g., missing user-agent)
        $suspiciousContext = $this->createRequestContext([
            'cookies' => [$deviceIdCookie['name'] => $deviceIdCookie['value']],
            'headers' => [
                // No user-agent, which is anomalous
                'accept-language' => 'en-US,en;q=0.9',
            ]
        ]);

        $decision = $this->engine->processRequest($suspiciousContext);

        $this->assertEquals('challenge', $decision['action'], "The action should be to issue a challenge.");
        $this->assertGreaterThanOrEqual($this->securityConfig['thresholds']['low'], $decision['score'], "The score should be above the 'low' threshold.");
        $this->assertLessThan($this->securityConfig['thresholds']['block'], $decision['score']);
    }

    public function testBlocksHighlySuspiciousRequest(): void
    {
        // Configure the engine to recognize the 'email_confirm' honeypot field.
        // We need to create a new engine instance for this test with a custom config.
        $config = SecurityProfiles::createSecurityProfile('balanced', [
            'honeypot' => ['fields' => ['email_confirm']],
            'verbose' => true,
            'weights'=> ['honeypotScore' => 1]
        ]);
        $engine = new FingerprintEngine($config);

        // 1. First, establish a device identity to avoid other scores interfering.
        $firstContext = $this->createRequestContext();
        $firstDecision = $engine->processRequest($firstContext);
        $this->assertArrayHasKey('newCookieForResponse', $firstDecision);
        $deviceIdCookie = $firstDecision['newCookieForResponse'];

        // 2. Now, simulate a request from that device that falls into a honeypot trap.
        $honeypotContext = $this->createRequestContext([
            'cookies' => [$deviceIdCookie['name'] => $deviceIdCookie['value']],
            // The bot filled in a hidden field, triggering the honeypot.
            'body' => ['email_confirm' => 'bot@example.com']
        ]);

        $decision = $engine->processRequest($honeypotContext);

        $this->assertEquals('block', $decision['action']);
        $this->assertGreaterThanOrEqual($config['thresholds']['block'], $decision['score']);
    }

    public function testDetectsCookieDropping(): void
    {
        $context = $this->createRequestContext(['clientIp' => '1.2.3.4']);

        // 1. Première requête, un "pending_cookie" est défini pour cette IP
        $this->engine->processRequest($context);

        // 2. Deuxième requête de la même IP, mais sans le cookie attendu
        $contextWithoutCookie = $this->createRequestContext(['clientIp' => '1.2.3.4']);
        $decision = $this->engine->processRequest($contextWithoutCookie);

        // Le score de "cookieDropping" devrait être de 100
        $this->assertEquals(100, $decision['vector']['cookieDroppingScore']);
        // L'action devrait être un challenge car le score final sera élevé
        $this->assertEquals('challenge', $decision['action']);
    }

    public function testDetectsFingerprintInconsistency(): void
    {
        $context = $this->createRequestContext();

        // 1. Première visite, le fingerprint initial est stocké
        $firstDecision = $this->engine->processRequest($context);
        $deviceIdCookie = $firstDecision['newCookieForResponse'];

        // 2. Deuxième visite avec le même cookie, mais un User-Agent complètement différent (incohérence)
        $nextContext = $this->createRequestContext([
            'cookies' => [$deviceIdCookie['name'] => $deviceIdCookie['value']],
            'headers' => [
                'user-agent' => 'DefinitelyNotTheSameBrowser/1.0',
                'accept-language' => 'fr-FR',
            ]
        ]);

        $decision = $this->engine->processRequest($nextContext);

        // Le score d'incohérence devrait être de 100
        $this->assertEquals(100, $decision['vector']['inconsistencyScore']);
        // L'action devrait être un challenge ou un blocage
        $this->assertContains($decision['action'], ['challenge', 'block']);
    }

    public function testAllowsWhitelistedIp(): void
    {
        $config = SecurityProfiles::createSecurityProfile('strict', [
            'whitelist' => [['type' => 'allowlist', 'entries' => ['10.0.0.1']]]
        ]);
        $engine = new FingerprintEngine($config);

        $context = $this->createRequestContext(['clientIp' => '10.0.0.1']);
        $decision = $engine->processRequest($context);

        $this->assertEquals('next', $decision['action']);
        $this->assertEquals(0, $decision['score']);
    }
}
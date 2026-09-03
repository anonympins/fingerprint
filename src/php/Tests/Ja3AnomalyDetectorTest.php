<?php

declare(strict_types=1);

namespace Anonympins\Fingerprint\Tests;

use PHPUnit\Framework\TestCase;
use Anonympins\Fingerprint\Ja3AnomalyDetector;

/**
 * Tests unitaires pour la classe Ja3AnomalyDetector.
 */
class Ja3AnomalyDetectorTest extends TestCase
{
    /**
     * Teste le parsing d'une chaîne JA3 brute valide.
     */
    public function testParseJa3ValidString(): void
    {
        $ja3 = '771,4865-4866-4867,0-23-65281-10-11,29-23-24,0';
        $parsed = Ja3AnomalyDetector::parseJa3($ja3);

        $this->assertNotNull($parsed);
        $this->assertSame(771, $parsed['tlsVersion']);
        $this->assertSame([4865, 4866, 4867], $parsed['ciphers']);
        $this->assertSame([0, 23, 65281, 10, 11], $parsed['extensions']);
        $this->assertSame([29, 23, 24], $parsed['curves']);
        $this->assertSame([0], $parsed['points']);
    }

    /**
     * Teste le parsing avec des valeurs manquantes ou malformées.
     */
    public function testParseJa3InvalidString(): void
    {
        $this->assertNull(Ja3AnomalyDetector::parseJa3(''));
        $this->assertNull(Ja3AnomalyDetector::parseJa3('771,4865,0-23')); // Moins de 5 parties
    }

    /**
     * Teste la détection du mécanisme GREASE.
     */
    public function testHasGrease(): void
    {
        // Contient la valeur GREASE 2570 (0x0A0A)
        $this->assertTrue(Ja3AnomalyDetector::hasGrease([4865, 2570, 4866]));
        // Ne contient pas de valeur GREASE
        $this->assertFalse(Ja3AnomalyDetector::hasGrease([4865, 4866, 4867]));
    }

    /**
     * Teste l'extraction de la famille du User-Agent.
     */
    public function testGetBrowserFamily(): void
    {
        $this->assertSame('Chrome', Ja3AnomalyDetector::getBrowserFamily('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'));
        $this->assertSame('Edge', Ja3AnomalyDetector::getBrowserFamily('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0'));
        $this->assertSame('Firefox', Ja3AnomalyDetector::getBrowserFamily('Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0'));
        $this->assertSame('Safari', Ja3AnomalyDetector::getBrowserFamily('Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15'));
        $this->assertNull(Ja3AnomalyDetector::getBrowserFamily('curl/7.68.0'));
    }

    /**
     * Teste la détection d'usurpation d'une bibliothèque connue (ex: Python/Go/curl).
     */
    public function testSpoofingLibraryDetected(): void
    {
        $pythonJa3 = '47344a349b75c4e82333475553b5f358'; // Signature Python dans DB
        $userAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36';

        $score = Ja3AnomalyDetector::getJa3AnomalyScore($pythonJa3, null, $userAgent, 'HTTP/2');

        // Devrait retourner un score élevé (90) car une signature python se fait passer pour Chrome
        $this->assertEquals(90, $score);
    }

    /**
     * Teste la détection d'une incohérence de navigateur (ex: signature Firefox avec UA Chrome).
     */
    public function testBrowserMismatchDetected(): void
    {
        $firefoxJa3 = 'b386946a5a586163c7c533636b45c355'; // Signature Firefox dans DB
        $userAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36';

        $score = Ja3AnomalyDetector::getJa3AnomalyScore($firefoxJa3, null, $userAgent, 'HTTP/2');

        $this->assertEquals(80, $score);
    }

    /**
     * Teste la détection de stagnation de hash avec rotation d'User-Agents.
     */
    public function testStagnationWithRotatingUserAgents(): void
    {
        // Mock d'un stockage de cache minimal en mémoire
        $cache = new class {
            private array $store = [];
            public function get(string $key): ?string { return $this->store[$key] ?? null; }
            public function set(string $key, string $val, int $ttl = 0): void { $this->store[$key] = $val; }
            public function setex(string $key, int $ttl, string $val): void { $this->store[$key] = $val; }
        };

        $unknownJa3 = '00000000000000000000000000000000';
        $chromeUA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0';
        $firefoxUA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Firefox/120.0';

        // Premier appel avec Chrome -> pas d'anomalie de stagnation encore
        $score1 = Ja3AnomalyDetector::getJa3AnomalyScore($unknownJa3, null, $chromeUA, 'HTTP/2', $cache);
        $this->assertLessThan(85, $score1);

        // Deuxième appel avec la même stack TLS mais un UA Firefox -> Détection de rotation !
        $score2 = Ja3AnomalyDetector::getJa3AnomalyScore($unknownJa3, null, $firefoxUA, 'HTTP/2', $cache);
        $this->assertEquals(85, $score2);
    }

    /**
     * Teste l'absence de valeurs GREASE pour un navigateur Chromium.
     */
    public function testMissingGreaseForChrome(): void
    {
        $chromeUA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0';
        // JA3 brut valide mais sans AUCUNE valeur GREASE dans les extensions ou les ciphers
        $ja3RawWithoutGrease = '771,4865-4866,0-23-10,29,0';

        $score = Ja3AnomalyDetector::getJa3AnomalyScore(null, $ja3RawWithoutGrease, $chromeUA, 'HTTP/2');
        $this->assertEquals(75, $score);
    }

    /**
     * Teste le cas légitime d'un navigateur Chromium disposant de GREASE.
     */
    public function testLegitimateChromeWithGrease(): void
    {
        $chromeUA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0';
        // 2570 est une valeur GREASE valide
        $ja3RawWithGrease = '771,4865-2570,0-23-10,29,0';

        $score = Ja3AnomalyDetector::getJa3AnomalyScore(null, $ja3RawWithGrease, $chromeUA, 'HTTP/2');
        $this->assertLessThan(75, $score);
    }

    /**
     * Teste la détection d'absence d'ALPN lors de connexions HTTP/2.
     */
    public function testHttp2WithoutAlpnExtension(): void
    {
        $chromeUA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0';
        // Pas d'extension 16 (ALPN) dans les extensions
        $ja3RawNoAlpn = '771,4865-2570,0-23-10,29,0';

        $score = Ja3AnomalyDetector::getJa3AnomalyScore(null, $ja3RawNoAlpn, $chromeUA, 'HTTP/2');
        $this->assertEquals(70, $score);
    }

    /**
     * Teste la présence d'ALPN lors de connexions HTTP/2 (cas normal).
     */
    public function testHttp2WithAlpnExtension(): void
    {
        $chromeUA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0';
        // L'extension 16 est présente
        $ja3RawWithAlpn = '771,4865-2570,0-23-10-16,29,0';

        $score = Ja3AnomalyDetector::getJa3AnomalyScore(null, $ja3RawWithAlpn, $chromeUA, 'HTTP/2');
        $this->assertLessThan(70, $score);
    }

    /**
     * Teste l'utilisation d'une version obsolète de TLS par un navigateur récent.
     */
    public function testObsoleteTlsVersionWithModernBrowser(): void
    {
        $chromeUA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0';
        // Version TLS 769 (TLS 1.0) initiée par un Chrome récent
        $obsoleteTlsJa3 = '769,4865-2570,0-23-10-16,29,0';

        $score = Ja3AnomalyDetector::getJa3AnomalyScore(null, $obsoleteTlsJa3, $chromeUA, 'HTTP/2');
        $this->assertEquals(80, $score);
    }
}
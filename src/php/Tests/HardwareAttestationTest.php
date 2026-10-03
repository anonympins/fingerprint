<?php

declare(strict_types=1);

namespace Anonympins\Fingerprint\Tests;

use Anonympins\Fingerprint\HardwareAttestation;
use Anonympins\Fingerprint\RequestContext;
use Anonympins\Fingerprint\Store\InMemoryStore;
use Anonympins\Fingerprint\Store\StoreManager;
use PHPUnit\Framework\TestCase;

class HardwareAttestationTest extends TestCase
{
    private InMemoryStore $store;

    // Clé arbitraire / mockée (aucun besoin de courbe réelle dans les tests mockés)
    private const MOCK_PUB_KEY = "MOCK_PUBLIC_KEY_PEM";
    private const MOCK_JWK = [
        'kty' => 'EC',
        'crv' => 'P-256',
        'x'   => 'mock_x_coordinate_12345678901234567890',
        'y'   => 'mock_y_coordinate_12345678901234567890'
    ];

    protected function setUp(): void
    {
        parent::setUp();
        $this->store = new InMemoryStore();
        StoreManager::configureStore($this->store);

        // Active le mock de signature par défaut pour accepter n'importe quelle clé
        // et rejeter uniquement si la signature vaut explicitement 'invalid_sig' ou 'fakesig'
        HardwareAttestation::setSignatureVerifier(function (string $data, string $signature, $key): bool {
            if ($signature === 'invalid_sig' || $signature === 'fakesig') {
                return false;
            }
            return true;
        });
    }

    protected function tearDown(): void
    {
        HardwareAttestation::setSignatureVerifier(null);
        parent::tearDown();
    }

    private function base64UrlEncode(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    public function testAppleAppAttestValidAssertionIncrementsCounter(): void
    {
        $storedCounter = 10;
        $newCounter = 11;

        // AuthData Apple (37 octets) : 32 octets rpIdHash + 1 octet flags + 4 octets counter big-endian
        $rpIdHash = str_repeat("\xAA", 32);
        $flags = "\x01";
        $counterBytes = pack('N', $newCounter);
        $authData = $rpIdHash . $flags . $counterBytes;

        $clientDataHash = hash('sha256', 'session_id:192.168.1.10', true);
        $dummySignature = 'valid_mock_signature_bytes_64';
        $assertionRaw = $authData . $dummySignature;

        $result = HardwareAttestation::verifyAppleAppAttestAssertion(
            self::MOCK_PUB_KEY,
            $assertionRaw,
            $clientDataHash,
            $storedCounter
        );

        $this->assertTrue($result['isValid'], 'L\'assertion signée par la clé Secure Enclave doit être valide.');
        $this->assertEquals($newCounter, $result['newCounter'], 'Le compteur doit être mis à jour à la nouvelle valeur.');
    }

    public function testAppleAppAttestRejectsReplayedOrDecrementedCounter(): void
    {
        $storedCounter = 15;
        $staleCounter = 15; // Tentative de rejeu du même compteur

        $authData = str_repeat("\xAA", 32) . "\x01" . pack('N', $staleCounter);
        $clientDataHash = hash('sha256', 'session_id:127.0.0.1', true);

        $result = HardwareAttestation::verifyAppleAppAttestAssertion(
            self::MOCK_PUB_KEY,
            $authData . 'valid_mock_signature',
            $clientDataHash,
            $storedCounter
        );

        $this->assertFalse($result['isValid'], 'Une assertion avec un compteur non strictement supérieur doit être rejetée.');
        $this->assertEquals($storedCounter, $result['newCounter']);
    }

    public function testGooglePlayIntegrityValidJwsVerification(): void
    {
        $header = ['alg' => 'ES256', 'x5c' => ['mock_cert_base64']];
        $expectedNonce = 'anti-replay-nonce-xyz';
        $pkgName = 'com.anonympins.app';

        $payload = [
            'requestDetails' => [
                'nonce' => $expectedNonce,
                'timestampMillis' => (string)(int)(microtime(true) * 1000)
            ],
            'appIntegrity' => [
                'packageName' => $pkgName
            ],
            'deviceIntegrity' => [
                'deviceRecognitionVerdict' => ['MEETS_STRONG_INTEGRITY', 'MEETS_DEVICE_INTEGRITY']
            ]
        ];

        $encodedHeader = $this->base64UrlEncode(json_encode($header));
        $encodedPayload = $this->base64UrlEncode(json_encode($payload));
        $signingInput = "{$encodedHeader}.{$encodedPayload}";
        $jwsToken = "{$signingInput}." . $this->base64UrlEncode('mock_valid_signature');

        $verdict = HardwareAttestation::verifyPlayIntegrityJws(
            $jwsToken,
            $pkgName,
            $expectedNonce
        );

        $this->assertTrue($verdict['isValid'], 'Le jeton Play Integrity signé avec intégrité matérielle doit être accepté.');
        $this->assertEquals($pkgName, $verdict['payload']['appIntegrity']['packageName']);
    }

    public function testGooglePlayIntegrityRejectsTamperedPackageOrStaleNonce(): void
    {
        $header = ['alg' => 'ES256'];
        $payload = [
            'requestDetails' => ['nonce' => 'expected-nonce', 'timestampMillis' => (string)(int)(microtime(true) * 1000)],
            'appIntegrity' => ['packageName' => 'com.fraudulent.repack'],
            'deviceIntegrity' => ['deviceRecognitionVerdict' => ['MEETS_STRONG_INTEGRITY']]
        ];

        $jws = $this->base64UrlEncode(json_encode($header)) . '.' . $this->base64UrlEncode(json_encode($payload)) . '.fakesig';

        $resMismatchPkg = HardwareAttestation::verifyPlayIntegrityJws($jws, 'com.anonympins.app', 'expected-nonce');
        $this->assertFalse($resMismatchPkg['isValid'], 'Un nom de package inattendu doit invalider l\'attestation.');

        $resMismatchNonce = HardwareAttestation::verifyPlayIntegrityJws($jws, 'com.fraudulent.repack', 'different-nonce');
        $this->assertFalse($resMismatchNonce['isValid'], 'Un nonce expiré ou rejoué doit être rejeté.');
    }

    public function testDbscProofVerificationSuccess(): void
    {
        $sessionId = 'device_session_456';
        $origin = 'https://example.com';
        $nonce = 'dbsc_challenge_nonce_789';

        $header = ['typ' => 'dbsc+jwt', 'alg' => 'ES256'];
        $payload = [
            'sub'   => $sessionId,
            'aud'   => $origin,
            'nonce' => $nonce,
            'iat'   => time(),
            'exp'   => time() + 300
        ];

        $encodedHeader = $this->base64UrlEncode(json_encode($header));
        $encodedPayload = $this->base64UrlEncode(json_encode($payload));
        $signingInput = "{$encodedHeader}.{$encodedPayload}";
        $dbscJwt = "{$signingInput}." . $this->base64UrlEncode('mock_dbsc_signature');

        $isValid = HardwareAttestation::verifyDbscProof(
            $dbscJwt,
            self::MOCK_JWK,
            $sessionId,
            $origin,
            $nonce
        );

        $this->assertTrue($isValid, 'La preuve de possession matérielle DBSC doit être validée.');
    }

    public function testDbscProofFailsOnStolenCookieOrSessionMismatch(): void
    {
        $sessionId = 'victim_session_id';
        $stolenSessionAttempt = 'attacker_session_id';

        $header = ['typ' => 'dbsc+jwt', 'alg' => 'ES256'];
        $payload = [
            'sub'   => $sessionId, // Session liée à la clé matérielle
            'aud'   => 'https://example.com',
            'nonce' => 'valid-nonce',
            'exp'   => time() + 300
        ];

        $signingInput = $this->base64UrlEncode(json_encode($header)) . '.' . $this->base64UrlEncode(json_encode($payload));
        $dbscJwt = "{$signingInput}." . $this->base64UrlEncode('mock_signature');

        $isValid = HardwareAttestation::verifyDbscProof(
            $dbscJwt,
            self::MOCK_JWK,
            $stolenSessionAttempt,
            'https://example.com',
            'valid-nonce'
        );

        $this->assertFalse($isValid, 'L\'attaquant ne peut pas utiliser la session sans la clé matérielle associée au sub.');
    }

    public function testProcessOrchestratesDbscBypass(): void
    {
        $sessionId = 'active_dbsc_session';
        $origin = 'https://example.com';
        $nonce = 'test_nonce_abc';

        // Enregistrement de la session matérielle dans le Store
        $this->store->set("dbsc-session:{$sessionId}", ['jwk' => self::MOCK_JWK]);
        $this->store->set("dbsc-nonce:{$sessionId}", $nonce);

        $header = ['typ' => 'dbsc+jwt', 'alg' => 'ES256'];
        $payload = [
            'sub'   => $sessionId,
            'aud'   => $origin,
            'nonce' => $nonce,
            'exp'   => time() + 300
        ];
        $signingInput = $this->base64UrlEncode(json_encode($header)) . '.' . $this->base64UrlEncode(json_encode($payload));
        $dbscJwt = "{$signingInput}." . $this->base64UrlEncode('mock_signature');

        $context = new RequestContext(
            '127.0.0.1',
            '/',
            [
                'sec-session-response' => $dbscJwt,
                'origin' => $origin
            ],
            [],
            null,
            ['device_id' => $sessionId],
            '1.1'
        );

        $res = HardwareAttestation::process($context, $sessionId, $this->store);

        $this->assertTrue($res['verified'], 'Le processus central doit valider l\'attestation matérielle DBSC.');
        $this->assertEquals('dbsc_tpm', $res['type']);
        $this->assertNull($this->store->get("dbsc-nonce:{$sessionId}"), 'Le nonce à usage unique doit être purgé.');
    }

    public function testProcessReturnsUnverifiedWhenNoAttestationPresent(): void
    {
        $context = new RequestContext(
            '127.0.0.1',
            '/',
            ['user-agent' => 'StandardBrowser/1.0'],
            [],
            null,
            [],
            '1.1'
        );

        $res = HardwareAttestation::process($context, 'sess_none', $this->store);

        $this->assertFalse($res['verified']);
        $this->assertEquals('none', $res['type']);
    }
}
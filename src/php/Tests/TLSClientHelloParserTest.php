<?php

declare(strict_types=1);

namespace Anonympins\Fingerprint\Tests;

use Anonympins\Fingerprint\Utils\TLSClientHelloParser;
use PHPUnit\Framework\TestCase;

/**
 * Tests unitaires pour le décodeur binaire TLS Client Hello.
 */
class TLSClientHelloParserTest extends TestCase
{
    /**
     * Helper pour construire un paquet TLS Client Hello binaire valide et réaliste.
     *
     * @param int $sslVersion Version TLS (ex: 0x0303 pour TLS 1.2)
     * @param array<int> $ciphers Liste des Cipher Suites
     * @param array<array{type: int, data: string}> $extensions Liste des extensions
     * @return string Paquet binaire brut
     */
    private function buildMockClientHello(int $sslVersion = 0x0303, array $ciphers = [4865, 2570], array $extensions = []): string
    {
        $recordType = pack('C', 0x16); // Handshake Record (22)
        $recordVersion = pack('n', 0x0301); // TLS 1.0 record layer version
        $recordLength = pack('n', 120); // Dummy length

        $handshakeType = pack('C', 0x01); // Client Hello (1)
        $handshakeLength = pack('C3', 0, 0, 110); // Dummy length

        $clientVersion = pack('n', $sslVersion);
        $random = str_repeat("\x00", 32); // Random de 32 octets
        $sessionId = pack('C', 0x00); // Session ID vide (longueur 0)

        // Construction des Cipher Suites
        $ciphersBinary = '';
        foreach ($ciphers as $cipher) {
            $ciphersBinary .= pack('n', $cipher);
        }
        $ciphersPayload = pack('n', strlen($ciphersBinary)) . $ciphersBinary;

        // Compression Methods (Standard: 1 méthode, valeur 0x00 = null)
        $compression = pack('C2', 1, 0);

        // Construction des Extensions
        $extensionsBinary = '';
        foreach ($extensions as $ext) {
            $extensionsBinary .= pack('n', $ext['type']) . pack('n', strlen($ext['data'])) . $ext['data'];
        }
        $extensionsPayload = pack('n', strlen($extensionsBinary)) . $extensionsBinary;

        return $recordType . $recordVersion . $recordLength . $handshakeType . $handshakeLength . $clientVersion . $random . $sessionId . $ciphersPayload . $compression . $extensionsPayload;
    }

    public function testParseValidClientHelloWithGreaseAndExtensions(): void
    {
        // On injecte l'extension 10 (Supported Groups / Curves)
        // Data: 4 octets de longueur de liste + 29 (X25519) + 2570 (GREASE)
        $extCurves = [
            'type' => 10,
            'data' => pack('n', 4) . pack('n2', 29, 2570)
        ];

        // On injecte l'extension 11 (EC Point Formats)
        // Data: 1 octet de longueur de liste + 0 (uncompressed)
        $extPoints = [
            'type' => 11,
            'data' => pack('C2', 1, 0)
        ];

        // On build le paquet binaire de test
        $binary = $this->buildMockClientHello(
            0x0303, // SSL Version: 771 (TLS 1.2)
            [4865, 2570], // Ciphers (2570 est une valeur GREASE)
            [$extCurves, $extPoints]
        );

        $result = TLSClientHelloParser::parse($binary);

        $this->assertNotNull($result);
        
        // Vérifications des filtrages GREASE et de la construction de la chaîne JA3
        // Chaîne JA3 attendue: "Version,Ciphers,Extensions,Curves,Points"
        // - Version: 771
        // - Ciphers: 4865 (2570 a été nettoyé car GREASE)
        // - Extensions: 10-11
        // - Curves: 29 (2570 a été nettoyé car GREASE)
        // - Points: 0
        $expectedJa3String = '771,4865,10-11,29,0';
        $this->assertSame($expectedJa3String, $result['ja3_string']);
        $this->assertSame(md5($expectedJa3String), $result['ja3_hash']);
    }

        public function testParseValidClientHelloWithJa4(): void
        {
            // On injecte l'extension 0 (SNI) avec données vides
            $extSni = [
                'type' => 0,
                'data' => pack('n', 0)
            ];

            // On injecte l'extension 16 (ALPN)
            // Data: list len (3) + str len (2) + "h2"
            $extAlpn = [
                'type' => 16,
                'data' => pack('n', 3) . pack('C', 2) . 'h2'
            ];

            // On injecte l'extension 13 (Signature Algorithms)
            // Data: list len (4) + 2 sig algs (0x0401, 0x0804)
            $extSigAlgs = [
                'type' => 13,
                'data' => pack('n', 4) . pack('n2', 0x0401, 0x0804)
            ];

            // On injecte l'extension 43 (Supported Versions) pour forcer la version TLS 1.3 (0x0304)
            // Data: list len (4) + 2 versions (0x0304, 0x0303)
            $extSupportedVersions = [
                'type' => 43,
                'data' => pack('C', 4) . pack('n2', 0x0304, 0x0303)
            ];

            // On build le paquet binaire de test
            $binary = $this->buildMockClientHello(
                0x0303, // Version de base
                [4865, 2570], // Ciphers (2570 est GREASE, sera ignoré dans les comptes)
                [$extSni, $extAlpn, $extSigAlgs, $extSupportedVersions]
            );

            $result = TLSClientHelloParser::parse($binary);

            $this->assertNotNull($result);
            $this->assertArrayHasKey('ja4_raw', $result);

            // Version la plus haute: 0x0304 -> "13"
            // SNI présent: "d"
            // Nombre de ciphers (hors GREASE): 4865 (0x1301) -> 1 -> "01"
            // Nombre d'extensions (hors GREASE): 0, 13, 16, 43 -> 4 -> "04"
            // ALPN: "h2"
            // Partie A attendue: "t13d0104h2"
            $this->assertStringStartsWith('t13d0104h2', $result['ja4_raw']);

            // Partie B: hash sha256 de "1301" haché en hexadécimal et tronqué à 12 caractères
            $expectedJa4b = substr(hash('sha256', '1301'), 0, 12);
            $this->assertStringContainsString($expectedJa4b, $result['ja4_raw']);

            // Partie C: extensions triées et hachées: "0000,000d,0010,002b_0401,0804"
            $extensionsString = '0000,000d,0010,002b';
            $sigAlgsString = '0401,0804';
            $expectedJa4c = substr(hash('sha256', $extensionsString . '_' . $sigAlgsString), 0, 12);
            $this->assertStringEndsWith($expectedJa4c, $result['ja4_raw']);
        }

    public function testParseReturnsNullWhenPacketTooShort(): void
    {
        $shortBinary = str_repeat("\x16", 40);
        $this->assertNull(TLSClientHelloParser::parse($shortBinary));
    }

    public function testParseReturnsNullOnInvalidRecordType(): void
    {
        // 0x17 au lieu de 0x16 (Application data au lieu de Handshake)
        $invalidRecord = $this->buildMockClientHello();
        $invalidRecord[0] = chr(0x17);

        $this->assertNull(TLSClientHelloParser::parse($invalidRecord));
    }

    public function testParseReturnsNullOnInvalidHandshakeType(): void
    {
        // 0x02 au lieu de 0x01 (Server Hello au lieu de Client Hello)
        $invalidHandshake = $this->buildMockClientHello();
        $invalidHandshake[5] = chr(0x02);

        $this->assertNull(TLSClientHelloParser::parse($invalidHandshake));
    }
}
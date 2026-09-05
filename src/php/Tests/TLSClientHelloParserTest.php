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
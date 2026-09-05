<?php

declare(strict_types=1);

namespace Anonympins\Fingerprint\Utils;

/**
 * Décode nativement un paquet TLS Client Hello binaire pour calculer l'empreinte JA3/JA4.
 */
class TLSClientHelloParser
{
    private const GREASE_VALUES = [
        2570, 6682, 10794, 14906, 19018, 23130, 27242, 31354,
        35466, 39578, 43690, 47802, 51914, 55926, 60038, 64150
    ];

    /**
     * Parse le Client Hello brut et retourne l'empreinte JA3 et une approximation JA4.
     * 
     * @param string $binary Le premier paquet TCP reçu sur la socket.
     * @return array{ja3_string: string, ja3_hash: string, ja4_raw: string}|null
     */
    public static function parse(string $binary): ?array
    {
        $len = strlen($binary);
        if ($len < 43) {
            return null; // Paquet trop court
        }

        // 1. Vérification du Record Layer Type (0x16 = Handshake)
        if (ord($binary[0]) !== 0x16) {
            return null;
        }

        // 2. Vérification du Handshake Type (0x01 = Client Hello)
        if (ord($binary[5]) !== 0x01) {
            return null;
        }

        $offset = 43; // Sauter l'en-tête, la version et le Random Client (32 octets)
        if ($len < $offset + 1) return null;

        // 3. Lecture du Session ID
        $sessionLen = ord($binary[$offset]);
        $offset += 1 + $sessionLen;
        if ($len < $offset + 2) return null;

        // 4. Lecture des Cipher Suites
        $ciphersLen = unpack('n', substr($binary, $offset, 2))[1];
        $offset += 2;
        if ($len < $offset + $ciphersLen + 1) return null;

        $ciphers = [];
        for ($i = 0; $i < $ciphersLen; $i += 2) {
            $ciphers[] = unpack('n', substr($binary, $offset + $i, 2))[1];
        }
        $offset += $ciphersLen;

        // 5. Lecture des Compression Methods
        $compressionLen = ord($binary[$offset]);
        $offset += 1 + $compressionLen;
        if ($len < $offset + 2) return null;

        // 6. Lecture des Extensions
        $extensionsLen = unpack('n', substr($binary, $offset, 2))[1];
        $offset += 2;

        $extensions = [];
        $curves = [];
        $points = [];

        $extLimit = $offset + $extensionsLen;
        while ($offset < $extLimit && $offset + 4 <= $len) {
            $extType = unpack('n', substr($binary, $offset, 2))[1];
            $extLen = unpack('n', substr($binary, $offset + 2, 2))[1];
            $offset += 4;

            if ($offset + $extLen > $len) break;

            $extensions[] = $extType;

            if ($extType === 10) { // Extension Supported Groups (Elliptic Curves)
                if ($extLen >= 2) {
                    $curvesLen = unpack('n', substr($binary, $offset, 2))[1];
                    for ($j = 2; $j < $curvesLen + 2; $j += 2) {
                        $curves[] = unpack('n', substr($binary, $offset + $j, 2))[1];
                    }
                }
            } elseif ($extType === 11) { // Extension EC Point Formats
                if ($extLen >= 1) {
                    $pointsLen = ord($binary[$offset]);
                    for ($j = 1; $j < $pointsLen + 1; $j++) {
                        $points[] = ord($binary[$offset + $j]);
                    }
                }
            }
            $offset += $extLen;
        }

        // Nettoyage des valeurs GREASE (RFC 8701) pour la conformité JA3
        $filterGrease = fn(array $arr) => array_values(array_filter($arr, fn($v) => !in_array($v, self::GREASE_VALUES, true)));

        $sslVersion = unpack('n', substr($binary, 9, 2))[1];
        $ja3String = implode(',', [
            $sslVersion,
            implode('-', $filterGrease($ciphers)),
            implode('-', $filterGrease($extensions)),
            implode('-', $filterGrease($curves)),
            implode('-', $filterGrease($points))
        ]);

        return [
            'ja3_string' => $ja3String,
            'ja3_hash'   => md5($ja3String)
        ];
    }
}
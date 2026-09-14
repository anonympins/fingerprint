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
            $sigAlgs = [];
            $supportedVersions = [];
            $hasSni = false;
            $alpnProtocol = '';

        $extLimit = $offset + $extensionsLen;
        while ($offset < $extLimit && $offset + 4 <= $len) {
            $extType = unpack('n', substr($binary, $offset, 2))[1];
            $extLen = unpack('n', substr($binary, $offset + 2, 2))[1];
            $offset += 4;

            if ($offset + $extLen > $len) break;

            $extensions[] = $extType;

                if ($extType === 0) {
                    $hasSni = true;
                } elseif ($extType === 10) { // Extension Supported Groups (Elliptic Curves)
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
                } elseif ($extType === 13) { // Signature Algorithms
                    if ($extLen >= 2 && $offset + 2 <= $len) {
                        $sigAlgsLen = unpack('n', substr($binary, $offset, 2))[1];
                        for ($j = 2; $j < $sigAlgsLen + 2; $j += 2) {
                            if ($offset + $j + 2 <= $len && $j + 2 <= $extLen) {
                                $sigAlgs[] = unpack('n', substr($binary, $offset + $j, 2))[1];
                            }
                        }
                    }
                } elseif ($extType === 16) { // ALPN
                    if ($extLen >= 3 && $offset + 2 <= $len) {
                        $alpnListLen = unpack('n', substr($binary, $offset, 2))[1];
                        if ($extLen >= 2 + $alpnListLen && $offset + 2 + $alpnListLen <= $len) {
                            $alpnStrLen = ord($binary[$offset + 2]);
                            if ($alpnListLen >= 1 + $alpnStrLen) {
                                $alpnProtocol = substr($binary, $offset + 3, $alpnStrLen);
                            }
                        }
                    }
                } elseif ($extType === 43) { // Supported Versions
                    if ($extLen >= 1 && $offset + 1 <= $len) {
                        $versionsLen = ord($binary[$offset]);
                        for ($j = 1; $j < $versionsLen + 1; $j += 2) {
                            if ($offset + $j + 2 <= $len && $j + 2 <= $extLen) {
                                $supportedVersions[] = unpack('n', substr($binary, $offset + $j, 2))[1];
                            }
                        }
                    }
            }
            $offset += $extLen;
        }

        // Nettoyage des valeurs GREASE (RFC 8701) pour la conformité JA3
        $filterGrease = fn(array $arr) => array_values(array_filter($arr, fn($v) => !in_array($v, self::GREASE_VALUES, true)));

            $cleanCiphers = $filterGrease($ciphers);
            $cleanExtensions = $filterGrease($extensions);
            $cleanCurves = $filterGrease($curves);
            $cleanPoints = $filterGrease($points);
            $cleanSigAlgs = $filterGrease($sigAlgs);
            $cleanSupportedVersions = $filterGrease($supportedVersions);

        $sslVersion = unpack('n', substr($binary, 9, 2))[1];
        $ja3String = implode(',', [
            $sslVersion,
                implode('-', $cleanCiphers),
                implode('-', $cleanExtensions),
                implode('-', $cleanCurves),
                implode('-', $cleanPoints)
        ]);

            // Calcul natif de JA4
            $highestVersion = $sslVersion;
            if (!empty($cleanSupportedVersions)) {
                $highestVersion = max($cleanSupportedVersions);
            }

            $ja4Version = "12";
            if ($highestVersion === 0x0304) {
                $ja4Version = "13";
            } elseif ($highestVersion === 0x0303) {
                $ja4Version = "12";
            } elseif ($highestVersion === 0x0302) {
                $ja4Version = "11";
            } elseif ($highestVersion === 0x0301) {
                $ja4Version = "10";
            }

            $sniStatus = $hasSni ? "d" : "i";
            $numCiphers = min(99, count($cleanCiphers));
            $numExtensions = min(99, count($cleanExtensions));

            $ja4Alpn = "00";
            if ($alpnProtocol !== '') {
                $lenAlpn = strlen($alpnProtocol);
                if ($lenAlpn === 1) {
                    $ja4Alpn = $alpnProtocol . $alpnProtocol;
                } else {
                    $ja4Alpn = $alpnProtocol[0] . $alpnProtocol[$lenAlpn - 1];
                }
            }

            $ja4_a = "t" . $ja4Version . $sniStatus . sprintf("%02d", $numCiphers) . sprintf("%02d", $numExtensions) . $ja4Alpn;

            $sortedCiphers = $cleanCiphers;
            sort($sortedCiphers);
            $ciphersHex = array_map(fn($c) => sprintf('%04x', $c), $sortedCiphers);
            $ciphersString = implode(',', $ciphersHex);
            $ja4_b = substr(hash('sha256', $ciphersString), 0, 12);

            $sortedExtensions = $cleanExtensions;
            sort($sortedExtensions);
            $extensionsHex = array_map(fn($e) => sprintf('%04x', $e), $sortedExtensions);
            $extensionsString = implode(',', $extensionsHex);

            $sortedSigAlgs = $cleanSigAlgs;
            sort($sortedSigAlgs);
            $sigAlgsHex = array_map(fn($s) => sprintf('%04x', $s), $sortedSigAlgs);
            $sigAlgsString = implode(',', $sigAlgsHex);

            $ja4_c_input = $extensionsString . '_' . $sigAlgsString;
            $ja4_c = substr(hash('sha256', $ja4_c_input), 0, 12);

            $ja4_hash = $ja4_a . "_" . $ja4_b . "_" . $ja4_c;

        return [
            'ja3_string' => $ja3String,
                'ja3_hash'   => md5($ja3String),
                'ja4_raw'    => $ja4_hash
        ];
    }
}
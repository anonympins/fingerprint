<?php

declare(strict_types=1);

namespace Anonympins\Fingerprint;

/**
 * Moteur de validation d'attestation matérielle cryptographique pour PHP :
 * 1. Apple App Attest (Secure Enclave)
 * 2. Google Play Integrity (Titan M / Android TEE)
 * 3. Device Bound Session Credentials (DBSC - W3C / TPM 2.0 / FIDO2)
 */
class HardwareAttestation
{
    /**
     * Callback personnalisé pour valider la signature cryptographique (mock ou bypass).
     * Signature attendue : function(string $data, string $signature, mixed $key): bool
     *
     * @var \Closure|null
     */
    public static ?\Closure $signatureVerifier = null;

    /**
     * Définit ou réinitialise le validateur de signature cryptographique.
     * Permet d'injecter un mock pour tester le moteur avec n'importe quelle clé.
     */
    public static function setSignatureVerifier(?callable $verifier): void
    {
        self::$signatureVerifier = $verifier !== null ? \Closure::fromCallable($verifier) : null;
    }

    /**
     * Décode une chaîne base64url de manière sécurisée.
     */
    public static function base64UrlDecode(string $str): string
    {
        $remainder = strlen($str) % 4;
        if ($remainder > 0) {
            $str .= str_repeat('=', 4 - $remainder);
        }
        $decoded = base64_decode(strtr($str, '-_', '+/'), true);
        return $decoded !== false ? $decoded : '';
    }

    /**
     * Convertit une signature IEEE P1363 (r || s, 64 octets) en séquence DER ASN.1 pour OpenSSL.
     */
    public static function ieeeP1363ToDer(string $rawSig): string
    {
        if (strlen($rawSig) !== 64) {
            return $rawSig;
        }
        $r = substr($rawSig, 0, 32);
        $s = substr($rawSig, 32, 32);

        $encodeInt = function (string $val): string {
            $val = ltrim($val, "\x00");
            if ($val === '') {
                $val = "\x00";
            }
            if (ord($val[0]) & 0x80) {
                $val = "\x00" . $val;
            }
            return "\x02" . chr(strlen($val)) . $val;
        };

        $rDer = $encodeInt($r);
        $sDer = $encodeInt($s);
        $seq = $rDer . $sDer;
        return "\x30" . chr(strlen($seq)) . $seq;
    }

    /**
     * Reconstruit une clé publique EC P-256 au format PEM à partir d'un JWK.
     */
    public static function jwkToPem(array $jwk): ?string
    {
        if (($jwk['kty'] ?? '') !== 'EC' || ($jwk['crv'] ?? '') !== 'P-256') {
            return null;
        }
        $x = self::base64UrlDecode((string)($jwk['x'] ?? ''));
        $y = self::base64UrlDecode((string)($jwk['y'] ?? ''));
        if (strlen($x) !== 32 || strlen($y) !== 32) {
            return null;
        }

        // En-tête ASN.1 SPKI fixe pour l'algorithme id-ecPublicKey avec courbe prime256v1
        $spkiHeader = hex2bin('3059301306072a8648ce3d020106082a8648ce3d03010703420004');
        $der = $spkiHeader . $x . $y;
        return "-----BEGIN PUBLIC KEY-----\n" . chunk_split(base64_encode($der), 64, "\n") . "-----END PUBLIC KEY-----\n";
    }

    // ==========================================
    // 1. APPLE APP ATTEST (SECURE ENCLAVE)
    // ==========================================
    public static function verifyAppleAppAttestAssertion(
        string $publicKeyPem,
        string $assertionRaw,
        string $clientDataHash,
        int $storedCounter = 0
    ): array {
        if (strlen($assertionRaw) < 37) {
            return ['isValid' => false, 'newCounter' => $storedCounter];
        }

        $authData = substr($assertionRaw, 0, 37);
        $signature = substr($assertionRaw, 37);

        // Monotonic counter: 4 octets en big-endian (octets 33 à 37)
        $counterBytes = substr($authData, 33, 4);
        $counterArr = unpack('N', $counterBytes);
        $counter = $counterArr ? $counterArr[1] : 0;

        if ($counter <= $storedCounter) {
            return ['isValid' => false, 'newCounter' => $storedCounter];
        }

        $signedData = $authData . $clientDataHash;

        if (self::$signatureVerifier !== null) {
            $isValid = (bool)(self::$signatureVerifier)($signedData, $signature, $publicKeyPem);
        } else {
            $pubKey = openssl_pkey_get_public($publicKeyPem);
            if (!$pubKey) {
                return ['isValid' => false, 'newCounter' => $storedCounter];
            }
            $isValid = openssl_verify($signedData, $signature, $pubKey, OPENSSL_ALGO_SHA256) === 1;
        }

        return [
            'isValid' => $isValid,
            'newCounter' => $isValid ? $counter : $storedCounter
        ];
    }

    // ==========================================
    // 2. GOOGLE PLAY INTEGRITY (TITAN M / TEE)
    // ==========================================
    public static function verifyPlayIntegrityJws(
        string $token,
        ?string $expectedPackageName = null,
        ?string $expectedNonce = null,
        int $maxAgeMs = 180000
    ): array {
        $parts = explode('.', trim($token));
        if (count($parts) !== 3) {
            return ['isValid' => false, 'payload' => []];
        }

        $headerJson = self::base64UrlDecode($parts[0]);
        $payloadJson = self::base64UrlDecode($parts[1]);
        $signature = self::base64UrlDecode($parts[2]);

        $header = json_decode($headerJson, true);
        $payload = json_decode($payloadJson, true);

        if (!is_array($header) || !is_array($payload)) {
            return ['isValid' => false, 'payload' => []];
        }

        // 1. Signature du signataire Google Play
        if (self::$signatureVerifier !== null) {
            $signingInput = $parts[0] . '.' . $parts[1];
            $key = $header['x5c'] ?? $header['kid'] ?? null;
            if (!(self::$signatureVerifier)($signingInput, $signature, $key)) {
                return ['isValid' => false, 'payload' => $payload];
            }
        } elseif (!empty($header['x5c']) && is_array($header['x5c'])) {
            $certDer = base64_decode((string)$header['x5c'][0], true);
            if ($certDer) {
                $pemCert = "-----BEGIN CERTIFICATE-----\n" . chunk_split(base64_encode($certDer), 64, "\n") . "-----END CERTIFICATE-----\n";
                $pubKey = openssl_pkey_get_public($pemCert);
                if ($pubKey) {
                    $signingInput = $parts[0] . '.' . $parts[1];
                    $derSig = strlen($signature) === 64 ? self::ieeeP1363ToDer($signature) : $signature;
                    if (openssl_verify($signingInput, $derSig, $pubKey, OPENSSL_ALGO_SHA256) !== 1) {
                        return ['isValid' => false, 'payload' => $payload];
                    }
                }
            }
        }

        // 2. Nonce
        $reqDetails = $payload['requestDetails'] ?? [];
        if ($expectedNonce !== null && ($reqDetails['nonce'] ?? null) !== $expectedNonce) {
            return ['isValid' => false, 'payload' => $payload];
        }

        // 3. Fraîcheur de la réponse
        if (isset($reqDetails['timestampMillis'])) {
            $ts = (int)$reqDetails['timestampMillis'];
            $now = (int)(microtime(true) * 1000);
            if (abs($now - $ts) > $maxAgeMs) {
                return ['isValid' => false, 'payload' => $payload];
            }
        }

        // 4. Intégrité de l'application
        if ($expectedPackageName !== null) {
            $appInteg = $payload['appIntegrity'] ?? [];
            if (($appInteg['packageName'] ?? null) !== $expectedPackageName) {
                return ['isValid' => false, 'payload' => $payload];
            }
        }

        // 5. Intégrité matérielle
        $devInteg = $payload['deviceIntegrity'] ?? [];
        $verdicts = $devInteg['deviceRecognitionVerdict'] ?? [];
        $isHardwareStrong = in_array('MEETS_STRONG_INTEGRITY', $verdicts, true) || in_array('MEETS_DEVICE_INTEGRITY', $verdicts, true);

        return [
            'isValid' => $isHardwareStrong,
            'payload' => $payload
        ];
    }

    // ==========================================
    // 3. DEVICE BOUND SESSION CREDENTIALS (DBSC)
    // ==========================================
    public static function verifyDbscProof(
        string $dbscJwt,
        array $jwk,
        string $expectedSessionId,
        string $expectedOrigin,
        ?string $expectedNonce = null
    ): bool {
        $parts = explode('.', trim($dbscJwt));
        if (count($parts) !== 3) {
            return false;
        }

        $header = json_decode(self::base64UrlDecode($parts[0]), true);
        $payload = json_decode(self::base64UrlDecode($parts[1]), true);
        $rawSig = self::base64UrlDecode($parts[2]);

        if (!is_array($header) || !is_array($payload)) {
            return false;
        }

        $typ = $header['typ'] ?? '';
        if ($typ !== 'dbsc+jwt' && $typ !== 'jwt') {
            return false;
        }
        if (($payload['sub'] ?? '') !== $expectedSessionId) {
            return false;
        }
        if (!empty($expectedOrigin) && isset($payload['aud']) && $payload['aud'] !== $expectedOrigin) {
            return false;
        }
        if ($expectedNonce !== null && ($payload['nonce'] ?? null) !== $expectedNonce) {
            return false;
        }
        if (isset($payload['exp']) && $payload['exp'] < time()) {
            return false;
        }

        $signingInput = $parts[0] . '.' . $parts[1];
        if (self::$signatureVerifier !== null) {
            return (bool)(self::$signatureVerifier)($signingInput, $rawSig, $jwk);
        }

        $pem = self::jwkToPem($jwk);
        if (!$pem) {
            return false;
        }

        $pubKey = openssl_pkey_get_public($pem);
        if (!$pubKey) {
            return false;
        }

        $derSig = strlen($rawSig) === 64 ? self::ieeeP1363ToDer($rawSig) : $rawSig;
        return openssl_verify($signingInput, $derSig, $pubKey, OPENSSL_ALGO_SHA256) === 1;
    }

    /**
     * Traite l'ensemble des attestations matérielles d'une requête HTTP.
     */
    public static function process(RequestContext $context, string $sessionId, object $store, array $config = []): array
    {
        // 1. DBSC
        $dbscHeader = $context->getHeader('sec-session-response');
        if ($dbscHeader && !empty($sessionId)) {
            $sessionRec = $store->get("dbsc-session:{$sessionId}");
            if (is_array($sessionRec) && !empty($sessionRec['jwk'])) {
                $nonce = $store->get("dbsc-nonce:{$sessionId}");
                $origin = $context->getHeader('origin') ?? $context->getHeader('host') ?? '';
                if (self::verifyDbscProof($dbscHeader, $sessionRec['jwk'], $sessionId, $origin, is_string($nonce) ? $nonce : null)) {
                    $store->delete("dbsc-nonce:{$sessionId}");
                    return ['verified' => true, 'type' => 'dbsc_tpm', 'details' => ['sessionId' => $sessionId]];
                }
            }
        }

        // 2. Google Play Integrity
        $playToken = $context->getHeader('x-play-integrity-token') ?? $context->getHeader('x-play-integrity');
        if ($playToken) {
            $pkgName = $config['androidPackageName'] ?? null;
            $nonce = $store->get("play-integrity-nonce:{$context->clientIp}");
            $res = self::verifyPlayIntegrityJws($playToken, $pkgName, is_string($nonce) ? $nonce : null);
            if ($res['isValid']) {
                if ($nonce) {
                    $store->delete("play-integrity-nonce:{$context->clientIp}");
                }
                return ['verified' => true, 'type' => 'google_play_integrity_strong', 'details' => $res['payload']];
            }
        }

        return ['verified' => false, 'type' => 'none', 'details' => []];
    }
}
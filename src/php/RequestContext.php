<?php

declare(strict_types=1);

namespace Anonympins\Fingerprint;

/**
 * Représente le contexte d'une requête HTTP, fournissant un accès unifié
 * aux informations nécessaires pour l'analyse de l'empreinte.
 * Cette classe est conçue pour être créée à partir d'un objet de requête
 * standard (ex: PSR-7, Symfony, Laravel).
 */
class RequestContext
{
    public string $clientIp;
    public string $path;
    /** @var array<string, string> */
    public array $headers;
    /** @var array<string, mixed> */
    public array $query;
    /** @var array<string, mixed>|object|null */
    public $body;
    /** @var array<string, string> */
    public array $cookies;
    public ?string $httpVersion;
    public int $requestTimestamp;

    /** @var ?array{type: string, name: string} */
    public ?array $graphqlOperation = null;

    /** @var ?array<string, mixed> */
    public ?array $newCookieForResponse = null;

    // Propriétés spécifiques qui peuvent être fournies par un proxy inverse
    public ?string $ja3;
    public ?string $ja4;
    public ?string $http2Fingerprint;
    public ?string $tcpFingerprint;

    /**
     * @param string $clientIp
     * @param string $path
     * @param array<string, string> $headers
     * @param array<string, mixed> $query
     * @param array<string, mixed>|object|null $body
     * @param array<string, string> $cookies
     * @param string|null $httpVersion
     * @param int|null $requestTimestamp
     */
    public function __construct(
        string $clientIp,
        string $path,
        array $headers,
        array $query,
        $body,
        array $cookies,
        ?string $httpVersion,
        ?int $requestTimestamp = null
    ) {
        $this->clientIp = $clientIp;
        $this->path = $path;
        // Normaliser les en-têtes en minuscules pour un accès cohérent
        $this->headers = array_change_key_case($headers, CASE_LOWER);
        $this->query = $query;
        $this->body = $body;
        $this->cookies = $cookies;
        $this->httpVersion = $httpVersion;
        $this->requestTimestamp = $requestTimestamp ?? (int)(microtime(true) * 1000);

        // Extraire les empreintes TLS/HTTP2/TCP si elles sont fournies par les en-têtes
        $this->ja3 = $this->headers['x-ja3-hash'] ?? null;
        $this->ja4 = $this->headers['x-ja4-hash'] ?? null;
        $this->http2Fingerprint = $this->headers['x-http2-fingerprint'] ?? null;
        $this->tcpFingerprint = $this->headers['x-tcp-fingerprint'] ?? null;
    }

    public function getHeader(string $name): ?string
    {
        return $this->headers[strtolower($name)] ?? null;
    }
}
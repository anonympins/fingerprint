<?php

declare(strict_types=1);

namespace Anonympins\Fingerprint;

use Anonympins\Fingerprint\Utils\MetricsManager;

/**
 * Direct integration of the fingerprint engine for PHP applications without a PSR framework.
 * Interacts directly with PHP superglobals and response headers.
 */
class DirectFingerprint
{
    private array $securityConfig;
    private FingerprintEngine $engine;

    /**
     * @param array $securityConfig Security configuration for the engine.
     */
    public function __construct(array $securityConfig)
    {
        $this->engine = new FingerprintEngine($securityConfig);
        $this->securityConfig = $securityConfig;
    }

    /**
     * Protects the current entry point.
     * Analyzes the incoming request and issues challenges or block responses, exiting the script if necessary.
     * If the request is allowed, returns the fingerprint data.
     *
     * @return array{score: float, vector: array}|null Fingerprint data if allowed, null otherwise.
     */
    public function protect(): ?array
    {
        // 1. Build request context from PHP superglobals
        $body = $_POST ?: json_decode(file_get_contents('php://input'), true);
        $headers = function_exists('getallheaders') ? getallheaders() : [];

        $context = new RequestContext(
            $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1',
            parse_url($_SERVER['REQUEST_URI'] ?? '', PHP_URL_PATH) ?: '/',
            $headers,
            $_GET,
            $body,
            $_COOKIE,
            $_SERVER['SERVER_PROTOCOL'] ?? '1.1'
        );

        // 2. Process request with engine
        $decision = $this->engine->processRequest($context);

        // 3. Act on decision
        if (isset($context->newCookieForResponse)) {
            $cookie = $context->newCookieForResponse;
            $this->sendCookie($cookie['name'], $cookie['value'], $cookie['options'] ?? []);
        }

        switch ($decision['action']) {
            case 'block':
            case 'challenge':
                http_response_code($decision['status'] ?? 403);
                if (is_array($decision['body'])) {
                    header('Content-Type: application/json');
                    echo json_encode($decision['body']);
                } else {
                    header('Content-Type: text/html; charset=utf-8');
                    echo $decision['body'];
                }
                exit();

            case 'redirect':
                if (isset($decision['cookie'])) {
                    $this->sendCookie($decision['cookie']['name'], $decision['cookie']['value'], $decision['cookie']['options'] ?? []);
                }
                header('Location: ' . $decision['path'], true, 302);
                exit();

            case 'next':
            default:
                // Request allowed, return fingerprint metrics
                return ['score' => $decision['score'], 'vector' => $decision['vector']];
        }
    }

    /**
     * Sends an HTTP cookie while handling modern flags like 'partitioned'.
     *
     * @param string $name
     * @param string $value
     * @param array<string, mixed> $options
     */
    private function sendCookie(string $name, string $value, array $options): void
    {
        $isPartitioned = !empty($options['partitioned']);
        unset($options['partitioned']);

        // PHP setcookie() does not natively support 'partitioned'.
        // If the cookie is secure and partitioned, emit raw header manually.
        if ($isPartitioned && !empty($options['secure'])) {
            $header = rawurlencode($name) . '=' . rawurlencode($value);
            if (!empty($options['expires'])) {
                $header .= '; Expires=' . gmdate('D, d M Y H:i:s T', (int)$options['expires']);
                $header .= '; Max-Age=' . max(0, (int)$options['expires'] - time());
            }
            if (!empty($options['path'])) {
                $header .= '; Path=' . $options['path'];
            }
            if (!empty($options['domain'])) {
                $header .= '; Domain=' . $options['domain'];
            }
            if (!empty($options['secure'])) {
                $header .= '; Secure';
            }
            if (!empty($options['httponly'])) {
                $header .= '; HttpOnly';
            }
            if (!empty($options['samesite'])) {
                $header .= '; SameSite=' . $options['samesite'];
            }
            $header .= '; Partitioned';
            header('Set-Cookie: ' . $header, false);
            return;
        }

        $allowedKeys = ['expires', 'path', 'domain', 'secure', 'httponly', 'samesite'];
        $cleanOptions = array_intersect_key($options, array_flip($allowedKeys));
        setcookie($name, $value, $cleanOptions);
    }

    /**
     * Handles a request to the /metrics endpoint, applying authorization rules.
     * If metrics are enabled and authorized, it outputs Prometheus formatted metrics and exits.
     * Otherwise, it handles unauthorized access or returns a 404 if metrics are not enabled.
     *
     * @param RequestContext $context The current request context.
     */
    public function handleMetricsRequest(RequestContext $context): void
    {
        // 2. Appliquer le callback d'autorisation personnalisé si défini.
        $authorizationCallback = $this->securityConfig['metricsAuthorizationCallback'] ?? null;
        if (is_callable($authorizationCallback)) {
            $decision = call_user_func($authorizationCallback, $context);

            if (is_bool($decision)) {
                if (!$decision) {
                    http_response_code(403); // Forbidden
                    echo "Access to metrics denied.";
                    exit();
                }
            } elseif (is_array($decision) && isset($decision['action'])) {
                switch ($decision['action']) {
                    case 'block':
                        http_response_code($decision['status'] ?? 403);
                        echo $decision['body'] ?? "Access denied.";
                        exit();
                    case 'redirect':
                        header('Location: ' . $decision['path'], true, $decision['status'] ?? 302);
                        exit();
                    case 'next':
                        // Autorisé, continuer pour servir les métriques
                        break;
                    default:
                        // Action inconnue, refuser par défaut
                        http_response_code(403);
                        echo "Invalid authorization decision.";
                        exit();
                }
            } else {
                // Retour inattendu du callback, refuser par défaut
                http_response_code(403);
                echo "Invalid authorization callback response.";
                exit();
            }
        }

        // 3. Si autorisé, servir les métriques.
        header('Content-Type: text/plain; version=0.0.4; charset=utf-8');
        echo MetricsManager::getPrometheusMetrics();
        exit();
    }

    /**
     * Returns Prometheus formatted metrics if enabled in the security configuration.
     * @return string|null
     */
    public function getPrometheusMetrics(): ?string
    {
        return MetricsManager::getPrometheusMetrics();
    }
}
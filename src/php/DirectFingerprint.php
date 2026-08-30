<?php

declare(strict_types=1);

namespace Anonympins\Fingerprint;

use Random\RandomException;

/**
 * Intégration directe du moteur de fingerprinting pour les applications PHP sans framework PSR.
 * Cette classe interagit directement avec les superglobales PHP et les fonctions de réponse.
 */
class DirectFingerprint
{
    private FingerprintEngine $engine;

    /**
     * @param array $securityConfig La configuration de sécurité pour le moteur.
     */
    public function __construct(array $securityConfig)
    {
        $this->engine = new FingerprintEngine($securityConfig);
    }

    /**
     * Protège le point d'entrée actuel.
     * Analyse la requête entrante et, si nécessaire, envoie une réponse de challenge/blocage et termine le script.
     * Si la requête est autorisée, la méthode retourne simplement et le reste du script peut s'exécuter.
     *
     * @return array{score: float, vector: array}|null Les données du fingerprint si la requête est autorisée, null sinon.
     * @throws RandomException
     */
    public function protect(): ?array
    {
        // 1. Construire le contexte de la requête à partir des superglobales PHP.
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

        // 2. Traiter la requête avec le moteur.
        $decision = $this->engine->processRequest($context);

        // 3. Agir sur la décision.
        if (isset($context->newCookieForResponse)) {
            $cookie = $context->newCookieForResponse;
            setcookie($cookie['name'], $cookie['value'], $cookie['options']);
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
                exit(); // Termine le script.

            case 'redirect':
                if (isset($decision['cookie'])) {
                    setcookie($decision['cookie']['name'], $decision['cookie']['value'], $decision['cookie']['options']);
                }
                header('Location: ' . $decision['path'], true, 302);
                exit(); // Termine le script.

            case 'next':
            default:
                // La requête est autorisée, on retourne les informations du fingerprint.
                return ['score' => $decision['score'], 'vector' => $decision['vector']];
        }
    }
}
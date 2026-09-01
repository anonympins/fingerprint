<?php

declare(strict_types=1);

namespace Anonympins\Fingerprint;
use Anonympins\Fingerprint\Config\SecurityProfiles;

/**
 * FingerprintClient - Wrapper PHP pour la bibliothèque de fingerprinting côté client.
 *
 * Cette classe facilite l'intégration de la bibliothèque JavaScript `fingerprint.client.js`
 * dans une application PHP. Elle gère l'injection sécurisée du script et la création
 * de "honeypots" (pièges à bots) dans les formulaires.
 */
class FingerprintClient
{
    /**
     * @var string Le chemin vers le fichier de la bibliothèque client JavaScript.
     */
    private string $clientScriptPath;

    /**
     * @var array La configuration à passer à la fonction `initializeClient` de la bibliothèque JS.
     */
    private array $clientConfig;

    /**
     * @var string|null Un nonce cryptographique pour la Content Security Policy (CSP).
     */
    private ?string $nonce;

    /**
     * Constructeur de la classe.
     *
     * @param string $clientScriptPath Le chemin d'accès web au fichier `fingerprint.client.js`.
     * @param array $clientConfig La configuration pour la bibliothèque client (souris, frappes, honeypots, etc.).
     */
    public function __construct(string $clientScriptPath, array $clientConfig = [])
    {
        $this->clientScriptPath = $clientScriptPath;

        $defaultConfig = [
            'mouse' => true,
            'keystrokes' => true,
            'clicks' => true,
            'honeypots' => [],
            'fetch' => [
                'handleChallenges' => true,
                'probationaryTtl' => 30000, // 30 seconds
            ],
            'wasm' => true, // Activer la tentative de chargement du module WASM
            'wasmPath' => '/fp.js' // Chemin vers le script de chargement WASM
        ];

        // Utiliser une fusion profonde pour permettre de surcharger des sous-clés
        $this->clientConfig = SecurityProfiles::deepMerge($defaultConfig, $clientConfig);

        try {
            // Génère un nonce pour CSP si possible, pour une sécurité renforcée.
            $this->nonce = bin2hex(random_bytes(16));
        } catch (\Exception $e) {
            $this->nonce = null;
        }
    }

    /**
     * Génère un champ de formulaire "honeypot" caché.
     * Les bots le rempliront, mais il sera invisible pour les humains.
     *
     * @param string $fieldName Le nom du champ (doit correspondre à la configuration client).
     * @return string Le code HTML du champ honeypot.
     */
    public function generateHoneypotField(string $fieldName): string
    {
        // Ajoute le champ à la configuration pour que le script client le surveille.
        if (!in_array($fieldName, $this->clientConfig['honeypots'])) {
            $this->clientConfig['honeypots'][] = $fieldName;
        }

        // Styles CSS pour cacher le champ de manière robuste.
        $styles = 'position:absolute; left:-9999px; top:-9999px; opacity:0;';

        return '<div style="' . $styles . '" aria-hidden="true">'
            . '<label for="' . htmlspecialchars($fieldName) . '">Ne pas remplir ce champ</label>'
            . '<input type="text" id="' . htmlspecialchars($fieldName) . '" name="' . htmlspecialchars($fieldName) . '" tabindex="-1" autocomplete="off">'
            . '</div>';
    }

    /**
     * Génère le bloc de script complet à inclure dans une page HTML.
     *
     * @return string Le code HTML des balises <script>.
     */
    public function getScriptTag(): string
    {
        $configJson = json_encode($this->clientConfig);
        $nonceAttr = $this->nonce ? ' nonce="' . $this->nonce . '"' : '';

        // Le script d'initialisation qui sera inclus dans la page.
        $initScript = <<<JS
document.addEventListener('DOMContentLoaded', function() {
    const config = {$configJson};
    if (window.ClientLibrary) {
        if (config.wasmPath) {
            const wasmScript = document.createElement('script');
            wasmScript.src = config.wasmPath;
            wasmScript.async = true;
            wasmScript.nonce = '{$this->nonce}';
            document.head.appendChild(wasmScript);
        }

        window.ClientLibrary.initializeClient(config);
    } else {
        console.error('Fingerprint client library not loaded.');
    }
});
JS;

        // On combine le chargement de la bibliothèque et le script d'initialisation.
        return '<script src="' . htmlspecialchars($this->clientScriptPath) . '"' . $nonceAttr . '></script>'
            . '<script' . $nonceAttr . '>' . $initScript . '</script>';
    }

    /**
     * Retourne le nonce généré pour pouvoir l'utiliser dans les en-têtes CSP.
     * @return string|null
     */
    public function getNonce(): ?string
    {
        return $this->nonce;
    }
}
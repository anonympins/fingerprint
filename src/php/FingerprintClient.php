<?php

declare(strict_types=1);

namespace Anonympins\Fingerprint;
use Anonympins\Fingerprint\Config\SecurityProfiles;

/**
 * FingerprintClient - PHP wrapper for the client-side fingerprinting library.
 *
 * Handles script injection and generation of polymorphic honeypot fields
 * inside HTML forms.
 */
class FingerprintClient
{
    /**
     * @var string Path to client script asset.
     */
    private string $clientScriptPath;

    /**
     * @var array Configuration payload passed to `initializeClient`.
     */
    private array $clientConfig;

    /**
     * @var string|null Cryptographic nonce for Content Security Policy (CSP).
     */
    private ?string $nonce;

    /**
     * Constructor.
     *
     * @param string $clientScriptPath Web-accessible path to `fingerprint.client.js`.
     * @param array $clientConfig Client initialization options.
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
            'wasm' => true, // Attempt to load WASM module
            'wasmPath' => '/fp.js' // Path to WASM loader script
        ];

        // Deep merge configuration overrides
        $this->clientConfig = SecurityProfiles::deepMerge($defaultConfig, $clientConfig);

        try {
            // Generate CSP nonce when possible
            $this->nonce = bin2hex(random_bytes(16));
        } catch (\Exception $e) {
            $this->nonce = null;
        }
    }

    /**
     * Generates a hidden honeypot form field.
     * Traps automated bots while remaining invisible to human users.
     *
     * @param string $fieldName Field name (must match client honeypot registration).
     * @return string Generated HTML markup.
     */
    public function generateHoneypotField(string $fieldName): string
    {
        // Register field in client configuration for monitoring
        if (!in_array($fieldName, $this->clientConfig['honeypots'])) {
            $this->clientConfig['honeypots'][] = $fieldName;
        }

        // Polymorphic CSS styling to robustly obscure honeypots
        $styleOptions = [
            'position:absolute; left:-9999px; top:-9999px; transform:scale(0); opacity:0; pointer-events:none;',
            'position:fixed; left:-8888px; top:-8888px; width:0; height:0; overflow:hidden; opacity:0; pointer-events:none;',
            'display:none; visibility:hidden; pointer-events:none;'
        ];
        $styles = $styleOptions[array_rand($styleOptions)];

        $containerTags = ['div', 'span', 'p', 'section'];
        $tag = $containerTags[array_rand($containerTags)];

        $nestingType = rand(0, 1);
        if ($nestingType === 1) {
            return '<' . $tag . ' style="' . $styles . '" aria-hidden="true">'
                . '<label for="' . htmlspecialchars($fieldName) . '">' . htmlspecialchars($fieldName) 
                . '<input type="text" id="' . htmlspecialchars($fieldName) . '" name="' . htmlspecialchars($fieldName) . '" tabindex="-1" autocomplete="off">'
                . '</label>'
                . '</' . $tag . '>';
        }

        return '<' . $tag . ' style="' . $styles . '" aria-hidden="true">'
            . '<label for="' . htmlspecialchars($fieldName) . '">' . htmlspecialchars($fieldName) . '</label>'
            . '<input type="text" id="' . htmlspecialchars($fieldName) . '" name="' . htmlspecialchars($fieldName) . '" tabindex="-1" autocomplete="off">'
            . '</' . $tag . '>';
    }

    /**
     * Generates HTML script tags to embed the client library on a page.
     *
     * @return string HTML <script> markup.
     */
    public function getScriptTag(): string
    {
        $configJson = json_encode($this->clientConfig);
        $nonceAttr = $this->nonce ? ' nonce="' . $this->nonce . '"' : '';

        // Inline initialization script embedded in HTML
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

        // Combine library loader script and inline initialization
        return '<script src="' . htmlspecialchars($this->clientScriptPath) . '"' . $nonceAttr . '></script>'
            . '<script' . $nonceAttr . '>' . $initScript . '</script>';
    }

    /**
     * Returns the generated CSP nonce.
     * @return string|null
     */
    public function getNonce(): ?string
    {
        return $this->nonce;
    }
}
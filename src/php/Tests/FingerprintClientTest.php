<?php

declare(strict_types=1);

namespace Anonympins\Fingerprint\Tests;

use Anonympins\Fingerprint\FingerprintClient;
use PHPUnit\Framework\TestCase;

class FingerprintClientTest extends TestCase
{
    public function testDefaultConfigurationIncludesWasmAndDefaultPath(): void
    {
        $client = new FingerprintClient('/js/fingerprint.client.js');
        $scriptTag = $client->getScriptTag();

        // Vérifie que le script principal est présent
        $this->assertStringContainsString('src="/js/fingerprint.client.js"', $scriptTag);

        // Vérifie les configurations WASM par défaut dans l'objet sérialisé pour le JS
        $this->assertStringContainsString('"wasm":true', $scriptTag);
        $this->assertStringContainsString('"wasmPath":"\/fp.js"', $scriptTag);
        $this->assertStringContainsString('wasmScript.src = config.wasmPath;', $scriptTag);
    }

    public function testWasmCanBeOverriddenOrDisabled(): void
    {
        $client = new FingerprintClient('/js/fingerprint.client.js', [
            'wasm' => false,
            'wasmPath' => '/custom/path/to/wasm.js'
        ]);
        $scriptTag = $client->getScriptTag();

        // Vérifie que les surcharges sont correctement prises en compte
        $this->assertStringContainsString('"wasm":false', $scriptTag);
        $this->assertStringContainsString('"wasmPath":"\/custom\/path\/to\/wasm.js"', $scriptTag);
    }

    public function testGenerateHoneypotFieldAddsFieldToConfig(): void
    {
        $client = new FingerprintClient('/js/fingerprint.client.js');
        
        $honeypotFieldHtml = $client->generateHoneypotField('confirm_email_trap');
        
        // Vérifie le code HTML du champ Honeypot
        $this->assertStringContainsString('name="confirm_email_trap"', $honeypotFieldHtml);
        $this->assertStringContainsString('tabindex="-1"', $honeypotFieldHtml);
        
        // Vérifie que le champ s'enregistre dynamiquement dans la configuration JS finale
        $scriptTag = $client->getScriptTag();
        $this->assertStringContainsString('"honeypots":["confirm_email_trap"]', $scriptTag);
    }

    public function testNonceIsGeneratedAndAppliedToScripts(): void
    {
        $client = new FingerprintClient('/js/fingerprint.client.js');
        $nonce = $client->getNonce();
        
        // Vérifie que le nonce est généré correctement (32 caractères hexa)
        $this->assertNotNull($nonce);
        $this->assertEquals(32, strlen($nonce));
        
        $scriptTag = $client->getScriptTag();
        
        // Le nonce doit être présent sur la balise script HTML
        $this->assertStringContainsString('nonce="' . $nonce . '"', $scriptTag);
        
        // Et configuré dynamiquement lors de l'injection du script de chargement WASM
        $this->assertStringContainsString('wasmScript.nonce = \'' . $nonce . '\'', $scriptTag);
    }
}
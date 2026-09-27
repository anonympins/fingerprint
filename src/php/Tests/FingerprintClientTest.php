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

        // Verify main script tag is present
        $this->assertStringContainsString('src="/js/fingerprint.client.js"', $scriptTag);

        // Verify default WASM configuration serialized for JS runtime
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

        // Verify configuration overrides are properly applied
        $this->assertStringContainsString('"wasm":false', $scriptTag);
        $this->assertStringContainsString('"wasmPath":"\/custom\/path\/to\/wasm.js"', $scriptTag);
    }

    public function testGenerateHoneypotFieldAddsFieldToConfig(): void
    {
        $client = new FingerprintClient('/js/fingerprint.client.js');
        
        $honeypotFieldHtml = $client->generateHoneypotField('confirm_email_trap');
        
        // Verify HTML markup of the honeypot field
        $this->assertStringContainsString('name="confirm_email_trap"', $honeypotFieldHtml);
        $this->assertStringContainsString('tabindex="-1"', $honeypotFieldHtml);
        
        // Verify field dynamically registers with client-side configuration
        $scriptTag = $client->getScriptTag();
        $this->assertStringContainsString('"honeypots":["confirm_email_trap"]', $scriptTag);
    }

    public function testNonceIsGeneratedAndAppliedToScripts(): void
    {
        $client = new FingerprintClient('/js/fingerprint.client.js');
        $nonce = $client->getNonce();
        
        // Verify nonce generation format (32 hex characters)
        $this->assertNotNull($nonce);
        $this->assertEquals(32, strlen($nonce));
        
        $scriptTag = $client->getScriptTag();
        
        // Nonce must be attached to HTML script tag
        $this->assertStringContainsString('nonce="' . $nonce . '"', $scriptTag);
        
        // And dynamically set during WASM loader script injection
        $this->assertStringContainsString('wasmScript.nonce = \'' . $nonce . '\'', $scriptTag);
    }
}
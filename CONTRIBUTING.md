# Contributing to fingerprint

We are happy to accept community contributions. Please review the guidelines below to ensure a smooth workflow.

## Development Environment

The library supports both **Node.js** and **PHP**. Testing pipelines are defined for both runtimes.

### Node.js Requirements
1. Install dependencies:
   ```bash
   npm install
   ```
2. Run testing suite (Vitest):
   ```bash
   npm run test
   ```

### PHP Requirements
1. Install Composer dependencies:
   ```bash
   composer install
   ```
2. Run PHPUnit test suite:
   ```bash
   vendor/bin/phpunit
   ```

## Coding Standards

* **Strict Typing**: Use strict typing on PHP code files (`declare(strict_types=1);`).
* **ES Modules**: JavaScript source files must write clean ES Module code.
* **Tests**: Write appropriate vitest or phpunit files for every new security feature or regression bug-fix.

## Pull Request Process

1. Fork the repository and build your feature branch from `main`.
2. Ensure all test suites pass green locally before opening your PR.
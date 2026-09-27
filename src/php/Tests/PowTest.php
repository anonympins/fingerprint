<?php

declare(strict_types=1);

namespace Anonympins\Fingerprint\Tests;

use Anonympins\Fingerprint\Config\SecurityProfiles;
use Anonympins\Fingerprint\FingerprintEngine;
use Anonympins\Fingerprint\ProblemManager;
use Anonympins\Fingerprint\Store\InMemoryStore;
use Anonympins\Fingerprint\Store\StoreManager;
use PHPUnit\Framework\TestCase;

class PowTest extends TestCase
{
    private FingerprintEngine $engine;

    protected function setUp(): void
    {
        // 1. Configure an in-memory store for test isolation.
        $store = new InMemoryStore();
        StoreManager::configureStore($store);

        // 2. Initialize ProblemManager with a valid configuration and store.
        $configPath = dirname(__FILE__) . '/config/problems.config.json';
        ProblemManager::getInstance($configPath, $store);

        // 3. Create engine instance.
        $this->engine = new FingerprintEngine(SecurityProfiles::createSecurityProfile('balanced'));
    }

    public function testGetProblemsIsExposedForTesting(): void
    {
        // Calls ProblemManager::getInstance() internally; setUp() ensures valid initialization.
        $problems = $this->engine->getProblems();
        $this->assertIsArray($problems);
    }
}
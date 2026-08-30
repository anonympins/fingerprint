<?php

declare(strict_types=1);

namespace Anonympins\Fingerprint\Tests;

use PHPUnit\Framework\TestCase;
use Anonympins\Fingerprint\FingerprintEngine;
use Anonympins\Fingerprint\ProblemManager;
use Anonympins\Fingerprint\Store\InMemoryStore;
use Anonympins\Fingerprint\Store\StoreManager;
use Anonympins\Fingerprint\Config\SecurityProfiles;

class PowTest extends TestCase
{
    private FingerprintEngine $engine;

    protected function setUp(): void
    {
        // 1. Configurer un store en mémoire pour l'isolation des tests.
        $store = new InMemoryStore();
        StoreManager::configureStore($store);

        // 2. Initialiser le ProblemManager avec une configuration et un store valides.
        // C'est l'étape cruciale qui manquait.
        $configPath = dirname(__FILE__) . '/problems.config.json';
        ProblemManager::getInstance($configPath, $store);

        // 3. Créer l'instance du moteur.
        $this->engine = new FingerprintEngine(SecurityProfiles::createSecurityProfile('balanced'));
    }

    public function testGetProblemsIsExposedForTesting(): void
    {
        // Cette méthode appelle ProblemManager::getInstance() en interne.
        // Grâce au setUp(), l'instance est déjà initialisée et le test passe.
        $problems = $this->engine->getProblems();
        $this->assertIsArray($problems);
    }
}
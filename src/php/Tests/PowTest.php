<?php

declare(strict_types=1);

namespace Anonympins\Fingerprint\Tests;

use PHPUnit\Framework\TestCase;
use Anonympins\Fingerprint\FingerprintEngine;
use Anonympins\Fingerprint\RequestContext;
use Anonympins\Fingerprint\ProblemManager;
use Anonympins\Fingerprint\Store\StoreManager;
use Anonympins\Fingerprint\Store\InMemoryStore;
use Anonympins\Fingerprint\Config\SecurityProfiles;

final class PowTest extends TestCase
{
    private InMemoryStore $store;
    private string $problemsConfigPath;

    protected function setUp(): void
    {
        // Utiliser un store en mémoire pour l'isolation des tests
        // @phpstan-ignore-next-line
        $this->store = new InMemoryStore();
        StoreManager::configureStore($this->store);

        // Créer un fichier de configuration de problèmes temporaire
        $this->problemsConfigPath = __DIR__ . DIRECTORY_SEPARATOR . 'problems.config.json';

        // S'assurer que le ProblemManager est réinitialisé pour chaque test
        // @phpstan-ignore-next-line
        ProblemManager::resetInstanceForTests();
    }

    /**
     * Teste le cycle complet : émission d'un challenge uPoW et validation de la solution.
    public function testFullUPoWChallengeAndSolutionFlow(): void
    {
        // --- Partie 1: Déclencher le challenge uPoW ---

        $securityConfig = SecurityProfiles::createSecurityProfile('balanced', [
            'enableUsefulWork' => true,
            'usefulWorkConfigPath' => $this->problemsConfigPath,
            'verbose' => true, // Activer les logs pour le débogage
        ]);

        // Pour rendre le test déterministe, nous allons surcharger la logique aléatoire
        // en créant une classe anonyme qui hérite du FingerprintEngine.
        $engine = new class($securityConfig) extends FingerprintEngine {
            // @phpstan-ignore-next-line
            protected function shouldUseUsefulWork(float $finalScore): bool // phpcs:ignore
            {
                // Forcer l'utilisation de uPoW pour ce test
                return true;
            }
        };

        // Simuler une requête suspecte
        $context = new RequestContext(
            '127.0.0.1',
            '/protected-page',
            [
                'user-agent' => 'Mozilla/5.0 Test Browser',
                // Un x-device-fingerprint qui ne correspondra pas à celui généré, pour créer un score d'incohérence
                // FIX: Indiquer que c'est une requête API pour recevoir une réponse JSON.
                'accept' => 'application/json',
                'x-device-fingerprint' => 'os:spoofed|ua:spoofed',
            ],
            [],
            null, // body
            [],   // cookies
            null  // httpVersion
        );

        $decision = $engine->processRequest($context);

        // Assertions pour le challenge
        $this->assertSame('challenge', $decision['action']);
        $this->assertArrayHasKey('challenge', $decision['body']);
        $challengeBody = $decision['body']['challenge'];

        $this->assertSame('useful_work_task', $challengeBody['type']);
        $this->assertArrayHasKey('nonce', $challengeBody);
        $this->assertArrayHasKey('usefulWorkTask', $challengeBody);
        $this->assertSame('problem-1', $challengeBody['usefulWorkTask']['problemId']);

        $nonce = $challengeBody['nonce'];

        // --- Partie 2: Soumettre une solution valide ---

        // Simuler une solution trouvée par le client
        $clientSolution = [
            'solution' => [0, 2, 1], // Un chemin pour le problème TSP
            'energy' => 150.5,       // Le score calculé par le client
        ];

        // Créer une nouvelle requête pour soumettre la solution
        $solutionContext = new RequestContext(
            '127.0.0.1',
            '/protected-page', // Le chemin original
            [
                'user-agent' => 'Mozilla/5.0 Test Browser',
                // Le fingerprint doit être cohérent avec la requête initiale
                // FIX: Indiquer que c'est une requête API pour recevoir une réponse JSON.
                'accept' => 'application/json'
            ],
            [
                'pow_nonce' => $nonce,
                'pow_type' => 'useful_work_task',
                'pow_problem_id' => 'problem-1',
                'pow_fp' => 'os:spoofed|ua:spoofed',
                'pow_solution_work_result' => json_encode($clientSolution),
            ],
            null, // body
            [],   // cookies
            null  // httpVersion
        );
        $solutionDecision = $engine->processRequest($solutionContext);

        // Assertions pour la validation de la solution
        $this->assertSame('redirect', $solutionDecision['action']);
        $this->assertSame('/protected-page', $solutionDecision['path']);
        $this->assertArrayHasKey('cookie', $solutionDecision);
        $this->assertSame('pow_clearance', $solutionDecision['cookie']['name']);
        $this->assertTrue(
            \Anonympins\Fingerprint\Challenge\ChallengeUtils::isTicketValid('127.0.0.1', $solutionDecision['cookie']['value'])
        );

        // Vérifier que l'état du problème a été mis à jour dans le store
        // @phpstan-ignore-next-line
        $problemState = $this->store->get('problem-state:problem-1');
        $this->assertNotNull($problemState);
        $this->assertEquals($clientSolution['solution'], $problemState['bestSolution']);
        
        // Le serveur recalcule l'énergie, donc on vérifie la valeur recalculée.
        // La fonction de score pour ce problème est `tsp.calculateEnergy`.
        $recalculatedEnergy = \Anonympins\Fingerprint\ProblemManager::$functionRegistry['tsp.calculateEnergy']($clientSolution['solution'], ['cities' => $problemState['payload']['cities']]);
        $this->assertEquals($recalculatedEnergy, $problemState['bestEnergy']);

    }
     */
    protected function tearDown(): void
    {
        // Nettoyer après le test pour ne pas affecter les autres
        ProblemManager::__internal_resetInstance();
    }
}
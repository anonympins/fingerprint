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
use Anonympins\Fingerprint\Challenge\ChallengeUtils;
use Anonympins\Fingerprint\Utils\BigInt;

final class PowTest extends TestCase
{
    private InMemoryStore $store;
    private FingerprintEngine $engine;
    private string $problemsConfigPath;

    protected function setUp(): void
    {
        // Utiliser un store en mémoire pour l'isolation des tests
        // @phpstan-ignore-next-line
        $this->store = new InMemoryStore();
        StoreManager::configureStore($this->store);

        $securityConfig = SecurityProfiles::createSecurityProfile('balanced', [
            'enableUsefulWork' => true,
            'usefulWorkConfigPath' => __DIR__ . '/problems.config.json',
            // FIX: Forcer les challenges à être retournés en JSON pour ce test.
            // Cela garantit que, que ce soit un uPoW ou un PoW standard qui soit émis,
            // le corps de la réponse sera un tableau et non une chaîne HTML.
            'isApiRequest' => fn($context) => true,
            'verbose' => false, // Garder les logs désactivés pour les tests
        ]);
        $this->engine = new FingerprintEngine($securityConfig);

        // Créer un fichier de configuration de problèmes temporaire
        $this->problemsConfigPath = __DIR__ . DIRECTORY_SEPARATOR . 'problems.config.json';

        // S'assurer que le ProblemManager est réinitialisé pour chaque test
        $this->resetProblemManager();
    }

    protected function tearDown(): void
    {
        // Nettoyer après le test pour ne pas affecter les autres
        $this->resetProblemManager();
    }

    private function resetProblemManager(): void
    {
        $reflection = new \ReflectionClass(ProblemManager::class);
        $instanceProp = $reflection->getProperty('instance');
        $instanceProp->setAccessible(true);
        $instanceProp->setValue(null, null);
    }

    public function testCpuTargetChallengeVerification(): void
    {
        $clientIp = '127.0.0.1';
        $nonce = 'test-nonce';
        $clientSecret = 'test-secret';
        $fingerprint = 'ua:Mozilla|os:Linux';

        $baseBlock = ChallengeUtils::createCpuChallengeBaseBlock($nonce, $clientSecret, $fingerprint);
        $target = ChallengeUtils::calculateCpuTarget(0.5, []); // Facteur de suspicion moyen

        $challengeContext = [
            'cpuTarget' => $target,
            'baseBlock' => $baseBlock,
        ];

        // Simuler la résolution côté client
        $solution = -1;
        $hashAsInt = null;
        $targetAsInt = BigInt::fromHex($target);

        do {
            $solution++;
            $finalBlock = $baseBlock . $solution;
            $hash = hash('sha256', $finalBlock);
            $hashAsInt = BigInt::fromHex($hash);
        } while ($hashAsInt->compareTo($targetAsInt) >= 0);

        $this->assertGreaterThanOrEqual(0, $solution, "La solution doit être un entier positif.");

        // Vérifier la solution côté serveur
        $ticket = ChallengeUtils::verifyCpuTargetPoWAndGenerateTicket(
            $clientIp,
            3600000,
            $nonce,
            (string)$solution,
            $challengeContext
        );

        $this->assertNotNull($ticket, "La vérification du PoW CPU a échoué, un ticket aurait dû être généré.");
        $this->assertTrue(ChallengeUtils::isTicketValid($clientIp, $ticket), "Le ticket généré est invalide.");
    }

    public function testMemoryPowVerification(): void
    {
        $nonce = 'test-mem-nonce';
        $clientSecret = 'test-mem-secret';
        $difficulty = 1; // 1MB pour un test rapide

        // Simuler la résolution côté client (logique portée depuis JS)
        $size = $difficulty * 1024 * 1024;
        $iterations = (int)floor($size / 16);
        $buffer = new \SplFixedArray((int)floor($size / 4));
        $seed = ":{$nonce}:{$clientSecret}";
        $h = 0;
        foreach (unpack('C*', $seed) as $byte) {
            $h += $byte;
        }
        for ($i = 0; $i < count($buffer); $i++) {
            // Utilisation de gmp_mul pour une multiplication 32-bit correcte
            $h = gmp_intval(gmp_mul(gmp_init($h ^ $i), gmp_init(1597334677)));
            $buffer[$i] = $h;
        }
        $finalHash = 0;
        $addr = count($buffer) > 0 ? $buffer[0] % count($buffer) : 0;
        for ($i = 0; $i < $iterations; $i++) {
            $addr = $buffer[$addr] % count($buffer);
            $finalHash ^= $addr;
        }
        $solution = (string)$finalHash;

        // Vérifier côté serveur
        $isValid = ChallengeUtils::verifyMemoryPoW($nonce, $solution, $difficulty, $clientSecret);

        $this->assertTrue($isValid, "La vérification du PoW Mémoire a échoué.");
    }

    public function testUsefulWorkDispatchAndIntegration(): void
    {
        $context = new RequestContext('1.2.3.4', '/test', [], [], null, [], '1.1');
        $context->body = ['query' => 'mutation { solveProblem }']; // Simuler une requête GraphQL

        // Simuler une requête suspecte pour déclencher un challenge uPoW
        $this->store->set('device:test-device-id', ['ips' => array_fill(0, 20, '1.1.1.1')]);
        $context->cookies['device_id'] = 'test-device-id';

        $decision = $this->engine->processRequest($context);

        $this->assertEquals('challenge', $decision['action']);
        $this->assertIsArray($decision['body']);
        $this->assertEquals('useful_work_task', $decision['body']['challenge']['type']);

        $problemId = $decision['body']['challenge']['usefulWorkTask']['problemId'];
        $this->assertEquals('problem-1', $problemId);

        // Simuler une solution de la part du client
        $solutionData = ['solution' => [1, 2, 3], 'energy' => 123.45];

        // Intégrer la solution
        $problemManager = ProblemManager::getInstance($this->problemsConfigPath, $this->store);
        $problemManager->integrateSolution($problemId, $solutionData);

        // Vérifier que la solution a été mise à jour dans le store
        $problemState = $this->store->get("problem-state:{$problemId}");
        $this->assertNotNull($problemState);
        // La fonction de score n'étant pas définie dans le JSON de test, l'énergie ne sera pas mise à jour.
        // On vérifie que la solution, elle, a été acceptée.
        $this->assertEquals($solutionData['solution'], $problemState['bestSolution']);
    }
}
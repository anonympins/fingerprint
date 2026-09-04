<?php

declare(strict_types=1);

namespace Anonympins\Fingerprint\Tests;

use Anonympins\Fingerprint\Optimization\FunctionRegistry;
use Anonympins\Fingerprint\ProblemManager;
use Anonympins\Fingerprint\Store\InMemoryStore;
use Anonympins\Fingerprint\Store\IStore;
use PHPUnit\Framework\TestCase;

// Assurez-vous que cette classe est autoloadable

class ProblemManagerTest extends TestCase
{
    private ?string $configPath = null;

    protected function setUp(): void
    {
        // Réinitialise le singleton avant chaque test pour garantir l'isolation
        ProblemManager::__internal_resetInstance();
        FunctionRegistry::__internal_resetRegistry(); // Assure un registre de fonctions propre
        $this->configPath = dirname(__FILE__).'/problems.config.json';
    }

    protected function tearDown(): void
    {
        ProblemManager::__internal_resetInstance();
        FunctionRegistry::__internal_resetRegistry();
    }

    private function createConfigFile(array $content): void
    {
        // S'assurer que le répertoire existe
        if (!is_dir(dirname($this->configPath))) {
            mkdir(dirname($this->configPath), 0777, true);
        }
        file_put_contents($this->configPath, json_encode($content, JSON_PRETTY_PRINT));
    }

    public function testGetInstanceThrowsExceptionIfNotInitialized(): void
    {
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('ProblemManager must be initialized with configPath and store.');
        ProblemManager::getInstance();
    }

    public function testGetInstanceCreatesAndReturnsInstance(): void
    {
        $storeMock = $this->createMock(IStore::class);

        $instance1 = ProblemManager::getInstance($this->configPath, $storeMock);
        $this->assertInstanceOf(ProblemManager::class, $instance1);

        // Les appels suivants doivent retourner la même instance
        $instance2 = ProblemManager::getInstance();
        $this->assertSame($instance1, $instance2);
        $this->assertTrue(ProblemManager::isInitialized());
    }

    public function testLoadProblemsHandlesMissingFile(): void
    {
        $storeMock = $this->createMock(IStore::class);
        $missingConfigPath = dirname(__FILE__).'/non_existent_config.json';
        if (file_exists($missingConfigPath)) {
            unlink($missingConfigPath); // S'assurer que le fichier n'existe pas
        }

        // Ne doit pas lever d'exception, mais simplement ne pas initialiser de problèmes
        $manager = ProblemManager::getInstance($missingConfigPath, $storeMock);
        $this->assertNull($manager->dispatchWork(0.5));
    }

    public function testDispatchWorkCyclesThroughProblems(): void
    {
        $storeMock = $this->createMock(IStore::class);
        $storeMock->method('get')->willReturn(null);

        // Créer un fichier de configuration avec plusieurs problèmes pour tester le cycle
        $this->createConfigFile([
            [
                "id" => "problem-1",
                "workUnit" => ["type" => "simulated_annealing_iterations", "baseIterations" => 10000, "scalingFactor" => 2.0]
            ],
            [
                "id" => "problem-2",
                "workUnit" => ["type" => "simulated_annealing_iterations", "baseIterations" => 20000]
            ],
            [
                "id" => "scaling-problem",
                "workUnit" => ["type" => "multi_objective_genetic_algorithm", "baseGenerations" => 100, "scalingFactor" => 2.0, "solverName" => "test.solver"]
            ],
            [
                "id" => "pareto-challenge",
                "workUnit" => ["type" => "multi_objective_genetic_algorithm", "solverName" => "test.solver"]
            ],
            [
                "id" => "problem-1",
                "workUnit" => ["type" => "simulated_annealing_iterations", "baseIterations" => 10000, "scalingFactor" => 2.0]
            ]
        ]);

        $manager = ProblemManager::getInstance($this->configPath, $storeMock);

        $work1 = $manager->dispatchWork(0.5);
        $this->assertEquals('problem-1', $work1['problemId']);

        $work2 = $manager->dispatchWork(0.5);
        $this->assertEquals('problem-2', $work2['problemId']);

        // Cycle through a few more times to ensure it loops
        $work3 = $manager->dispatchWork(0.5);
        $this->assertEquals('scaling-problem', $work3['problemId']);

        $work4 = $manager->dispatchWork(0.5);
        $this->assertEquals('pareto-challenge', $work4['problemId']);

        $work5 = $manager->dispatchWork(0.5);
        $this->assertEquals('problem-1', $work5['problemId']); // Back to the start
    }

    public function testDispatchWorkScalesDifficulty(): void
    {
        $storeMock = $this->createMock(IStore::class);
        $storeMock->method('get')->willReturn(null);

        $this->createConfigFile([
            [
                "id" => "problem-1",
                "workUnit" => ["type" => "simulated_annealing_iterations", "baseIterations" => 10000, "scalingFactor" => 2.0]
            ],
            [
                "id" => "problem-1",
                "workUnit" => ["type" => "simulated_annealing_iterations", "baseIterations" => 10000, "scalingFactor" => 2.0]
            ],
            [
                "id" => "scaling-problem",
                "workUnit" => ["type" => "multi_objective_genetic_algorithm", "baseGenerations" => 100, "scalingFactor" => 2.0, "solverName" => "test.solver"]
            ]
        ]);

        $manager = ProblemManager::getInstance($this->configPath, $storeMock);

        // Facteur de suspicion faible
        $workLow = $manager->dispatchWork(0.1);
        $this->assertLessThan(12000, $workLow['task']['iterations']); // 10000 * 2^0.1 ≈ 10717

        // Facteur de suspicion moyen - dispatch 'problem-1'
        $workMedium = $manager->dispatchWork(0.5);
        $this->assertEquals(14142, $workMedium['task']['iterations']); // 10000 * 2^0.5

        // Facteur de suspicion élevé - dispatch 'scaling-problem'
        $workHigh = $manager->dispatchWork(1.0);
        $this->assertEquals(200, $workHigh['task']['generations']); // 100 * 2^1.0
    }

    public function testIntegrateSolutionUpdatesStateForBetterSolution(): void
    {
        $problemId = 'problem-1';

        $storeMock = $this->createMock(IStore::class);

        $this->createConfigFile([
            [
                "id" => $problemId,
                "workUnit" => [
                    "type" => "simulated_annealing_iterations", // @phpstan-ignore-line
                    "baseIterations" => 10000,
                    // **LA CORRECTION** : La fonction de score est requise pour la vérification.
                    "scoreFunction" => "test.calculateEnergy"
                ]
            ]
        ]);

        // Enregistrer une fonction de score factice pour le test.
        FunctionRegistry::register('test.calculateEnergy', function ($solution, $payload) { // @phpstan-ignore-line
            return 800.0; // Retourne la nouvelle "meilleure" énergie attendue.
        });

        $storeMock->method('get')
            ->with("problem-state:{$problemId}")
            ->willReturn(['bestEnergy' => 1000.0]);

        // On s'attend à ce que le store soit mis à jour avec la nouvelle meilleure solution
        $storeMock->expects($this->once())
            ->method('set')
            ->with(
                "problem-state:{$problemId}",
                $this->callback(function ($state) {
                    return isset($state['bestEnergy']) && $state['bestEnergy'] === 800.0 && isset($state['bestSolution']);
                })
            );

        $manager = ProblemManager::getInstance($this->configPath, $storeMock);

        $newSolution = [
            'solution' => [1, 2, 3],
            'energy' => 800.0 // C'est une meilleure solution (score plus bas)
        ];
        $manager->integrateSolution($problemId, $newSolution);
    }

    public function testIntegrateSolutionDoesNotUpdateStateForWorseSolution(): void
    {
        $problemId = 'problem-1';

        $storeMock = $this->createMock(IStore::class);

        $this->createConfigFile([
            [
                "id" => $problemId,
                "workUnit" => [
                    "type" => "simulated_annealing_iterations", // @phpstan-ignore-line
                    "baseIterations" => 10000,
                    "scoreFunction" => "test.calculateEnergy"
                ]
            ]
        ]);

        // La fonction de score factice retourne une énergie *pire* que celle existante. // @phpstan-ignore-line
        FunctionRegistry::register('test.calculateEnergy', function ($solution, $payload) {
            return 1200.0;
        });

        $storeMock->method('get') // @phpstan-ignore-line
            ->with("problem-state:{$problemId}")
            ->willReturn(['bestEnergy' => 1000.0]);

        // On s'attend à ce que `set` ne soit JAMAIS appelé car la solution n'est pas meilleure
        $storeMock->expects($this->never())->method('set');

        $manager = ProblemManager::getInstance($this->configPath, $storeMock);

        $worseSolution = [
            'solution' => [3, 2, 1], // Le contenu de la solution n'a pas d'importance pour ce test
            'energy' => 1200.0 // C'est une moins bonne solution
        ];
        $manager->integrateSolution($problemId, $worseSolution);
    }

    public function testIntegrateParetoFront(): void
    {
        $problemId = 'pareto-challenge';

        $storeMock = $this->createMock(IStore::class);

        $this->createConfigFile([
            [
                "id" => "pareto-challenge",
                "workUnit" => ["type" => "multi_objective_genetic_algorithm", "solverName" => "test.solver"]
            ]
        ]);
        // Simule le comportement réel : le store contient déjà l'état initial.
        $initialState = ['paretoFront' => [['solution' => 'A', 'objectives' => [10, 20]]]];
        $storeMock->method('get')
            ->with("problem-state:{$problemId}")
            ->willReturn($initialState);

        // A new solution that dominates the existing one.
        $newFront = [['solution' => 'B', 'objectives' => [5, 15]]];

        $storeMock->expects($this->once())
            ->method('set')
            ->with(
                "problem-state:{$problemId}",
                $this->callback(function ($state) {
                    // The new front should contain only the new, dominant solution 'B'.
                    return isset($state['paretoFront']) && count($state['paretoFront']) === 1 && $state['paretoFront'][0]['solution'] === 'B';
                })
            );

        $manager = ProblemManager::getInstance($this->configPath, $storeMock);
        $manager->integrateSolution($problemId, ['paretoFront' => $newFront]);
    }

    public function testLoadProblemsFromStore(): void
    {
        $store = new InMemoryStore();
        $problemId = 'problem-1';

        $this->createConfigFile([
            [
                "id" => "problem-1",
                "workUnit" => ["type" => "simulated_annealing_iterations", "baseIterations" => 10000]
            ]
        ]);
        $initialState = ['bestEnergy' => 5000.0, 'bestSolution' => [1, 2, 3]];
        $store->set("problem-state:{$problemId}", $initialState);

        $manager = ProblemManager::getInstance($this->configPath, $store);
        $work = $manager->dispatchWork(0.1); // Dispatch 'problem-1'

        $this->assertEquals($problemId, $work['problemId']);
        $this->assertEquals($initialState['bestSolution'], $work['task']['initialSolution']);
    }
}
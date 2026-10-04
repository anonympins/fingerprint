<?php

declare(strict_types=1);

namespace Anonympins\Fingerprint\Tests;

use Anonympins\Fingerprint\AutoTuner;
use PHPUnit\Framework\TestCase;

class AutoTunerTest extends TestCase
{
    private string $tempDir;

    protected function setUp(): void
    {
        parent::setUp();
        $this->tempDir = sys_get_temp_dir() . '/autotuner_test_' . uniqid();
        mkdir($this->tempDir, 0777, true);
    }

    protected function tearDown(): void
    {
        if (is_dir($this->tempDir)) {
            $files = glob($this->tempDir . '/*') ?: [];
            foreach ($files as $file) {
                if (is_file($file)) {
                    unlink($file);
                }
            }
            rmdir($this->tempDir);
        }
        parent::tearDown();
    }

    public function testSavePathRejectsNonJsonFiles(): void
    {
        $config = [];
        $data = [];
        $tuner = new AutoTuner($config, $data, [
            'savePath' => $this->tempDir . '/malicious.php',
        ]);

        $reflection = new \ReflectionClass($tuner);
        $method = $reflection->getMethod('validateAndResolveSavePath');
        $method->setAccessible(true);

        $result = $method->invoke($tuner, $this->tempDir . '/malicious.php');
        $this->assertNull($result);
    }

    public function testSavePathRejectsNullByteInjection(): void
    {
        $config = [];
        $data = [];
        $tuner = new AutoTuner($config, $data);

        $reflection = new \ReflectionClass($tuner);
        $method = $reflection->getMethod('validateAndResolveSavePath');
        $method->setAccessible(true);

        $result = $method->invoke($tuner, $this->tempDir . "/file.json\0.php");
        $this->assertNull($result);
    }

    public function testSavePathRejectsPathTraversalOutsideAllowedDir(): void
    {
        $config = [];
        $data = [];
        $tuner = new AutoTuner($config, $data);

        $reflection = new \ReflectionClass($tuner);
        $method = $reflection->getMethod('validateAndResolveSavePath');
        $method->setAccessible(true);

        $result = $method->invoke($tuner, $this->tempDir . '/../escaped.json');
        $this->assertNull($result);
    }

    public function testSavePathAcceptsValidJsonPath(): void
    {
        $config = [];
        $data = [];
        $validPath = $this->tempDir . '/valid-config.json';
        $tuner = new AutoTuner($config, $data, [
            'savePath' => $validPath,
        ]);

        $reflection = new \ReflectionClass($tuner);
        $method = $reflection->getMethod('validateAndResolveSavePath');
        $method->setAccessible(true);

        $result = $method->invoke($tuner, $validPath);
        $this->assertNotNull($result);
        $this->assertStringEndsWith('valid-config.json', str_replace('\\', '/', $result));
    }
}
<?php

declare(strict_types=1);

namespace Anonympins\Fingerprint\Tests;

use Anonympins\Fingerprint\FingerprintBuilder;
use PHPUnit\Framework\TestCase;

class FingerprintBuilderTest extends TestCase
{
    public function testCyrb53IsDeterministic(): void
    {
        $input = "test-string";
        // Note: The PHP and JS implementations of cyrb53 produce different hash strings
        // due to differences in large number handling, but they are internally consistent.
        $this->assertEquals(FingerprintBuilder::cyrb53($input), FingerprintBuilder::cyrb53($input));
        $this->assertNotEquals(FingerprintBuilder::cyrb53("a"), FingerprintBuilder::cyrb53("b"));
    }

    public function testBuilderHandlesNullAndEmptyValues(): void
    {
        $builder = new FingerprintBuilder();
        $builder->add('key1', 'value1');
        $builder->add('key2', null);
        $builder->add('key3', '');

        // The JS equivalent for this hash is '6263243896157005'
        $this->assertEquals('key1:6263243896157005', (string)$builder);
    }

    public function testToStringSortsKeysDeterministically(): void
    {
        $builder1 = new FingerprintBuilder();
        $builder1->add('b', '2')->add('a', '1');

        $builder2 = new FingerprintBuilder();
        $builder2->add('a', '1')->add('b', '2');

        $this->assertEquals((string)$builder1, (string)$builder2);
    }

    public function testCompareLogic(): void
    {
        $fp1 = (new FingerprintBuilder())->add('hw', '8_16')->add('gpu', 'nvidia')->__toString();
        $fp2 = (new FingerprintBuilder())->add('hw', '8_16')->add('gpu', 'nvidia')->__toString();
        $fp3 = (new FingerprintBuilder())->add('hw', '4_8')->add('gpu', 'amd')->__toString();
        $fp4 = (new FingerprintBuilder())->add('hw', '8_16')->add('os', 'win32')->__toString(); // Partial match

        $this->assertEquals(1.0, FingerprintBuilder::compare($fp1, $fp2), "Identical FPs should return 1.0");
        $this->assertEquals(0.0, FingerprintBuilder::compare($fp1, $fp3), "Completely different FPs should have a score of 0");
        
        $this->assertEqualsWithDelta(0.25, FingerprintBuilder::compare($fp1, $fp4), 0.2, "Partial match should have a specific score");
        
        $this->assertEquals(0.0, FingerprintBuilder::compare($fp1, ''), "Comparison with empty string should be 0.0");
        $this->assertEquals(0.0, FingerprintBuilder::compare(null, $fp2), "Comparison with null should be 0.0");
    }
}
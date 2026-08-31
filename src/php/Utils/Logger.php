<?php

declare(strict_types=1);

namespace Anonympins\Fingerprint\Utils;

/**
 * Un simple wrapper de logger pour passer les données à une fonction de rappel.
 */
class Logger
{
    /**
     * @var callable
     */
    private $callback;

    public function __construct(callable $callback)
    {
        $this->callback = $callback;
    }

    public function log(string $level, string $type, array $data): void
    {
        $logEntry = array_merge($data, [
            'type' => $type,
            'timestamp' => (int)floor(microtime(true) * 1000),
        ]);
        ($this->callback)($logEntry);
    }
}
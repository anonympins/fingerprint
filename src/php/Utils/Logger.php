<?php

declare(strict_types=1);

namespace Anonympins\Fingerprint\Utils;

/**
 * A simple logger wrapper to forward data to a callback function.
 */
class Logger
{
    /**
     * @var callable
     */
    private $callback;

    /**
     * Creates a new Logger instance with the given callback.
     * The callback will be invoked with a single log entry array argument
     * each time `log()` is called.
     *
     * @param callable $callback The callback used to process log entries.
     */
    public function __construct(callable $callback)
    {
        $this->callback = $callback;
    }

    /**
     * Emits a log entry by merging the provided data with a type and a
     * millisecond-precision timestamp, then forwarding it to the callback.
     * Note: the `$level` parameter is currently accepted but not included
     * in the emitted log entry.
     *
     * @param string $level The log level (e.g. "info", "warning", "error").
     * @param string $type The log entry type/category.
     * @param array $data Additional data to include in the log entry.
     * @return void
     */
    public function log(string $level, string $type, array $data): void
    {
        $logEntry = array_merge($data, [
            'type' => $type,
            'timestamp' => (int)floor(microtime(true) * 1000),
        ]);
        ($this->callback)($logEntry);
    }
}
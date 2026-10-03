<?php

declare(strict_types=1);

namespace Anonympins\Fingerprint\Crdt;

/**
 * CRDT LWW-Element-Set (Last-Write-Wins Element Set).
 * Résolution de réplication optimiste sans conflit pour les pools de Threat Intelligence et Whitelists.
 */
class LwwElementSet
{
    /** @var array<string, array{key: string, addTs: int, remTs: int, ttlMs: int}> */
    private array $elements = [];

    public function add(string $key, int $timestamp, int $ttlMs = 0): void
    {
        if (!isset($this->elements[$key])) {
            $this->elements[$key] = [
                'key' => $key,
                'addTs' => $timestamp,
                'remTs' => 0,
                'ttlMs' => $ttlMs,
            ];
        } elseif ($timestamp > $this->elements[$key]['addTs']) {
            $this->elements[$key]['addTs'] = $timestamp;
            $this->elements[$key]['ttlMs'] = $ttlMs;
        }
    }

    public function remove(string $key, int $timestamp): void
    {
        if (!isset($this->elements[$key])) {
            $this->elements[$key] = [
                'key' => $key,
                'addTs' => 0,
                'remTs' => $timestamp,
                'ttlMs' => 0,
            ];
        } elseif ($timestamp > $this->elements[$key]['remTs']) {
            $this->elements[$key]['remTs'] = $timestamp;
        }
    }

    public function contains(string $key, ?int $now = null): bool
    {
        if (!isset($this->elements[$key])) {
            return false;
        }
        $rec = $this->elements[$key];
        if ($rec['addTs'] <= $rec['remTs']) {
            return false;
        }
        $currentTime = $now ?? (int)(microtime(true) * 1000);
        return $rec['ttlMs'] <= 0 || ($currentTime < $rec['addTs'] + $rec['ttlMs']);
    }

    /**
     * @return array<string>
     */
    public function getActiveElements(?int $now = null): array
    {
        $currentTime = $now ?? (int)(microtime(true) * 1000);
        $active = [];
        foreach ($this->elements as $key => $rec) {
            if ($rec['addTs'] > $rec['remTs'] && ($rec['ttlMs'] <= 0 || $currentTime < $rec['addTs'] + $rec['ttlMs'])) {
                $active[] = $key;
            }
        }
        return $active;
    }

    /**
     * @return array<int, array{key: string, addTs: int, remTs: int, ttlMs: int}>
     */
    public function exportDelta(): array
    {
        return array_values($this->elements);
    }

    /**
     * @param array<int, array<string, mixed>> $delta
     */
    public function mergeDelta(array $delta): void
    {
        foreach ($delta as $entry) {
            $key = (string)($entry['key'] ?? '');
            if ($key === '') {
                continue;
            }
            $addTs = (int)($entry['addTs'] ?? 0);
            $remTs = (int)($entry['remTs'] ?? 0);
            $ttlMs = (int)($entry['ttlMs'] ?? 0);

            if (!isset($this->elements[$key])) {
                $this->elements[$key] = [
                    'key' => $key,
                    'addTs' => $addTs,
                    'remTs' => $remTs,
                    'ttlMs' => $ttlMs,
                ];
            } else {
                if ($addTs > $this->elements[$key]['addTs']) {
                    $this->elements[$key]['addTs'] = $addTs;
                    $this->elements[$key]['ttlMs'] = $ttlMs;
                }
                if ($remTs > $this->elements[$key]['remTs']) {
                    $this->elements[$key]['remTs'] = $remTs;
                }
            }
        }
    }

    public function pruneExpired(?int $now = null, int $maxTombstoneAgeMs = 7 * 86400 * 1000): void
    {
        $currentTime = $now ?? (int)(microtime(true) * 1000);
        foreach ($this->elements as $key => $rec) {
            $isExpired = $rec['ttlMs'] > 0 && ($currentTime >= $rec['addTs'] + $rec['ttlMs']);
            $isOldTombstone = $rec['remTs'] > 0 && ($currentTime - $rec['remTs'] > $maxTombstoneAgeMs);
            if ($isExpired || $isOldTombstone) {
                unset($this->elements[$key]);
            }
        }
    }

    public function count(): int
    {
        return count($this->elements);
    }

    public function clear(): void
    {
        $this->elements = [];
    }
}
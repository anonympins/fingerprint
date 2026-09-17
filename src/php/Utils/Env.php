<?php

declare(strict_types=1);

namespace Anonympins\Fingerprint\Utils;

class Env
{
    /** @var array<string, mixed> */
    private static array $localCache = [];

    /**
     * @param string $key
     * @param mixed $default
     * @return mixed
     */
    public static function get(string $key, $default = null)
    {
        if (array_key_exists($key, self::$localCache)) {
            return self::$localCache[$key];
        }
        if (isset($_ENV[$key]) && $_ENV[$key] !== '') {
            return $_ENV[$key];
        }
        if (isset($_SERVER[$key]) && $_SERVER[$key] !== '') {
            return $_SERVER[$key];
        }
        $val = getenv($key);
        if ($val !== false && $val !== '') {
            return $val;
        }
        return $default;
    }

    public static function set(string $key, $value): void
    {
        self::$localCache[$key] = $value;
        $_ENV[$key] = $value;
        $_SERVER[$key] = $value;
        @putenv("{$key}={$value}");
    }

    public static function clear(string $key): void
    {
        unset(self::$localCache[$key]);
        unset($_ENV[$key]);
        unset($_SERVER[$key]);
        @putenv($key);
    }
}
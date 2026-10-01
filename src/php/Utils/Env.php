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
        // phpcs:disable WordPress.Security.ValidatedSanitizedInput.InputNotSanitized,WordPress.Security.ValidatedSanitizedInput.MissingUnslash -- Environment and server variables may contain raw cryptographic keys.
        if (isset($_ENV[$key]) && $_ENV[$key] !== '') {
            $envVal = function_exists('wp_unslash') ? wp_unslash($_ENV[$key]) : $_ENV[$key];
            return is_string($envVal) ? (function_exists('sanitize_textarea_field') ? sanitize_textarea_field($envVal) : $envVal) : $envVal;
        }
        if (isset($_SERVER[$key]) && $_SERVER[$key] !== '') {
            $serverVal = function_exists('wp_unslash') ? wp_unslash($_SERVER[$key]) : $_SERVER[$key];
            if (is_string($serverVal)) {
                return function_exists('sanitize_textarea_field') ? sanitize_textarea_field($serverVal) : $serverVal;
            }
            return $serverVal;
        }
        // phpcs:enable WordPress.Security.ValidatedSanitizedInput.InputNotSanitized,WordPress.Security.ValidatedSanitizedInput.MissingUnslash
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
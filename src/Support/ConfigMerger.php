<?php

namespace Siberfx\RiskAnalyzer\Support;

/**
 * Fills keys missing from a published config with the package defaults.
 * Nested sections are merged key by key; lists (paths, patterns...) are
 * taken from the published config as a whole so they can be shortened.
 */
final class ConfigMerger
{
    /**
     * @param  array<array-key, mixed>  $defaults
     * @param  array<array-key, mixed>  $published
     * @return array<array-key, mixed>
     */
    public static function merge(array $defaults, array $published): array
    {
        foreach ($published as $key => $value) {
            $default = $defaults[$key] ?? null;

            $defaults[$key] = is_array($default) && is_array($value) && ! array_is_list($default) && ! array_is_list($value)
                ? self::merge($default, $value)
                : $value;
        }

        return $defaults;
    }
}

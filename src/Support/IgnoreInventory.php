<?php

namespace Siberfx\RiskAnalyzer\Support;

use Illuminate\Routing\Route;
use Siberfx\RiskAnalyzer\ScanContext;

/**
 * Every active ignore in a project, with its reason: config entries, route
 * attributes and inline "risk-analyzer-ignore" comments. Each entry has a
 * key that identifies it without line numbers or secret values, so a committed
 * snapshot only changes when an ignore is added or removed.
 */
final class IgnoreInventory
{
    private const string INLINE = '/risk-analyzer-ignore\b(.*)$/i';

    private const string RULE_ID = '/^[a-z0-9]+(-[a-z0-9]+)*$/';

    /**
     * @return list<array{kind: string, where: string, target: string, rules: list<string>, reason: ?string, key: string}>
     */
    public static function collect(ScanContext $context): array
    {
        $entries = [];

        // config/risk-analyzer.php: a key => reason pair, or a bare pattern.
        foreach ((array) $context->config('routes.ignore', []) as $key => $value) {
            $pattern = trim((string) (is_string($key) ? $key : $value), '/');
            $entries[] = self::entry('route-config', 'risk-analyzer.php (routes.ignore)', $pattern, ['unprotected-route'], is_string($key) ? (string) $value : null);
        }

        foreach ((array) $context->config('dependencies.ignore', []) as $advisory) {
            $entries[] = self::entry('dependency', 'risk-analyzer.php (dependencies.ignore)', (string) $advisory, ['vulnerable-dependency'], null);
        }

        // Secret values are hashed in the key and masked in the output: a snapshot must not store them.
        foreach ((array) $context->config('secrets.allow', []) as $value) {
            $value = (string) $value;
            $masked = strlen($value) > 6 ? substr($value, 0, 4).'…' : '…';
            $entries[] = self::entry('secret', 'risk-analyzer.php (secrets.allow)', $masked, [], null, hash('sha256', $value));
        }

        foreach ((array) $context->config('rules.disabled', []) as $rule) {
            $entries[] = self::entry('rule', 'risk-analyzer.php (rules.disabled)', (string) $rule, ['all'], null);
        }

        if ($context->isLaravel()) {
            foreach ($context->router()->getRoutes()->getRoutes() as $route) {
                foreach (RouteInspector::ignoreAttributes($route) as $attribute) {
                    $source = RouteInspector::source($route);
                    $where = $source === null ? 'route' : $context->relative($source[0]).':'.$source[1];

                    $entries[] = self::entry('route-attribute', $where, implode('|', $route->methods()).' '.$route->uri(),
                        $attribute->rules, $attribute->reason);
                }
            }
        }

        foreach (self::files($context) as $file) {
            foreach ((array) preg_split('/\R/', (string) $context->read($file)) as $index => $line) {
                $line = (string) $line;

                if (! preg_match(self::INLINE, $line, $match)) {
                    continue;
                }

                [$rules, $reason] = self::inlineParts($match[1]);
                $entries[] = self::entry('inline', "{$file}:".($index + 1), $file, $rules, $reason);
            }
        }

        return $entries;
    }

    /**
     * Entries in $current that $snapshot does not already list (matched by key, as many times as they appear).
     *
     * @param  list<array<string, mixed>>  $current
     * @param  array<mixed>  $snapshot  a decoded snapshot file; entries without a string key never match
     * @return list<array<string, mixed>>
     */
    public static function added(array $current, array $snapshot): array
    {
        $known = array_count_values(array_map(fn (mixed $entry) => is_array($entry) ? (string) ($entry['key'] ?? '') : '', $snapshot));
        $added = [];

        foreach ($current as $entry) {
            if (($known[$entry['key']] ?? 0) > 0) {
                $known[$entry['key']]--;

                continue;
            }

            $added[] = $entry;
        }

        return $added;
    }

    /**
     * @param  list<string>  $rules  empty or ['all'] for every rule
     * @return array{kind: string, where: string, target: string, rules: list<string>, reason: ?string, key: string}
     */
    private static function entry(string $kind, string $where, string $target, array $rules, ?string $reason, ?string $keyTarget = null): array
    {
        $rules = $rules === [] || in_array('all', $rules, true) ? ['all'] : array_values(array_unique($rules));
        sort($rules);

        return [
            'kind' => $kind,
            'where' => $where,
            'target' => $target,
            'rules' => $rules,
            'reason' => $reason === null || trim($reason) === '' ? null : trim($reason),
            'key' => implode('|', [$kind, $keyTarget ?? $target, implode(',', $rules)]),
        ];
    }

    /**
     * @return array{0: list<string>, 1: ?string} rule ids and reason from the text after "risk-analyzer-ignore"
     */
    private static function inlineParts(string $text): array
    {
        $parts = explode('--', $text, 2);
        $ids = array_values(array_filter(
            preg_split('/[\s,:]+/', strtolower($parts[0])) ?: [],
            fn (string $id) => preg_match(self::RULE_ID, $id) === 1,
        ));

        // Blade comments end in --}}, block comments in */ (or */} in JSX), HTML comments in -->.
        $reason = isset($parts[1]) ? preg_replace('/(\*\/\}?|-->|--\}\})\s*$/', '', $parts[1]) : null;

        return [$ids === [] || in_array('all', $ids, true) ? [] : $ids, $reason];
    }

    /**
     * Source files that can hold inline ignores: PHP and Blade, frontend and infrastructure files.
     *
     * @return list<string>
     */
    private static function files(ScanContext $context): array
    {
        $files = [...$context->files(['.php']), ...$context->frontendFiles(), ...$context->infrastructureFiles()];

        return array_values(array_unique($files));
    }
}

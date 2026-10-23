<?php

namespace Siberfx\RiskAnalyzer\Support;

use Composer\Semver\Comparator;
use Illuminate\Contracts\Cache\Repository as Cache;
use Illuminate\Http\Client\Factory as Http;
use Illuminate\Http\Client\Pool;
use Illuminate\Http\Client\Response;
use RuntimeException;
use Siberfx\RiskAnalyzer\Severity;

/**
 * Minimal client for the OSV.dev API (https://google.github.io/osv.dev/api/).
 */
final class OsvClient
{
    private const int BATCH_SIZE = 500;

    public function __construct(
        private readonly Http $http,
        private readonly ?Cache $cache,
        private readonly string $endpoint = 'https://api.osv.dev',
        private readonly int $timeout = 15,
        private readonly int $ttl = 21600,
    ) {}

    /**
     * Advisories affecting each package, keyed like the input.
     *
     * @param  array<string, array{ecosystem: string, name: string, version: string}>  $packages
     * @return array<string, list<array{id: string, aliases: list<string>, summary: string, severity: Severity, fixed: ?string, url: string}>>
     */
    public function vulnerabilities(array $packages): array
    {
        $ids = $this->query($packages);
        $details = $this->details(array_values(array_unique(array_merge(...array_values($ids ?: [[]])))));
        $results = [];

        foreach ($ids as $key => $vulnIds) {
            foreach ($vulnIds as $id) {
                if (isset($details[$id])) {
                    $results[$key][] = $this->summarise($details[$id], $packages[$key]);
                }
            }
        }

        return $results;
    }

    /**
     * @param  array<string, array{ecosystem: string, name: string, version: string}>  $packages
     * @return array<string, list<string>>
     */
    private function query(array $packages): array
    {
        $ids = [];
        $pending = [];

        foreach ($packages as $key => $package) {
            $cached = $this->cache?->get($this->cacheKey('q', $package['ecosystem'].'|'.$package['name'].'|'.$package['version']));

            if (is_array($cached)) {
                if ($cached !== []) {
                    $ids[$key] = array_values(array_filter($cached, is_string(...)));
                }
            } else {
                $pending[$key] = $package;
            }
        }

        foreach (array_chunk($pending, self::BATCH_SIZE, preserve_keys: true) as $chunk) {
            $response = $this->http->timeout($this->timeout)->acceptJson()->post($this->endpoint.'/v1/querybatch', [
                'queries' => array_map(fn (array $package) => [
                    'package' => ['ecosystem' => $package['ecosystem'], 'name' => $package['name']],
                    'version' => $package['version'],
                ], array_values($chunk)),
            ]);

            if (! $response->successful()) {
                throw new RuntimeException("OSV query failed with HTTP {$response->status()}.");
            }

            $results = (array) $response->json('results', []);

            foreach (array_keys($chunk) as $index => $key) {
                $found = [];

                foreach ((array) ($results[$index]['vulns'] ?? []) as $vuln) {
                    if (is_array($vuln) && is_string($vuln['id'] ?? null)) {
                        $found[] = $vuln['id'];
                    }
                }

                $package = $chunk[$key];
                $this->cache?->put($this->cacheKey('q', $package['ecosystem'].'|'.$package['name'].'|'.$package['version']), $found, $this->ttl);

                if ($found !== []) {
                    $ids[$key] = $found;
                }
            }
        }

        return $ids;
    }

    /**
     * @param  list<string>  $ids
     * @return array<string, array<string, mixed>>
     */
    private function details(array $ids): array
    {
        $details = [];
        $missing = [];

        foreach ($ids as $id) {
            $cached = $this->cache?->get($this->cacheKey('v', $id));

            is_array($cached) ? $details[$id] = $cached : $missing[] = $id;
        }

        foreach (array_chunk($missing, 20) as $chunk) {
            $responses = $this->http->pool(fn (Pool $pool) => array_map(
                fn (string $id) => $pool->as($id)->timeout($this->timeout)->acceptJson()->get($this->endpoint.'/v1/vulns/'.rawurlencode($id)),
                $chunk,
            ));

            foreach ($responses as $id => $response) {
                if ($response instanceof Response && $response->successful()) {
                    $details[$id] = (array) $response->json();
                    $this->cache?->put($this->cacheKey('v', (string) $id), $details[$id], $this->ttl);
                }
            }
        }

        return $details;
    }

    /**
     * @param  array<string, mixed>  $vuln
     * @param  array{ecosystem: string, name: string, version: string}  $package
     * @return array{id: string, aliases: list<string>, summary: string, severity: Severity, fixed: ?string, url: string}
     */
    private function summarise(array $vuln, array $package): array
    {
        $id = (string) $vuln['id'];
        $aliases = array_values(array_filter((array) ($vuln['aliases'] ?? []), 'is_string'));
        $preferred = array_find([$id, ...$aliases], fn (string $alias) => str_starts_with($alias, 'GHSA-')) ?? $id;

        return [
            'id' => $id,
            'aliases' => $aliases,
            'summary' => trim((string) ($vuln['summary'] ?? $vuln['details'] ?? 'No summary provided.')),
            'severity' => $this->severity($vuln),
            'fixed' => $this->fixedVersion($vuln, $package),
            'url' => str_starts_with($preferred, 'GHSA-') ? "https://github.com/advisories/{$preferred}" : "https://osv.dev/vulnerability/{$id}",
        ];
    }

    /**
     * @param  array<string, mixed>  $vuln
     */
    private function severity(array $vuln): Severity
    {
        $label = strtoupper((string) ($vuln['database_specific']['severity'] ?? ''));

        $severity = match ($label) {
            'CRITICAL' => Severity::Critical,
            'HIGH' => Severity::High,
            'MODERATE', 'MEDIUM' => Severity::Medium,
            'LOW' => Severity::Low,
            default => null,
        };

        if ($severity !== null) {
            return $severity;
        }

        // Fall back to the CVSS base score when the database gives one.
        foreach ((array) ($vuln['severity'] ?? []) as $entry) {
            $score = $entry['score'] ?? null;

            if (is_numeric($score)) {
                return match (true) {
                    $score >= 9 => Severity::Critical,
                    $score >= 7 => Severity::High,
                    $score >= 4 => Severity::Medium,
                    default => Severity::Low,
                };
            }
        }

        return Severity::Medium;
    }

    /**
     * Lowest "fixed" version above the installed one.
     *
     * @param  array<string, mixed>  $vuln
     * @param  array{ecosystem: string, name: string, version: string}  $package
     */
    private function fixedVersion(array $vuln, array $package): ?string
    {
        $candidates = [];

        foreach ((array) ($vuln['affected'] ?? []) as $affected) {
            if (strcasecmp((string) ($affected['package']['name'] ?? ''), $package['name']) !== 0) {
                continue;
            }

            foreach ((array) ($affected['ranges'] ?? []) as $range) {
                foreach ((array) ($range['events'] ?? []) as $event) {
                    $fixed = isset($event['fixed']) ? ltrim((string) $event['fixed'], 'v') : null;

                    if ($fixed !== null && $this->greaterThan($fixed, $package['version'])) {
                        $candidates[] = $fixed;
                    }
                }
            }
        }

        usort($candidates, fn ($a, $b) => $this->greaterThan($a, $b) ? 1 : -1);

        return $candidates[0] ?? null;
    }

    private function greaterThan(string $a, string $b): bool
    {
        try {
            return Comparator::greaterThan($a, $b);
        } catch (\Throwable) {
            return version_compare($a, $b, '>');
        }
    }

    private function cacheKey(string $type, string $value): string
    {
        return 'risk-analyzer:osv:'.$type.':'.sha1($value);
    }
}

<?php

namespace Siberfx\RiskAnalyzer\Support;

use Illuminate\Contracts\Cache\Repository as Cache;
use Illuminate\Http\Client\Factory as Http;
use Throwable;

/**
 * Support dates from endoflife.date (https://endoflife.date/docs/api/v1/) and
 * PHP releases from php.net. Every method returns null when the data cannot
 * be fetched, so callers fall back to their built-in tables.
 */
final class EndOfLifeClient
{
    public function __construct(
        private readonly Http $http,
        private readonly ?Cache $cache,
        private readonly string $endpoint = 'https://endoflife.date',
        private readonly string $phpEndpoint = 'https://www.php.net',
        private readonly int $timeout = 10,
        private readonly int $ttl = 86400,
    ) {}

    /**
     * Last day of security support per release cycle, e.g. ['8.4' => '2028-12-31'].
     *
     * @return array<array-key, string>|null
     */
    public function endOfSupport(string $product): ?array
    {
        $dates = $this->remember('eol:'.$product, function () use ($product): ?array {
            $response = $this->http->timeout($this->timeout)->acceptJson()->get("{$this->endpoint}/api/v1/products/".rawurlencode($product));

            if (! $response->successful()) {
                return null;
            }

            $dates = [];

            foreach ((array) $response->json('result.releases', []) as $release) {
                if (is_array($release) && isset($release['name']) && is_string($release['eolFrom'] ?? null)) {
                    $dates[(string) $release['name']] = $release['eolFrom'];
                }
            }

            return $dates === [] ? null : $dates;
        });

        return $dates === null ? null : array_filter($dates, 'is_string');
    }

    /**
     * Releases of a PHP branch, newest first, with whether each one fixed security issues.
     *
     * @return array<array-key, bool>|null e.g. ['8.4.27' => true, '8.4.25' => false]
     */
    public function phpReleases(string $branch): ?array
    {
        $releases = $this->remember('php:'.$branch, function () use ($branch): ?array {
            $response = $this->http->timeout($this->timeout)->acceptJson()
                ->get("{$this->phpEndpoint}/releases/index.php", ['json' => '', 'version' => $branch, 'max' => 100]);

            if (! $response->successful() || ! is_array($response->json())) {
                return null;
            }

            $releases = [];

            foreach ((array) $response->json() as $version => $release) {
                if (is_string($version) && str_starts_with($version, $branch.'.') && is_array($release)) {
                    $releases[$version] = in_array('security', (array) ($release['tags'] ?? []), true);
                }
            }

            uksort($releases, fn (string $a, string $b) => version_compare($b, $a));

            return $releases === [] ? null : $releases;
        });

        return $releases === null ? null : array_map(fn (mixed $security) => $security === true, $releases);
    }

    /**
     * @param  callable(): (array<mixed>|null)  $fetch
     * @return array<mixed>|null
     */
    private function remember(string $key, callable $fetch): ?array
    {
        $key = 'risk-analyzer:eol:'.sha1($this->endpoint.'|'.$this->phpEndpoint.'|'.$key);
        $cached = $this->cache?->get($key);

        if (is_array($cached)) {
            return $cached;
        }

        try {
            $value = $fetch();
        } catch (Throwable) {
            return null;
        }

        if ($value !== null) {
            $this->cache?->put($key, $value, $this->ttl);
        }

        return $value;
    }
}

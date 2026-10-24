<?php

namespace Siberfx\RiskAnalyzer\Rules\Dependencies;

use Composer\Semver\VersionParser;
use Illuminate\Contracts\Cache\Factory as CacheFactory;
use Illuminate\Http\Client\Factory as Http;
use Illuminate\Support\Carbon;
use Siberfx\RiskAnalyzer\Category;
use Siberfx\RiskAnalyzer\Finding;
use Siberfx\RiskAnalyzer\Rules\AbstractProjectRule;
use Siberfx\RiskAnalyzer\ScanContext;
use Siberfx\RiskAnalyzer\Severity;
use Siberfx\RiskAnalyzer\Support\EndOfLifeClient;
use Siberfx\RiskAnalyzer\Support\NodeVersions;
use Throwable;

final class UnsupportedRuntime extends AbstractProjectRule
{
    /** Last day of security support, used offline or when endoflife.date is unreachable. */
    public const array PHP = [
        '8.0' => '2023-11-26', '8.1' => '2025-12-31', '8.2' => '2026-12-31',
        '8.3' => '2027-12-31', '8.4' => '2028-12-31', '8.5' => '2029-12-31',
    ];

    public const array LARAVEL = [
        '9' => '2024-02-06', '10' => '2025-02-04', '11' => '2026-03-12', '12' => '2027-02-24', '13' => '2028-03-17',
    ];

    public const array NODE = [
        '14' => '2023-04-30', '16' => '2023-09-11', '17' => '2022-06-01', '18' => '2025-04-30', '19' => '2023-06-01',
        '20' => '2026-04-30', '21' => '2024-06-01', '22' => '2027-04-30', '23' => '2025-06-01', '24' => '2028-04-30',
        '25' => '2026-06-01', '26' => '2029-04-30',
    ];

    private ?EndOfLifeClient $client = null;

    public function id(): string
    {
        return 'unsupported-runtime';
    }

    public function title(): string
    {
        return 'Unsupported PHP, Laravel or Node.js';
    }

    public function description(): string
    {
        return 'PHP, Laravel and Node.js versions past their security-support date (or within 90 days of it): the running PHP and its patch level, the composer.json PHP constraint, and Node versions pinned in .nvmrc, package.json, Dockerfiles, compose files and GitHub Actions. Dates come from endoflife.date and php.net (cached), with built-in tables offline.';
    }

    public function category(): Category
    {
        return Category::Dependencies;
    }

    public function severity(): Severity
    {
        return Severity::High;
    }

    public function run(ScanContext $context): iterable
    {
        $this->client = $context->offline ? null : $this->client($context);

        $php = PHP_MAJOR_VERSION.'.'.PHP_MINOR_VERSION;
        $laravel = explode('.', $context->app->version())[0];
        $phpDates = $this->dates('php', self::PHP);

        yield from $this->check("PHP {$php}", $phpDates[$php] ?? null, 'php');
        yield from $this->check("Laravel {$laravel}", $this->dates('laravel', self::LARAVEL)[$laravel] ?? null, 'laravel');
        yield from $this->patchLevel($php, $phpDates[$php] ?? null);
        yield from $this->composerConstraint($context, $phpDates);

        if ($context->config('runtime.node', true)) {
            $nodeDates = $this->dates('nodejs', self::NODE);
            $binary = $context->config('runtime.node_binary', 'node');

            $seen = [];

            foreach (NodeVersions::detect($context, is_string($binary) ? $binary : false) as $node) {
                $anchor = 'node.'.($node['file'] ?? $node['source']).'.'.$node['major'];

                if (! isset($seen[$anchor])) {
                    $seen[$anchor] = true;

                    yield from $this->check("Node {$node['major']} ({$node['source']})", $nodeDates[(string) $node['major']] ?? null,
                        $anchor, $node['file'], $node['line']);
                }
            }
        }
    }

    /**
     * A newer patch release of the running branch that fixed security issues.
     *
     * @return iterable<Finding>
     */
    private function patchLevel(string $branch, ?string $endOfSupport): iterable
    {
        if ($endOfSupport !== null && Carbon::now()->greaterThan(Carbon::parse($endOfSupport)->endOfDay())) {
            return; // Already reported as unsupported.
        }

        $releases = $this->client?->phpReleases($branch);
        $running = PHP_MAJOR_VERSION.'.'.PHP_MINOR_VERSION.'.'.PHP_RELEASE_VERSION;

        if ($releases === null) {
            return;
        }

        $newer = array_filter($releases, fn (string $version) => version_compare($version, $running, '>'), ARRAY_FILTER_USE_KEY);

        if ($newer === []) {
            return;
        }

        $latest = (string) array_key_first($newer);
        $security = array_keys(array_filter($newer));
        $backports = 'Upgrade PHP. Distribution packages (Debian, Ubuntu, RHEL) may backport fixes without changing the version; check your vendor\'s advisories if so.';

        if ($security !== []) {
            $fixedIn = implode(', ', array_slice(array_reverse($security), 0, 3)).(count($security) > 3 ? ', ...' : '');

            yield $this->finding("PHP {$running} is missing security releases ({$fixedIn}); the latest is {$latest}.", null,
                $backports, anchor: 'php.patch.'.$running, meta: ['running' => $running, 'latest' => $latest, 'security_releases' => $security]);

            return;
        }

        yield $this->finding("PHP {$running} is behind the latest patch release {$latest}.", Severity::Low,
            $backports, anchor: 'php.patch.'.$running, meta: ['running' => $running, 'latest' => $latest]);
    }

    /**
     * composer.json allowing installs on an unsupported PHP, e.g. "php": "^8.1".
     *
     * @param  array<array-key, string>  $dates
     * @return iterable<Finding>
     */
    private function composerConstraint(ScanContext $context, array $dates): iterable
    {
        $composer = $context->readJson('composer.json') ?? [];
        $constraints = [
            'require.php' => $composer['require']['php'] ?? null,
            'config.platform.php' => $composer['config']['platform']['php'] ?? null,
        ];

        foreach ($constraints as $key => $constraint) {
            if (! is_string($constraint)) {
                continue;
            }

            try {
                $lower = (new VersionParser)->parseConstraints($constraint)->getLowerBound();
            } catch (Throwable) {
                continue;
            }

            $branch = implode('.', array_slice(explode('.', $lower->getVersion()), 0, 2));
            $end = $dates[$branch] ?? null;

            if ($lower->isZero() || $end === null || ! Carbon::now()->greaterThan(Carbon::parse($end)->endOfDay())) {
                continue;
            }

            yield $this->finding("composer.json {$key} \"{$constraint}\" allows PHP {$branch}, which stopped receiving security fixes on {$end}.", Severity::Medium,
                'Raise the lower bound to a supported PHP version so the app cannot be installed on an unsupported one.',
                'composer.json', anchor: 'composer.'.$key, meta: ['constraint' => $constraint, 'branch' => $branch]);
        }
    }

    /**
     * @return iterable<Finding>
     */
    private function check(string $label, ?string $endOfSupport, string $anchor, ?string $file = null, ?int $line = null): iterable
    {
        if ($endOfSupport === null) {
            return;
        }

        $end = Carbon::parse($endOfSupport)->endOfDay();
        $now = Carbon::now();

        if ($now->greaterThan($end)) {
            yield $this->finding("{$label} stopped receiving security fixes on {$endOfSupport}.", null,
                'Upgrade to a supported release.', $file, $line, anchor: $anchor.'.eol');
        } elseif ($now->diffInDays($end) <= 90) {
            yield $this->finding("{$label} stops receiving security fixes on {$endOfSupport}.", Severity::Low,
                'Plan the upgrade now.', $file, $line, anchor: $anchor.'.eol-soon');
        }
    }

    /**
     * Live dates over the built-in table, so cycles released after this version are known too.
     *
     * @param  array<array-key, string>  $fallback
     * @return array<array-key, string>
     */
    private function dates(string $product, array $fallback): array
    {
        return array_replace($fallback, $this->client?->endOfSupport($product) ?? []);
    }

    private function client(ScanContext $context): EndOfLifeClient
    {
        $cache = null;

        try {
            $cache = $context->app->make(CacheFactory::class)->store();
        } catch (Throwable) {
            // No cache store configured: query every time.
        }

        return new EndOfLifeClient(
            $context->app->make(Http::class),
            $cache,
            rtrim((string) $context->config('runtime.endpoint', 'https://endoflife.date'), '/'),
            rtrim((string) $context->config('runtime.php_endpoint', 'https://www.php.net'), '/'),
            (int) $context->config('runtime.timeout', 10),
            (int) $context->config('runtime.cache_ttl', 86400),
        );
    }
}

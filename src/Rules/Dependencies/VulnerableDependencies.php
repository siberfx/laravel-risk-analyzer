<?php

namespace Siberfx\RiskAnalyzer\Rules\Dependencies;

use Illuminate\Contracts\Cache\Factory as CacheFactory;
use Illuminate\Http\Client\Factory as Http;
use Siberfx\RiskAnalyzer\Category;
use Siberfx\RiskAnalyzer\Rules\AbstractProjectRule;
use Siberfx\RiskAnalyzer\ScanContext;
use Siberfx\RiskAnalyzer\Severity;
use Siberfx\RiskAnalyzer\Support\Lockfiles;
use Siberfx\RiskAnalyzer\Support\OsvClient;
use Throwable;

final class VulnerableDependencies extends AbstractProjectRule
{
    public function id(): string
    {
        return 'vulnerable-dependency';
    }

    public function title(): string
    {
        return 'Vulnerable dependencies';
    }

    public function description(): string
    {
        return 'Packages in composer.lock and package-lock.json with published advisories, looked up in the OSV.dev database (GitHub Security Advisories, FriendsOfPHP, npm). Severity comes from the advisory; the lowest fixing version is suggested.';
    }

    public function category(): Category
    {
        return Category::Dependencies;
    }

    public function severity(): Severity
    {
        return Severity::Critical;
    }

    public function run(ScanContext $context): iterable
    {
        if ($context->offline) {
            return;
        }

        $includeDev = (bool) $context->config('dependencies.include_dev', true);
        $packages = [
            ...Lockfiles::composer($context),
            ...($context->config('dependencies.npm', true) ? Lockfiles::npm($context) : []),
        ];

        $queries = [];

        foreach ($packages as $package) {
            if (($includeDev || ! $package['dev']) && ! str_starts_with($package['version'], 'dev-')) {
                $queries[$package['ecosystem'].':'.$package['name'].'@'.$package['version']] = $package;
            }
        }

        if ($queries === []) {
            return;
        }

        try {
            $results = $this->client($context)->vulnerabilities($queries);
        } catch (Throwable $exception) {
            yield $this->finding('Dependency advisories could not be checked: '.$exception->getMessage(), Severity::Info,
                'Check network access to the OSV API, or run with --offline to skip this rule.', anchor: 'osv-unavailable');

            return;
        }

        $ignored = (array) $context->config('dependencies.ignore', []);

        foreach ($results as $key => $advisories) {
            $package = $queries[$key];

            foreach ($advisories as $advisory) {
                if (array_intersect([$advisory['id'], ...$advisory['aliases']], $ignored) !== []) {
                    continue;
                }

                $fix = $advisory['fixed'] !== null ? "Upgrade to {$advisory['fixed']} or later." : 'No fixed version is published yet; check the advisory for workarounds.';
                $command = $package['ecosystem'] === 'npm' ? "npm install {$package['name']}@^{$advisory['fixed']}" : "composer update {$package['name']} --with-dependencies";

                yield $this->finding(
                    "{$package['name']} {$package['version']}: {$advisory['summary']} ({$advisory['id']})",
                    $advisory['severity'],
                    $fix.($advisory['fixed'] !== null ? " ({$command})" : '').' '.$advisory['url'],
                    $package['source'],
                    anchor: $package['name'].'|'.$advisory['id'],
                    meta: [
                        'package' => $package['name'],
                        'version' => $package['version'],
                        'ecosystem' => $package['ecosystem'],
                        'dev' => $package['dev'],
                        'advisory' => $advisory['id'],
                        'aliases' => $advisory['aliases'],
                        'fixed' => $advisory['fixed'],
                        'url' => $advisory['url'],
                    ],
                );
            }
        }
    }

    private function client(ScanContext $context): OsvClient
    {
        $cache = null;

        try {
            $cache = $context->app->make(CacheFactory::class)->store();
        } catch (Throwable) {
            // No cache store configured: query every time.
        }

        return new OsvClient(
            $context->app->make(Http::class),
            $cache,
            rtrim((string) $context->config('dependencies.endpoint', 'https://api.osv.dev'), '/'),
            (int) $context->config('dependencies.timeout', 15),
            (int) $context->config('dependencies.cache_ttl', 21600),
        );
    }
}

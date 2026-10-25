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
        return 'Packages in composer.lock, package-lock.json, yarn.lock, pnpm-lock.yaml and bun.lock (also inside frontend folders such as a separate SPA) with published advisories, looked up in the OSV.dev database (GitHub Security Advisories, FriendsOfPHP, npm). Severity comes from the advisory; the lowest fixing version is suggested.';
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
        $javascript = (bool) $context->config('dependencies.npm', true);
        $packages = [
            ...Lockfiles::composer($context),
            ...($javascript ? Lockfiles::javascript($context) : []),
        ];

        $queries = [];

        foreach ($javascript ? ['', ...$this->frontendFolders($context)] : [''] as $folder) {
            $scope = $folder === '' ? $context : new ScanContext($context->app, $context->basePath($folder), $context->config, $context->production, $context->offline);
            $prefix = $folder === '' ? '' : $folder.'/';

            if ($javascript && $scope->exists('bun.lockb') && ! $scope->exists('bun.lock')) {
                yield $this->finding("{$prefix}bun.lockb is a binary lockfile and cannot be checked for advisories.", Severity::Info,
                    'Switch to the text lockfile with `bun install --save-text-lockfile` (the default since Bun 1.2) and commit bun.lock.',
                    $prefix.'bun.lockb', anchor: $prefix.'bun.lockb');
            }

            foreach ($folder === '' ? $packages : Lockfiles::javascript($scope) as $package) {
                if (($includeDev || ! $package['dev']) && ! str_starts_with($package['version'], 'dev-')) {
                    $package['source'] = $prefix.$package['source'];
                    $queries[$prefix.$package['ecosystem'].':'.$package['name'].'@'.$package['version']] = $package;
                }
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
                $command = match (basename($package['source'])) {
                    'composer.lock' => "composer update {$package['name']} --with-dependencies",
                    'yarn.lock' => "yarn up {$package['name']}@^{$advisory['fixed']}, or yarn upgrade on Yarn 1",
                    'pnpm-lock.yaml' => "pnpm update {$package['name']}@^{$advisory['fixed']}",
                    'bun.lock' => "bun update {$package['name']}@^{$advisory['fixed']}",
                    default => "npm install {$package['name']}@^{$advisory['fixed']}",
                };
                $folder = dirname($package['source']);
                $command = $folder === '.' ? $command : "cd {$folder} && {$command}";
                $cves = array_filter($advisory['aliases'], fn (string $alias) => str_starts_with($alias, 'CVE-') && $alias !== $advisory['id']);
                $ids = implode(' / ', [$advisory['id'], ...$cves]);

                yield $this->finding(
                    "{$package['name']} {$package['version']}: {$advisory['summary']} ({$ids})",
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

    /**
     * Frontend folders (frontend.paths or --frontend) inside or outside the
     * project that have their own JavaScript lockfile, e.g. a separate SPA.
     *
     * @return list<string>
     */
    private function frontendFolders(ScanContext $context): array
    {
        $folders = [];

        foreach ($context->frontendRoots() as $root) {
            $folder = $context->relative($context->basePath($root));

            if ($folder !== '' && $context->basePath($folder) !== $context->basePath()
                && array_any(['package-lock.json', 'yarn.lock', 'pnpm-lock.yaml', 'bun.lock', 'bun.lockb'], fn (string $lock) => $context->exists($folder.'/'.$lock))) {
                $folders[] = $folder;
            }
        }

        return array_values(array_unique($folders));
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

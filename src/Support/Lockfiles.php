<?php

namespace Siberfx\RiskAnalyzer\Support;

use Siberfx\RiskAnalyzer\ScanContext;

/**
 * Reads installed package versions from composer.lock and the JavaScript
 * lockfiles: package-lock.json, yarn.lock (classic and Berry),
 * pnpm-lock.yaml (v5 to v9) and the text bun.lock.
 */
final class Lockfiles
{
    /**
     * @return list<array{ecosystem: string, name: string, version: string, dev: bool, abandoned: bool|string, source: string}>
     */
    public static function composer(ScanContext $context): array
    {
        $lock = $context->readJson('composer.lock');

        if ($lock === null) {
            return [];
        }

        $packages = [];

        foreach (['packages' => false, 'packages-dev' => true] as $section => $dev) {
            foreach ((array) ($lock[$section] ?? []) as $package) {
                if (! isset($package['name'], $package['version'])) {
                    continue;
                }

                $packages[] = [
                    'ecosystem' => 'Packagist',
                    'name' => (string) $package['name'],
                    'version' => ltrim((string) $package['version'], 'v'),
                    'dev' => $dev,
                    'abandoned' => $package['abandoned'] ?? false,
                    'source' => 'composer.lock',
                ];
            }
        }

        return $packages;
    }

    /**
     * Packages actually installed in vendor/ (or composer.json's config.vendor-dir), from
     * vendor/composer/installed.json: {"packages": [...], "dev-package-names": [...]} on
     * Composer 2, a plain list on Composer 1. Catches a vendor/ folder that has drifted from
     * composer.lock, or a deployment without one.
     *
     * @return list<array{ecosystem: string, name: string, version: string, dev: bool, abandoned: bool|string, source: string}>
     */
    public static function installedComposer(ScanContext $context): array
    {
        $vendor = trim(str_replace('\\', '/', (string) ($context->readJson('composer.json')['config']['vendor-dir'] ?? 'vendor')), '/');
        $source = ($vendor === '' ? 'vendor' : $vendor).'/composer/installed.json';
        $installed = $context->readJson($source);

        if ($installed === null) {
            return [];
        }

        $list = array_is_list($installed) ? $installed : (array) ($installed['packages'] ?? []);
        $devNames = array_is_list($installed) ? [] : (array) ($installed['dev-package-names'] ?? []);
        $packages = [];

        foreach ($list as $package) {
            if (! is_array($package) || ! isset($package['name'], $package['version'])) {
                continue;
            }

            $packages[] = [
                'ecosystem' => 'Packagist',
                'name' => (string) $package['name'],
                'version' => ltrim((string) $package['version'], 'v'),
                'dev' => in_array($package['name'], $devNames, true),
                'abandoned' => $package['abandoned'] ?? false,
                'source' => $source,
            ];
        }

        return $packages;
    }

    /**
     * Packages actually installed in node_modules/, from the hidden lockfile npm 7+
     * writes to node_modules/.package-lock.json (same format as package-lock.json v2/v3).
     *
     * @return list<array{ecosystem: string, name: string, version: string, dev: bool, abandoned: bool|string, source: string}>
     */
    public static function installedNpm(ScanContext $context): array
    {
        return self::npm($context, 'node_modules/.package-lock.json');
    }

    /**
     * Every JavaScript lockfile in the project, one entry per package version.
     *
     * @return list<array{ecosystem: string, name: string, version: string, dev: bool, abandoned: bool|string, source: string}>
     */
    public static function javascript(ScanContext $context): array
    {
        $packages = [];

        foreach ([...self::npm($context), ...self::yarn($context), ...self::pnpm($context), ...self::bun($context)] as $package) {
            $packages[$package['name'].'@'.$package['version']] ??= $package;
        }

        return array_values($packages);
    }

    /**
     * yarn.lock v1 ("version \"1.2.3\"") and Berry ("version: 1.2.3"). Workspace and link entries are skipped.
     *
     * @return list<array{ecosystem: string, name: string, version: string, dev: bool, abandoned: bool|string, source: string}>
     */
    public static function yarn(ScanContext $context): array
    {
        $packages = [];
        $name = null;

        foreach (preg_split('/\R/', (string) $context->read('yarn.lock')) ?: [] as $line) {
            if ($line === '' || str_starts_with($line, '#')) {
                continue;
            }

            if (! str_starts_with($line, ' ')) {
                // "@babel/core@^7.0.0", "@babel/core@^7.1.0": or "lodash@npm:^4.17.21":
                $spec = trim(explode(',', rtrim($line, ':'))[0], " \"'");
                $at = strrpos($spec, '@');
                $name = $at > 0 && preg_match('/@(workspace|link|portal|file|patch|exec):/', $spec) !== 1 ? substr($spec, 0, $at) : null;

                // Aliases: "string-width-cjs@npm:string-width@^4.2.0" installs string-width.
                if ($name !== null && str_contains($name, '@npm:')) {
                    $name = substr($name, strpos($name, '@npm:') + 5);
                }

                continue;
            }

            if ($name !== null && preg_match('/^\s+version:?\s+"?([^"\s]+)"?\s*$/', $line, $match) === 1) {
                if (preg_match('/^\d/', $match[1]) === 1 && ! str_ends_with($match[1], '-use.local')) {
                    $packages[$name.'@'.$match[1]] = self::npmEntry($name, ['version' => $match[1]], 'yarn.lock');
                }

                $name = null;
            }
        }

        return array_values($packages);
    }

    /**
     * pnpm-lock.yaml "packages:" keys: "/name/1.2.3" (v5), "/name@1.2.3" (v6) and "name@1.2.3" (v9),
     * with peer suffixes such as "(react@18.2.0)" or "_react@18.2.0" removed.
     *
     * @return list<array{ecosystem: string, name: string, version: string, dev: bool, abandoned: bool|string, source: string}>
     */
    public static function pnpm(ScanContext $context): array
    {
        $packages = [];
        $dev = [];
        $inPackages = false;
        $current = null;

        foreach (preg_split('/\R/', (string) $context->read('pnpm-lock.yaml')) ?: [] as $line) {
            if ($line !== '' && ! str_starts_with($line, ' ')) {
                $inPackages = rtrim($line) === 'packages:';
                $current = null;

                continue;
            }

            if (! $inPackages) {
                continue;
            }

            if (preg_match('/^  ([^\s].*):\s*$/', $line, $match) === 1) {
                $current = null;
                $key = ltrim(trim($match[1], "'\""), '/');
                $key = (string) preg_replace('/\(.*$/', '', $key);
                $at = strrpos($key, '@');

                if (preg_match('/^((?:@[^\/]+\/)?[^\/@]+)\/(\d[^\/_]*)/', $key, $parts) === 1) {
                    [, $name, $version] = $parts; // v5: "react-dom/18.2.0_react@18.2.0"
                } elseif ($at > 0) {
                    [$name, $version] = [substr($key, 0, $at), substr($key, $at + 1)];
                } else {
                    continue;
                }

                if (preg_match('/^\d/', $version) === 1) {
                    $current = $name.'@'.$version;
                    $packages[$current] = self::npmEntry($name, ['version' => $version], 'pnpm-lock.yaml');
                }

                continue;
            }

            if ($current !== null && preg_match('/^    dev:\s*true\s*$/', $line) === 1) {
                $dev[$current] = true;
            }
        }

        foreach (array_keys($dev) as $key) {
            $packages[$key] = [...$packages[$key], 'dev' => true];
        }

        return array_values($packages);
    }

    /**
     * The text bun.lock (Bun 1.2+): JSON with trailing commas, packages as ["name@1.2.3", ...].
     *
     * @return list<array{ecosystem: string, name: string, version: string, dev: bool, abandoned: bool|string, source: string}>
     */
    public static function bun(ScanContext $context): array
    {
        $contents = $context->read('bun.lock');

        if ($contents === null) {
            return [];
        }

        $lock = json_decode((string) preg_replace('/,(\s*[}\]])/', '$1', $contents), true);
        $packages = [];

        foreach ((array) (is_array($lock) ? ($lock['packages'] ?? []) : []) as $package) {
            $spec = is_array($package) ? ($package[0] ?? null) : null;
            $at = is_string($spec) ? strrpos($spec, '@') : false;

            if ($at === false || $at === 0) {
                continue;
            }

            $version = substr((string) $spec, $at + 1);

            if (preg_match('/^\d/', $version) === 1) {
                $name = substr((string) $spec, 0, $at);
                $packages[$name.'@'.$version] = self::npmEntry($name, ['version' => $version], 'bun.lock');
            }
        }

        return array_values($packages);
    }

    /**
     * Supports lockfileVersion 1 (nested "dependencies") and 2/3 ("packages").
     *
     * @return list<array{ecosystem: string, name: string, version: string, dev: bool, abandoned: bool|string, source: string}>
     */
    public static function npm(ScanContext $context, string $source = 'package-lock.json'): array
    {
        $lock = $context->readJson($source);

        if ($lock === null) {
            return [];
        }

        $packages = [];

        if (isset($lock['packages']) && is_array($lock['packages'])) {
            foreach ($lock['packages'] as $path => $package) {
                if ($path === '' || ! isset($package['version']) || ($package['link'] ?? false)) {
                    continue;
                }

                $name = $package['name'] ?? substr((string) $path, (int) strrpos((string) $path, 'node_modules/') + 13);
                $packages[$name.'@'.$package['version']] = self::npmEntry($name, $package, $source);
            }

            return array_values($packages);
        }

        $walk = function (array $dependencies) use (&$walk, &$packages, $source): void {
            foreach ($dependencies as $name => $package) {
                if (isset($package['version'])) {
                    $packages[$name.'@'.$package['version']] = self::npmEntry((string) $name, $package, $source);
                }

                $walk((array) ($package['dependencies'] ?? []));
            }
        };
        $walk((array) ($lock['dependencies'] ?? []));

        return array_values($packages);
    }

    /**
     * @param  array<string, mixed>  $package
     * @return array{ecosystem: string, name: string, version: string, dev: bool, abandoned: bool|string, source: string}
     */
    private static function npmEntry(string $name, array $package, string $source = 'package-lock.json'): array
    {
        return [
            'ecosystem' => 'npm',
            'name' => $name,
            'version' => (string) $package['version'],
            'dev' => (bool) ($package['dev'] ?? false),
            'abandoned' => false,
            'source' => $source,
        ];
    }
}

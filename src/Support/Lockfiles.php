<?php

namespace Siberfx\RiskAnalyzer\Support;

use Siberfx\RiskAnalyzer\ScanContext;

/**
 * Reads installed package versions from composer.lock and package-lock.json.
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
     * Supports lockfileVersion 1 (nested "dependencies") and 2/3 ("packages").
     *
     * @return list<array{ecosystem: string, name: string, version: string, dev: bool, abandoned: bool|string, source: string}>
     */
    public static function npm(ScanContext $context): array
    {
        $lock = $context->readJson('package-lock.json');

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
                $packages[$name.'@'.$package['version']] = self::npmEntry($name, $package);
            }

            return array_values($packages);
        }

        $walk = function (array $dependencies) use (&$walk, &$packages): void {
            foreach ($dependencies as $name => $package) {
                if (isset($package['version'])) {
                    $packages[$name.'@'.$package['version']] = self::npmEntry((string) $name, $package);
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
    private static function npmEntry(string $name, array $package): array
    {
        return [
            'ecosystem' => 'npm',
            'name' => $name,
            'version' => (string) $package['version'],
            'dev' => (bool) ($package['dev'] ?? false),
            'abandoned' => false,
            'source' => 'package-lock.json',
        ];
    }
}

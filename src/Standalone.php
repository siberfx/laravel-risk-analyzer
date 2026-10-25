<?php

namespace Siberfx\RiskAnalyzer;

use Illuminate\Config\Repository;
use Illuminate\Container\Container;
use Illuminate\Contracts\Config\Repository as RepositoryContract;
use Illuminate\Http\Client\Factory as Http;
use InvalidArgumentException;
use Siberfx\RiskAnalyzer\Support\ConfigMerger;
use Siberfx\RiskAnalyzer\Support\StandaloneContainer;

/**
 * Runs Risk Analyzer without a Laravel application: Symfony, Yii2, plain PHP
 * or a frontend/infrastructure repository. Used by vendor/bin/risk-analyzer
 * and usable from any PHPUnit or Pest suite:
 *
 *   Standalone::scan(__DIR__.'/..')->assertClean('high');
 *
 * The configuration & route rules need a booted Laravel app and are skipped.
 */
final class Standalone
{
    /**
     * Defaults for projects that are not Laravel apps: the whole project,
     * minus dependencies, caches, build output and tests. They replace the
     * Laravel folders (app, routes, resources/views...) of the package config.
     */
    public const array DEFAULTS = [
        'paths' => ['.'],
        'exclude' => [
            'vendor', 'node_modules', 'var', 'runtime', 'storage', 'cache', 'bootstrap/cache', 'tests', 'test',
            'web/assets', 'public/assets', 'public/bundles', 'public/build', '.git', '.idea', '.worktrees',
        ],
        'frontend' => [
            'paths' => ['.'],
            'exclude' => [
                'node_modules', 'vendor', 'dist', 'build', '.angular', '.next', '.nuxt', 'coverage', 'tests', '__tests__', 'e2e',
                'var', 'runtime', 'storage', 'web/assets', 'public/assets', 'public/bundles', 'public/build', 'assets/vendor', '.worktrees',
                'plugins', 'vendors', 'bower_components', 'third-party', 'third_party',
            ],
        ],
    ];

    /** Config files looked for in the scanned folder, first match wins. */
    public const array CONFIG_FILES = ['risk-analyzer.php', 'config/risk-analyzer.php'];

    /**
     * Scans $path and returns the report. Takes the same named options as
     * RiskAnalyzer::scan() (only, skip, production, offline, frontend...).
     *
     * @param  array<string, mixed>  $config  overrides on top of the config file
     */
    public static function scan(string $path = '.', ?string $configFile = null, array $config = [], mixed ...$options): Report
    {
        return self::make($path, $configFile, $config)->scan(...$options);
    }

    /**
     * @param  array<string, mixed>  $config  overrides on top of the config file
     */
    public static function make(string $path = '.', ?string $configFile = null, array $config = []): RiskAnalyzer
    {
        return self::container($path, $configFile, $config)->make(RiskAnalyzer::class);
    }

    /**
     * A container with the config, an HTTP client and the analyzer for $path.
     *
     * @param  array<string, mixed>  $config  overrides on top of the config file
     */
    public static function container(string $path = '.', ?string $configFile = null, array $config = []): Container
    {
        $base = realpath($path);

        if ($base === false || ! is_dir($base)) {
            throw new InvalidArgumentException("Project folder [{$path}] does not exist.");
        }

        $settings = self::config($base, $configFile, $config);
        $container = new StandaloneContainer;
        $repository = new Repository(['risk-analyzer' => $settings]);

        $container->instance('config', $repository);
        $container->instance(RepositoryContract::class, $repository);
        $container->instance(Http::class, new Http);
        $container->instance(RiskAnalyzer::class, new RiskAnalyzer($container, $settings, $base));

        return $container;
    }

    /**
     * Package defaults, then the standalone defaults, then the project's
     * config file (or $configFile), then $overrides.
     *
     * @param  array<string, mixed>  $overrides
     * @return array<string, mixed>
     */
    public static function config(string $base, ?string $configFile = null, array $overrides = []): array
    {
        $config = ConfigMerger::merge(require __DIR__.'/../config/risk-analyzer.php', self::DEFAULTS);

        if ($configFile !== null && ! is_file($configFile)) {
            throw new InvalidArgumentException("Config file [{$configFile}] does not exist.");
        }

        $configFile ??= array_values(array_filter(array_map(fn (string $name) => $base.'/'.$name, self::CONFIG_FILES), 'is_file'))[0] ?? null;

        if ($configFile !== null) {
            $published = require $configFile;

            if (! is_array($published)) {
                throw new InvalidArgumentException("Config file [{$configFile}] must return an array.");
            }

            $config = ConfigMerger::merge($config, $published);
        }

        /** @var array<string, mixed> */
        return ConfigMerger::merge($config, $overrides);
    }
}

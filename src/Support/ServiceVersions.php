<?php

namespace Siberfx\RiskAnalyzer\Support;

use Illuminate\Contracts\Foundation\Application;
use Illuminate\Redis\RedisManager;
use PDO;
use Siberfx\RiskAnalyzer\ScanContext;
use Throwable;

/**
 * Asks the database and Redis servers the app uses for their versions, over
 * separate short-timeout connections. Unreachable services are left out.
 */
final class ServiceVersions
{
    private const string PROBE = 'risk-analyzer-probe';

    private const int TIMEOUT = 5;

    /**
     * @return list<array{product: string, label: string, version: string, source: string}>
     */
    public static function detect(ScanContext $context): array
    {
        return array_values(array_filter([self::database($context), self::redis($context)]));
    }

    /**
     * The release cycle endoflife.date uses: "8.0" for MySQL 8.0.39, "16" for PostgreSQL 16.4, "9.6" for 9.6.24.
     */
    public static function cycle(string $product, string $version): ?string
    {
        if (preg_match('/(\d+)\.(\d+)/', $version, $match) !== 1) {
            return null;
        }

        return $product === 'postgresql' && (int) $match[1] >= 10 ? $match[1] : $match[1].'.'.$match[2];
    }

    /**
     * MySQL/MariaDB "select version()" or PostgreSQL "show server_version" to a product and version.
     *
     * @return array{product: string, label: string, version: string}|null
     */
    public static function parseDatabase(string $driver, string $reported): ?array
    {
        // MariaDB behind replication-compatible servers reports "5.5.5-10.11.6-MariaDB".
        $reported = (string) preg_replace('/^5\.5\.5-/', '', trim($reported));

        if (preg_match('/^(\d+\.\d+(?:\.\d+)?)/', $reported, $match) !== 1) {
            return null;
        }

        return match (true) {
            $driver === 'pgsql' => ['product' => 'postgresql', 'label' => 'PostgreSQL', 'version' => $match[1]],
            $driver === 'mariadb' || stripos($reported, 'mariadb') !== false => ['product' => 'mariadb', 'label' => 'MariaDB', 'version' => $match[1]],
            default => ['product' => 'mysql', 'label' => 'MySQL', 'version' => $match[1]],
        };
    }

    /**
     * INFO server output (phpredis flat, predis grouped by section) to Redis or Valkey and its version.
     *
     * @param  array<array-key, mixed>  $info
     * @return array{product: string, label: string, version: string}|null
     */
    public static function parseRedis(array $info): ?array
    {
        $flat = [];
        array_walk_recursive($info, function (mixed $value, int|string $key) use (&$flat): void {
            $flat[strtolower((string) $key)] = (string) $value;
        });

        if (isset($flat['valkey_version'])) {
            return ['product' => 'valkey', 'label' => 'Valkey', 'version' => $flat['valkey_version']];
        }

        return isset($flat['redis_version']) ? ['product' => 'redis', 'label' => 'Redis', 'version' => $flat['redis_version']] : null;
    }

    /**
     * @return array{product: string, label: string, version: string, source: string}|null
     */
    private static function database(ScanContext $context): ?array
    {
        $settings = $context->settings();
        $name = (string) $settings->get('database.default');
        $config = $settings->get("database.connections.{$name}");

        if (! is_array($config) || ! in_array($config['driver'] ?? null, ['mysql', 'mariadb', 'pgsql'], true)) {
            return null;
        }

        $manager = $context->app->make('db');

        try {
            $connection = $manager->build([
                ...$config,
                'name' => self::PROBE,
                'options' => array_replace((array) ($config['options'] ?? []), [PDO::ATTR_TIMEOUT => self::TIMEOUT]),
            ]);

            $reported = (string) $connection->scalar($config['driver'] === 'pgsql' ? 'show server_version' : 'select version()');
        } catch (Throwable) {
            return null;
        } finally {
            try {
                $manager->purge(self::PROBE);
            } catch (Throwable) {
                // Nothing to clean up.
            }
        }

        $parsed = self::parseDatabase((string) $config['driver'], $reported);

        return $parsed === null ? null : [...$parsed, 'source' => "connection '{$name}'"];
    }

    /**
     * The Redis connection used by the cache, session or queue, if any of them uses Redis.
     *
     * @return array{product: string, label: string, version: string, source: string}|null
     */
    private static function redis(ScanContext $context): ?array
    {
        // Redis connections are built from a Laravel app's config (never the case standalone).
        if (! $context->app instanceof Application) {
            return null;
        }

        $settings = $context->settings();
        $cacheStore = (string) $settings->get('cache.default');
        $queue = (string) $settings->get('queue.default');

        $name = match (true) {
            $settings->get("cache.stores.{$cacheStore}.driver") === 'redis' => $settings->get("cache.stores.{$cacheStore}.connection", 'default'),
            $settings->get('session.driver') === 'redis' => $settings->get('session.connection') ?? 'default',
            $settings->get("queue.connections.{$queue}.driver") === 'redis' => $settings->get("queue.connections.{$queue}.connection", 'default'),
            default => null,
        };

        $redis = (array) $settings->get('database.redis', []);

        if (! is_string($name) || ! is_array($redis[$name] ?? null)) {
            return null;
        }

        try {
            $manager = new RedisManager($context->app, (string) ($redis['client'] ?? 'phpredis'), [
                'options' => (array) ($redis['options'] ?? []),
                self::PROBE => [...$redis[$name], 'timeout' => self::TIMEOUT, 'read_timeout' => self::TIMEOUT],
            ]);
            $info = $manager->connection(self::PROBE)->command('info', ['server']);
            $manager->purge(self::PROBE);
        } catch (Throwable) {
            return null;
        }

        $parsed = is_array($info) ? self::parseRedis($info) : null;

        return $parsed === null ? null : [...$parsed, 'source' => "Redis connection '{$name}'"];
    }
}

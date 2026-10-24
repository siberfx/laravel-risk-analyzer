<?php

use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Siberfx\RiskAnalyzer\Finding;
use Siberfx\RiskAnalyzer\Rules\Dependencies\UnsupportedRuntime;
use Siberfx\RiskAnalyzer\ScanContext;
use Siberfx\RiskAnalyzer\Support\ServiceVersions;

beforeEach(fn () => Carbon::setTestNow('2026-10-24'));
afterEach(fn () => Carbon::setTestNow());

/**
 * @param  list<array{product: string, label: string, version: string, source: string}>  $services
 * @return list<array{string, string}>
 */
function serviceFindings(array $services, bool $production = true): array
{
    $rule = new UnsupportedRuntime(fn () => $services);
    $context = new ScanContext(app(), test()->project(['composer.json' => '{}']), (array) config('risk-analyzer'), production: $production, offline: true);

    return collect(iterator_to_array($rule->run($context), false))
        ->filter(fn (Finding $finding) => str_starts_with($finding->snippet ?? '', 'service.'))
        ->map(fn (Finding $finding) => [$finding->severity->value, $finding->message])
        ->values()->all();
}

it('reads database versions', function (string $driver, string $reported, ?array $expected) {
    expect(ServiceVersions::parseDatabase($driver, $reported))->toBe($expected);
})->with([
    'mysql' => ['mysql', '8.0.39', ['product' => 'mysql', 'label' => 'MySQL', 'version' => '8.0.39']],
    'mariadb via mysql driver' => ['mysql', '10.11.6-MariaDB-0+deb12u1', ['product' => 'mariadb', 'label' => 'MariaDB', 'version' => '10.11.6']],
    'mariadb with replication prefix' => ['mysql', '5.5.5-10.6.18-MariaDB-log', ['product' => 'mariadb', 'label' => 'MariaDB', 'version' => '10.6.18']],
    'mariadb driver' => ['mariadb', '11.4.2-MariaDB', ['product' => 'mariadb', 'label' => 'MariaDB', 'version' => '11.4.2']],
    'postgresql' => ['pgsql', '16.4 (Debian 16.4-1.pgdg120+1)', ['product' => 'postgresql', 'label' => 'PostgreSQL', 'version' => '16.4']],
    'unknown' => ['mysql', 'unknown', null],
]);

it('reads Redis and Valkey versions from INFO', function (array $info, ?array $expected) {
    expect(ServiceVersions::parseRedis($info))->toBe($expected);
})->with([
    'phpredis' => [['redis_version' => '7.2.4', 'redis_mode' => 'standalone'], ['product' => 'redis', 'label' => 'Redis', 'version' => '7.2.4']],
    'predis sections' => [['Server' => ['redis_version' => '6.0.16']], ['product' => 'redis', 'label' => 'Redis', 'version' => '6.0.16']],
    'valkey' => [['redis_version' => '7.2.4', 'server_name' => 'valkey', 'valkey_version' => '8.0.1'], ['product' => 'valkey', 'label' => 'Valkey', 'version' => '8.0.1']],
    'nothing' => [[], null],
]);

it('maps versions to release cycles', function (string $product, string $version, string $cycle) {
    expect(ServiceVersions::cycle($product, $version))->toBe($cycle);
})->with([
    ['mysql', '8.0.39', '8.0'],
    ['mariadb', '10.11.6', '10.11'],
    ['postgresql', '16.4', '16'],
    ['postgresql', '9.6.24', '9.6'],
    ['redis', '7.2.4', '7.2'],
]);

it('flags database and Redis servers past or near end of support in production', function () {
    $services = [
        ['product' => 'mysql', 'label' => 'MySQL', 'version' => '8.0.39', 'source' => "connection 'mysql'"],
        ['product' => 'postgresql', 'label' => 'PostgreSQL', 'version' => '14.13', 'source' => "connection 'pgsql'"],
        ['product' => 'redis', 'label' => 'Redis', 'version' => '7.2.4', 'source' => "Redis connection 'cache'"],
    ];

    expect(serviceFindings($services))->toBe([
        ['high', "MySQL 8.0 (connection 'mysql', 8.0.39) stopped receiving security fixes on 2026-04-30."],
        ['low', "PostgreSQL 14 (connection 'pgsql', 14.13) stops receiving security fixes on 2026-11-12."],
    ])->and(serviceFindings($services, production: false))->toBe([]);

    config()->set('risk-analyzer.runtime.services', false);
    expect(serviceFindings($services))->toBe([]);
});

it('skips sqlite and unreachable servers quickly, and leaves no probe connection behind', function () {
    expect(ServiceVersions::detect(new ScanContext(app(), base_path(), [])))->toBe([]);

    config()->set('database.default', 'mysql');
    config()->set('database.connections.mysql', ['driver' => 'mysql', 'host' => '127.0.0.1', 'port' => 1, 'database' => 'app', 'username' => 'app', 'password' => '']);
    config()->set('cache.default', 'redis');
    config()->set('cache.stores.redis', ['driver' => 'redis', 'connection' => 'cache']);
    config()->set('database.redis.cache', ['host' => '127.0.0.1', 'port' => 1]);

    $started = microtime(true);

    expect(ServiceVersions::detect(new ScanContext(app(), base_path(), [])))->toBe([])
        ->and(microtime(true) - $started)->toBeLessThan(12)
        ->and(array_keys(DB::getConnections()))->not->toContain('risk-analyzer-probe');
});

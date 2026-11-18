<?php

use Illuminate\Http\Client\Request;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Http;
use Siberfx\RiskAnalyzer\Finding;
use Siberfx\RiskAnalyzer\RiskAnalyzer;
use Siberfx\RiskAnalyzer\Tests\TestCase;

function lockProject(TestCase $test, array $composer = []): string
{
    return $test->project([
        'composer.json' => json_encode(['require' => ['laravel/framework' => '^12.0'], ...$composer]),
        'composer.lock' => json_encode([
            'packages' => [
                ['name' => 'guzzlehttp/psr7', 'version' => '2.4.1', 'type' => 'library'],
                ['name' => 'swiftmailer/swiftmailer', 'version' => 'v6.3.0', 'abandoned' => 'symfony/mailer'],
                ['name' => 'acme/plugin', 'version' => '1.0.0', 'type' => 'composer-plugin'],
            ],
            'packages-dev' => [
                ['name' => 'acme/dev-tool', 'version' => 'dev-main'],
            ],
        ]),
        'package-lock.json' => json_encode([
            'lockfileVersion' => 3,
            'packages' => [
                '' => ['name' => 'app'],
                'node_modules/axios' => ['version' => '1.6.0', 'dev' => true],
            ],
        ]),
    ]);
}

function fakeOsv(): void
{
    Http::fake([
        'api.osv.dev/v1/querybatch' => Http::response(['results' => [
            ['vulns' => [['id' => 'GHSA-wxmh-65f7-jcvw']]],
            [],
            [],
            ['vulns' => [['id' => 'GHSA-8hc4-vh64-cxmj']]],
        ]]),
        'api.osv.dev/v1/vulns/GHSA-wxmh-65f7-jcvw' => Http::response([
            'id' => 'GHSA-wxmh-65f7-jcvw',
            'aliases' => ['CVE-2023-29197'],
            'summary' => 'Improper header name validation',
            'database_specific' => ['severity' => 'MODERATE'],
            'affected' => [[
                'package' => ['ecosystem' => 'Packagist', 'name' => 'guzzlehttp/psr7'],
                'ranges' => [['type' => 'ECOSYSTEM', 'events' => [['introduced' => '0'], ['fixed' => '1.9.1'], ['introduced' => '2.0.0'], ['fixed' => '2.4.5']]]],
            ]],
        ]),
        'api.osv.dev/v1/vulns/GHSA-8hc4-vh64-cxmj' => Http::response([
            'id' => 'GHSA-8hc4-vh64-cxmj',
            'summary' => 'Server-Side Request Forgery in axios',
            'database_specific' => ['severity' => 'HIGH'],
            'affected' => [['package' => ['ecosystem' => 'npm', 'name' => 'axios'], 'ranges' => [['events' => [['introduced' => '1.3.2'], ['fixed' => '1.7.4']]]]]],
        ]),
    ]);
}

it('looks up composer and npm packages in OSV', function () {
    fakeOsv();

    $findings = app(RiskAnalyzer::class)->scan(only: ['vulnerable-dependency'], baseline: false, basePath: lockProject($this))->findings;

    expect($findings)->toHaveCount(2)
        ->and($findings[0]->severity->value)->toBe('high')
        ->and($findings[0]->meta['fixed'])->toBe('1.7.4')
        ->and($findings[0]->file)->toBe('package-lock.json')
        ->and($findings[0]->message)->toBe('axios 1.6.0: Server-Side Request Forgery in axios (GHSA-8hc4-vh64-cxmj)')
        ->and($findings[1]->message)->toBe('guzzlehttp/psr7 2.4.1: Improper header name validation (GHSA-wxmh-65f7-jcvw / CVE-2023-29197)')
        ->and($findings[1]->meta['fixed'])->toBe('2.4.5')
        ->and($findings[1]->remediation)->toContain('https://github.com/advisories/GHSA-wxmh-65f7-jcvw');

    Http::assertSent(fn (Request $request) => str_ends_with($request->url(), '/v1/querybatch')
        && count($request['queries']) === 4
        && $request['queries'][0] === ['package' => ['ecosystem' => 'Packagist', 'name' => 'guzzlehttp/psr7'], 'version' => '2.4.1']);
});

it('caches advisory lookups between scans', function () {
    fakeOsv();
    $root = lockProject($this);

    app(RiskAnalyzer::class)->scan(only: ['vulnerable-dependency'], baseline: false, basePath: $root);
    app(RiskAnalyzer::class)->scan(only: ['vulnerable-dependency'], baseline: false, basePath: $root);

    Http::assertSentCount(3);
});

it('honours ignored advisories and offline mode', function () {
    fakeOsv();
    config()->set('risk-analyzer.dependencies.ignore', ['CVE-2023-29197']);
    app()->forgetInstance(RiskAnalyzer::class);
    $root = lockProject($this);

    expect(app(RiskAnalyzer::class)->scan(only: ['vulnerable-dependency'], baseline: false, basePath: $root)->findings)->toHaveCount(1)
        ->and(app(RiskAnalyzer::class)->scan(only: ['vulnerable-dependency'], offline: true, baseline: false, basePath: $root)->findings)->toBeEmpty();
});

it('reports an unreachable advisory database as info instead of failing', function () {
    Http::fake(['*' => Http::response('down', 503)]);

    $findings = app(RiskAnalyzer::class)->scan(only: ['vulnerable-dependency'], baseline: false, basePath: lockProject($this))->findings;

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity->value)->toBe('info');
});

/**
 * OSV fake that answers querybatch by package, not by position.
 *
 * @param  array<string, string>  $vulnerable  "ecosystem:name@version" => advisory id
 */
function fakeOsvFor(array $vulnerable): void
{
    Http::fake(function (Request $request) use ($vulnerable) {
        if (str_ends_with($request->url(), '/v1/querybatch')) {
            return Http::response(['results' => array_map(function (array $query) use ($vulnerable) {
                $id = $vulnerable[$query['package']['ecosystem'].':'.$query['package']['name'].'@'.$query['version']] ?? null;

                return $id === null ? [] : ['vulns' => [['id' => $id]]];
            }, $request['queries'])]);
        }

        $id = basename($request->url());
        $key = (string) array_search($id, $vulnerable, true);
        [$ecosystem, $name] = explode(':', substr($key, 0, (int) strrpos($key, '@')), 2);

        return Http::response([
            'id' => $id,
            'summary' => "Advisory for {$name}",
            'database_specific' => ['severity' => 'HIGH'],
            'affected' => [['package' => ['ecosystem' => $ecosystem, 'name' => $name], 'ranges' => [['events' => [['introduced' => '0'], ['fixed' => '9.0.0']]]]]],
        ]);
    });
}

it('checks the packages installed in vendor and node_modules that differ from the lockfiles', function () {
    fakeOsvFor(['Packagist:guzzlehttp/psr7@2.4.1' => 'GHSA-psr7-0000-0001', 'npm:axios@1.6.0' => 'GHSA-axio-0000-0001']);

    $root = $this->project([
        'composer.lock' => json_encode(['packages' => [['name' => 'guzzlehttp/psr7', 'version' => '2.4.5']]]),
        'vendor/composer/installed.json' => json_encode([
            'packages' => [
                ['name' => 'guzzlehttp/psr7', 'version' => '2.4.1', 'version_normalized' => '2.4.1.0'],
                ['name' => 'pestphp/pest', 'version' => 'v4.1.0'],
            ],
            'dev' => true,
            'dev-package-names' => ['pestphp/pest'],
        ]),
        'package-lock.json' => json_encode(['lockfileVersion' => 3, 'packages' => ['' => ['name' => 'app'], 'node_modules/axios' => ['version' => '1.7.4']]]),
        'node_modules/.package-lock.json' => json_encode(['lockfileVersion' => 3, 'packages' => ['node_modules/axios' => ['version' => '1.6.0']]]),
    ]);

    $findings = app(RiskAnalyzer::class)->scan(only: ['vulnerable-dependency'], baseline: false, basePath: $root)->findings;
    $files = array_map(fn (Finding $finding) => $finding->file, $findings);
    sort($files);

    expect($files)->toBe(['node_modules/.package-lock.json', 'vendor/composer/installed.json']);

    $composer = collect($findings)->firstWhere('file', 'vendor/composer/installed.json');
    $npm = collect($findings)->firstWhere('file', 'node_modules/.package-lock.json');

    expect($composer->meta['installed'])->toBeTrue()
        ->and($composer->remediation)->toContain('composer.lock pins 2.4.5; run `composer install`')
        ->and($composer->remediation)->toContain('composer update guzzlehttp/psr7 --with-dependencies')
        ->and($npm->remediation)->toContain('run `npm ci`');

    // Locked and installed versions are each queried once; pest counts because include_dev defaults to true.
    Http::assertSent(fn (Request $request) => str_ends_with($request->url(), '/v1/querybatch') && count($request['queries']) === 5);
});

it('reports a version that is both locked and installed once, against the lockfile', function () {
    fakeOsvFor(['Packagist:guzzlehttp/psr7@2.4.1' => 'GHSA-psr7-0000-0001']);

    $root = $this->project([
        'composer.lock' => json_encode(['packages' => [['name' => 'guzzlehttp/psr7', 'version' => '2.4.1']]]),
        'vendor/composer/installed.json' => json_encode(['packages' => [['name' => 'guzzlehttp/psr7', 'version' => '2.4.1']]]),
    ]);

    $findings = app(RiskAnalyzer::class)->scan(only: ['vulnerable-dependency'], baseline: false, basePath: $root)->findings;

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->file)->toBe('composer.lock')
        ->and($findings[0]->meta['installed'])->toBeFalse();
});

it('checks vendor without a lockfile, and skips installed packages when turned off', function () {
    fakeOsvFor(['Packagist:guzzlehttp/psr7@2.4.1' => 'GHSA-psr7-0000-0001']);

    $root = $this->project([
        'composer.json' => json_encode(['config' => ['vendor-dir' => 'lib/vendor']]),
        'lib/vendor/composer/installed.json' => json_encode([['name' => 'guzzlehttp/psr7', 'version' => 'v2.4.1']]), // Composer 1 format
    ]);

    $findings = app(RiskAnalyzer::class)->scan(only: ['vulnerable-dependency'], baseline: false, basePath: $root)->findings;

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->file)->toBe('lib/vendor/composer/installed.json')
        ->and($findings[0]->remediation)->not->toContain('composer install')
        ->and($findings[0]->remediation)->not->toContain('cd ');

    config()->set('risk-analyzer.dependencies.installed', false);
    app()->forgetInstance(RiskAnalyzer::class);

    expect(app(RiskAnalyzer::class)->scan(only: ['vulnerable-dependency'], baseline: false, basePath: $root)->findings)->toBeEmpty();
});

it('reports abandoned packages from the lock file', function () {
    $findings = app(RiskAnalyzer::class)->scan(only: ['abandoned-package'], baseline: false, basePath: lockProject($this))->findings;

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->message)->toBe('swiftmailer/swiftmailer is abandoned, use symfony/mailer instead.');
});

it('checks composer supply-chain settings', function () {
    $root = lockProject($this, [
        'config' => ['secure-http' => false, 'allow-plugins' => true],
        'repositories' => [['type' => 'composer', 'url' => 'http://packages.example.com']],
        'minimum-stability' => 'dev',
    ]);

    $messages = collect(app(RiskAnalyzer::class)->scan(only: ['composer-hardening'], baseline: false, basePath: $root)->findings)
        ->map(fn (Finding $f) => $f->severity->value)->all();

    expect($messages)->toBe(['high', 'high', 'medium', 'low', 'low']);
});

it('flags PHP and Laravel versions past security support', function () {
    Carbon::setTestNow('2031-01-01');

    $findings = app(RiskAnalyzer::class)->scan(only: ['unsupported-runtime'], baseline: false)->findings;

    expect($findings)->toHaveCount(2)
        ->and($findings[0]->severity->value)->toBe('high');

    Carbon::setTestNow();
});

<?php

use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Http;
use Siberfx\RiskAnalyzer\Finding;
use Siberfx\RiskAnalyzer\RiskAnalyzer;
use Siberfx\RiskAnalyzer\Support\NodeVersions;

beforeEach(fn () => Carbon::setTestNow('2026-10-24'));
afterEach(fn () => Carbon::setTestNow());

/**
 * @return list<array{string, string, ?string}> severity, message, location
 */
function runtimeVersionFindings(string $root, bool $offline = false): array
{
    return collect(app(RiskAnalyzer::class)->scan(only: ['unsupported-runtime'], offline: $offline, baseline: false, basePath: $root)->findings)
        ->map(fn (Finding $finding) => [$finding->severity->value, $finding->message, $finding->location()])
        ->all();
}

function branch(): string
{
    return PHP_MAJOR_VERSION.'.'.PHP_MINOR_VERSION;
}

function running(int $offset = 0): string
{
    return branch().'.'.(PHP_RELEASE_VERSION + $offset);
}

/**
 * @param  array<string, list<string>>  $releases  version => tags
 */
function fakePhpReleases(array $releases): void
{
    Http::fake([
        'endoflife.date/*' => Http::response('not found', 404),
        'www.php.net/releases/*' => Http::response(array_map(fn (array $tags) => ['tags' => $tags, 'date' => '21 Oct 2026'], $releases)),
    ]);
}

it('takes support dates from endoflife.date when online', function () {
    Http::fake([
        'endoflife.date/api/v1/products/php' => Http::response(['result' => ['releases' => [
            ['name' => branch(), 'isEol' => true, 'eolFrom' => '2026-01-01', 'latest' => ['name' => running()]],
        ]]]),
        'endoflife.date/*' => Http::response('not found', 404),
    ]);

    expect(runtimeVersionFindings($this->project(['composer.json' => '{}'])))->toBe([
        ['high', 'PHP '.branch().' stopped receiving security fixes on 2026-01-01.', null],
    ]);

    Http::assertNotSent(fn ($request) => str_contains($request->url(), 'php.net'));
});

it('flags a PHP patch level that is missing security releases', function () {
    fakePhpReleases([running(2) => [''], running(1) => ['security'], running() => ['security']]);

    expect(runtimeVersionFindings($this->project(['composer.json' => '{}'])))->toBe([
        ['high', 'PHP '.running().' is missing security releases ('.running(1).'); the latest is '.running(2).'.', null],
    ]);
});

it('reports a patch level behind only on bug-fix releases as low', function () {
    fakePhpReleases([running(1) => [''], running() => ['security']]);

    expect(runtimeVersionFindings($this->project(['composer.json' => '{}'])))->toBe([
        ['low', 'PHP '.running().' is behind the latest patch release '.running(1).'.', null],
    ]);
});

it('stays quiet on the latest patch, offline, and when php.net is down', function () {
    $root = $this->project(['composer.json' => '{}']);

    fakePhpReleases([running() => ['security']]);
    expect(runtimeVersionFindings($root))->toBe([]);

    expect(runtimeVersionFindings($root, offline: true))->toBe([]);

    Http::fake(['*' => Http::response('down', 503)]);
    expect(runtimeVersionFindings($root))->toBe([]);
});

it('caches support dates and releases between scans', function () {
    Http::fake([
        'endoflife.date/*' => Http::response(['result' => ['releases' => [['name' => '99', 'eolFrom' => '2099-01-01']]]]),
        'www.php.net/releases/*' => Http::response([running() => ['tags' => ['security']]]),
    ]);
    $root = $this->project(['composer.json' => '{}']);

    runtimeVersionFindings($root);
    runtimeVersionFindings($root);

    // endoflife.date for php, laravel and nodejs, php.net once.
    expect(Http::recorded())->toHaveCount(4);
});

it('flags a composer.json PHP constraint that allows an unsupported version', function () {
    $root = $this->project(['composer.json' => json_encode([
        'require' => ['php' => '^8.1'],
        'config' => ['platform' => ['php' => '8.0.30']],
    ])]);

    expect(runtimeVersionFindings($root, offline: true))->toBe([
        ['medium', 'composer.json require.php "^8.1" allows PHP 8.1, which stopped receiving security fixes on 2025-12-31.', 'composer.json'],
        ['medium', 'composer.json config.platform.php "8.0.30" allows PHP 8.0, which stopped receiving security fixes on 2023-11-26.', 'composer.json'],
    ]);

    expect(runtimeVersionFindings($this->project(['composer.json' => json_encode(['require' => ['php' => '^8.4']])]), offline: true))->toBe([]);
});

it('checks Node versions pinned anywhere in the project', function () {
    $root = $this->project([
        'composer.json' => '{}',
        '.nvmrc' => "v20.11.1\n",
        'package.json' => json_encode(['engines' => ['node' => '>=18'], 'volta' => ['node' => '22.1.0']]),
        'Dockerfile' => "FROM node:20-alpine AS assets\nRUN npm ci\nFROM node:20-alpine\nFROM node:lts\n",
        'docker-compose.yml' => "services:\n  vite:\n    image: node:22\n",
        '.github/workflows/ci.yml' => "jobs:\n  build:\n    steps:\n      - uses: actions/setup-node@v4\n        with:\n          node-version: [18, '22.x']\n      - with:\n          node-version: \${{ matrix.node }}\n",
    ]);

    expect(runtimeVersionFindings($root, offline: true))->toBe([
        ['high', 'Node 18 (.github/workflows/ci.yml:6) stopped receiving security fixes on 2025-04-30.', '.github/workflows/ci.yml:6'],
        ['high', 'Node 20 (.nvmrc:1) stopped receiving security fixes on 2026-04-30.', '.nvmrc:1'],
        ['high', 'Node 20 (Dockerfile:1) stopped receiving security fixes on 2026-04-30.', 'Dockerfile:1'],
        ['high', 'Node 18 (package.json engines.node) stopped receiving security fixes on 2025-04-30.', 'package.json'],
    ]);

    config()->set('risk-analyzer.runtime.node', false);
    app()->forgetInstance(RiskAnalyzer::class);

    expect(runtimeVersionFindings($root, offline: true))->toBe([]);
});

it('reads Node majors from versions and ranges', function (string $value, ?int $major, ?int $lowest) {
    expect(NodeVersions::major($value))->toBe($major)
        ->and(NodeVersions::lowestMajor($value))->toBe($lowest);
})->with([
    ['20', 20, 20],
    ['v20.11.1', 20, 20],
    ['20-alpine', 20, 20],
    ['20.x', 20, 20],
    ['lts/*', null, null],
    ['current', null, null],
    ['>=18', null, 18],
    ['^20 || ^22', null, 20],
    ['>=18.0.0 <23', null, 18],
]);

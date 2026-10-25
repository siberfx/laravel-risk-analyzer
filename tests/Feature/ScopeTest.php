<?php

use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Http;
use Siberfx\RiskAnalyzer\RiskAnalyzer;

function mixedProject(): array
{
    $lock = fn (string $package) => json_encode(['lockfileVersion' => 3, 'packages' => ['' => ['name' => 'app'], "node_modules/{$package}" => ['version' => '1.0.0']]]);

    return [
        'app/Http/Controllers/A.php' => controllerAction('exec($request->input("cmd"));'),
        'resources/js/app.js' => "eval(location.hash);\n",
        'client/src/main.ts' => "document.write(location.search);\n",
        'docker/Dockerfile' => "FROM php:8.1-fpm\nRUN chmod -R 777 /var/www\n",
        'deploy/release.sh' => "curl https://get.example.com | sh\n",
        'composer.lock' => json_encode(['packages' => [['name' => 'acme/php-lib', 'version' => '1.0.0']]]),
        'package-lock.json' => $lock('root-lib'),
        'client/package-lock.json' => $lock('client-lib'),
    ];
}

/**
 * @return list<string> package names sent to OSV
 */
function queriedPackages(): array
{
    return Http::recorded()
        ->filter(fn (array $pair) => str_ends_with($pair[0]->url(), '/v1/querybatch'))
        ->flatMap(fn (array $pair) => collect($pair[0]['queries'])->pluck('package.name'))
        ->values()->all();
}

function scanScoped(string $root, array $options): array
{
    $report = app(RiskAnalyzer::class)->scan(...['baseline' => false, 'basePath' => $root, ...$options]);

    return [
        'rules' => collect(array_keys($report->rules))->sort()->values()->all(),
        'files' => collect($report->findings)->pluck('file')->filter()->unique()->sort()->values()->all(),
        'report' => $report,
    ];
}

beforeEach(fn () => Http::fake(['api.osv.dev/*' => Http::response(['results' => []])]));

it('limits --frontend to the frontend rules and the frontend lockfiles', function () {
    $scan = scanScoped($this->project(mixedProject()), ['frontend' => []]);

    expect($scan['rules'])->toBe(['frontend-code-execution', 'frontend-debug', 'frontend-open-redirect', 'frontend-postmessage', 'frontend-secret', 'frontend-token-storage', 'vulnerable-dependency', 'xss-frontend'])
        ->and($scan['files'])->toBe(['resources/js/app.js'])
        // resources/js has no lockfile of its own, so the root one is the frontend's; composer.lock is not.
        ->and(queriedPackages())->toBe(['root-lib']);
});

it('checks only the lockfiles of --frontend folders', function () {
    $scan = scanScoped($this->project(mixedProject()), ['frontend' => ['client']]);

    expect($scan['files'])->toBe(['client/src/main.ts'])
        ->and($scan['report']->frontend)->toBe(['client'])
        ->and(queriedPackages())->toBe(['client-lib']);
});

it('limits --infrastructure to the Docker, CI and script rules and pinned versions', function () {
    $scan = scanScoped($this->project(mixedProject()), ['infrastructure' => [], 'offline' => true]);

    expect($scan['rules'])->toBe(['ci-workflow-risks', 'compose-hardening', 'dockerfile-hardening', 'shell-script-risks', 'unsupported-runtime'])
        ->and($scan['files'])->toBe(['deploy/release.sh', 'docker/Dockerfile'])
        ->and(collect($scan['report']->findings)->where('rule', 'unsupported-runtime')->pluck('message')->all())
        ->each->toContain('(base image)')
        ->and($scan['report']->infrastructure)->toBe(['.']);

    expect(scanScoped($this->project(mixedProject()), ['infrastructure' => ['deploy'], 'offline' => true])['files'])->toBe(['deploy/release.sh']);
});

it('runs both scopes together, and narrows them with --only and --skip', function () {
    $root = $this->project(mixedProject());

    expect(scanScoped($root, ['frontend' => [], 'infrastructure' => [], 'offline' => true])['files'])
        ->toBe(['deploy/release.sh', 'docker/Dockerfile', 'resources/js/app.js'])
        ->and(scanScoped($root, ['frontend' => [], 'only' => ['xss-frontend', 'frontend-code-execution'], 'skip' => ['frontend-code-execution']])['rules'])->toBe(['xss-frontend'])
        ->and(fn () => scanScoped($root, ['frontend' => [], 'only' => ['sql-injection']]))
        ->toThrow(InvalidArgumentException::class, 'None of [sql-injection] belong to the --frontend scan.');
});

it('still runs everything without a scope', function () {
    $scan = scanScoped($this->project(mixedProject()), ['offline' => true]);

    expect($scan['rules'])->toHaveCount(count(app(RiskAnalyzer::class)->rules()))
        ->and($scan['files'])->toContain('app/Http/Controllers/A.php', 'resources/js/app.js', 'docker/Dockerfile');
});

it('takes a bare --frontend and --infrastructure on the command line', function () {
    $this->app->setBasePath($this->project(mixedProject()));

    Artisan::call('risk-analyzer:scan', ['--frontend' => [null], '--offline' => true, '--no-baseline' => true, '--fail-on' => 'critical']);
    $output = Artisan::output();

    expect($output)->toContain('8 rules')
        ->toContain('frontend: resources/js')
        ->toContain('resources/js/app.js')
        ->not->toContain('app/Http/Controllers/A.php')
        ->not->toContain('docker/Dockerfile');

    Artisan::call('risk-analyzer:scan', ['--infrastructure' => ['deploy'], '--offline' => true, '--no-baseline' => true]);

    expect(Artisan::output())->toContain('5 rules')->toContain('infrastructure: deploy')->toContain('deploy/release.sh');

    $this->artisan('risk-analyzer:scan', ['--infrastructure' => ['missing']])
        ->expectsOutputToContain('Infrastructure folder [missing] does not exist.')
        ->assertExitCode(2);
});

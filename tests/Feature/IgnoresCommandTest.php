<?php

use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Route;
use Siberfx\RiskAnalyzer\Attributes\RiskAnalyzerIgnore;
use Siberfx\RiskAnalyzer\RiskAnalyzer;
use Siberfx\RiskAnalyzer\Support\IgnoreInventory;

/**
 * @return list<array<string, mixed>>
 */
function inventory(string $root): array
{
    return IgnoreInventory::collect(app(RiskAnalyzer::class)->context($root));
}

it('lists config ignores with their reasons and masks secret values', function () {
    $root = $this->project([]);
    config()->set('risk-analyzer.routes.ignore', ['admin/sso/*' => 'SSO entry points', 'admin/preview']);
    config()->set('risk-analyzer.dependencies.ignore', ['GHSA-xxxx-xxxx-xxxx']);
    config()->set('risk-analyzer.secrets.allow', ['sk_test_documented_example']);
    config()->set('risk-analyzer.rules.disabled', ['debug-leftover']);

    $entries = collect(inventory($root));
    $routes = $entries->where('kind', 'route-config')->values();

    expect($routes[0]['target'])->toBe('admin/sso/*')
        ->and($routes[0]['reason'])->toBe('SSO entry points')
        ->and($routes[1]['target'])->toBe('admin/preview')
        ->and($routes[1]['reason'])->toBeNull()
        ->and($entries->firstWhere('kind', 'dependency')['reason'])->toBeNull()
        ->and($entries->firstWhere('kind', 'secret')['target'])->toBe('sk_t…')
        ->and($entries->firstWhere('kind', 'rule')['rules'])->toBe(['all']);

    // A snapshot file must not contain the secret itself.
    expect(json_encode(inventory($root)))->not->toContain('sk_test_documented_example');
});

it('finds inline ignores in PHP, Blade, React and infrastructure files, with their reasons', function () {
    $root = $this->project([
        'app/Http/Controllers/Report.php' => "<?php\n// risk-analyzer-ignore sql-injection -- table name comes from an enum\n\$x = 1;\n\$y = 2; // risk-analyzer-ignore\n",
        'resources/views/post.blade.php' => "{{-- risk-analyzer-ignore xss-blade -- sanitised by HTMLPurifier --}}\n",
        'resources/js/Comment.jsx' => "{/* risk-analyzer-ignore xss-frontend -- HTML is sanitised by the API */}\n",
        'docker/Dockerfile' => "FROM php:8.3\n# risk-analyzer-ignore dockerfile-hardening -- internal mirror\n",
    ]);

    $inline = collect(inventory($root))->where('kind', 'inline')->values();

    expect($inline->map(fn (array $entry) => [$entry['where'], $entry['rules'], $entry['reason']])->all())->toBe([
        ['app/Http/Controllers/Report.php:2', ['sql-injection'], 'table name comes from an enum'],
        ['app/Http/Controllers/Report.php:4', ['all'], null],
        ['resources/views/post.blade.php:1', ['xss-blade'], 'sanitised by HTMLPurifier'],
        ['resources/js/Comment.jsx:1', ['xss-frontend'], 'HTML is sanitised by the API'],
        ['docker/Dockerfile:2', ['dockerfile-hardening'], 'internal mirror'],
    ]);
});

it('lists route attributes with their reasons', function () {
    Route::get('admin/status', #[RiskAnalyzerIgnore('unprotected-route', reason: 'public status page')] fn () => 'ok');
    Route::get('admin/plain', fn () => 'ok');

    $routes = collect(inventory($this->project([])))->where('kind', 'route-attribute');

    expect($routes->count())->toBe(1)
        ->and($routes->first()['target'])->toBe('GET|HEAD admin/status')
        ->and($routes->first()['rules'])->toBe(['unprotected-route'])
        ->and($routes->first()['reason'])->toBe('public status page');
});

it('reports only ignores that the snapshot does not list', function () {
    $root = $this->project(['app/A.php' => "<?php\n// risk-analyzer-ignore sql-injection -- first\n"]);
    $snapshot = inventory($root);

    expect(IgnoreInventory::added(inventory($root), $snapshot))->toBe([]);

    $root2 = $this->project(['app/A.php' => "<?php\n// risk-analyzer-ignore sql-injection -- first\n// risk-analyzer-ignore command-injection -- second\n"]);
    $added = IgnoreInventory::added(inventory($root2), $snapshot);

    expect(array_column($added, 'where'))->toBe(['app/A.php:3']);
});

it('fails the --check when an ignore is added and passes when the snapshot matches', function () {
    $root = $this->project(['app/A.php' => "<?php\n// risk-analyzer-ignore sql-injection -- first\n"]);
    $snapshot = $root.'/.risk-analyzer-ignores.json';
    file_put_contents($snapshot, json_encode(inventory($root)));

    // The command scans the application's own base path, so the test project becomes the application.
    app()->setBasePath($root);
    app()->forgetInstance(RiskAnalyzer::class);

    expect(Artisan::call('risk-analyzer:ignores', ['--check' => $snapshot]))->toBe(0);

    file_put_contents($root.'/app/A.php', "<?php\n// risk-analyzer-ignore sql-injection -- first\n// risk-analyzer-ignore xss-echo -- new one\n");

    expect(Artisan::call('risk-analyzer:ignores', ['--check' => $snapshot]))->toBe(1)
        ->and(Artisan::output())->toContain('1 new ignore(s)')->toContain('new one');
});

<?php

use Siberfx\RiskAnalyzer\RiskAnalyzerServiceProvider;
use Siberfx\RiskAnalyzer\Support\ConfigMerger;
use Siberfx\RiskAnalyzer\Support\ConfigSynchronizer;

const OLD_CONFIG = <<<'PHP'
<?php

return [

    // Ours: stricter in CI.
    'fail_on' => env('RISK_ANALYZER_FAIL_ON', 'medium'),

    'routes' => [
        'auth_middleware' => ['auth'],
        'admin_patterns' => ['admin'], // only /admin is ours
    ],

];
PHP;

it('merges nested defaults but keeps published lists whole', function () {
    $merged = ConfigMerger::merge(
        ['routes' => ['admin_patterns' => ['admin', 'dashboard'], 'auth_flow_patterns' => ['callback']], 'paths' => ['app', 'config']],
        ['routes' => ['admin_patterns' => ['admin']], 'paths' => ['src']],
    );

    expect($merged)->toBe([
        'routes' => ['admin_patterns' => ['admin'], 'auth_flow_patterns' => ['callback']],
        'paths' => ['src'],
    ]);
});

it('fills options added to nested sections for apps with an older published config', function () {
    config()->set('risk-analyzer', ['routes' => ['admin_patterns' => ['admin']]]);

    (new RiskAnalyzerServiceProvider(app()))->register();

    expect(config('risk-analyzer.routes.admin_patterns'))->toBe(['admin'])
        ->and(config('risk-analyzer.routes.auth_flow_patterns'))->toContain('callback')
        ->and(config('risk-analyzer.routes.auth_middleware'))->toContain('can');
});

it('adds missing config keys without touching what the user wrote', function () {
    $result = (new ConfigSynchronizer)->sync((string) file_get_contents(__DIR__.'/../../config/risk-analyzer.php'), OLD_CONFIG);

    expect($result['added'])->toContain('routes.auth_flow_patterns', 'routes.ignore', 'paths', 'secrets')
        ->not->toContain('routes.admin_patterns', 'fail_on')
        ->and($result['code'])->toContain("// Ours: stricter in CI.\n    'fail_on' => env('RISK_ANALYZER_FAIL_ON', 'medium'),")
        ->toContain("        'admin_patterns' => ['admin'], // only /admin is ours\n        'sensitive_patterns' => [")
        ->toContain("        'auth_flow_patterns' => ['callback', 'oauth', 'sso', 'saml', 'webhook', 'webhooks'],\n        'ignore' => [],\n    ],\n")
        ->toContain("    'dependencies' => [\n        'endpoint' => env('RISK_ANALYZER_OSV_ENDPOINT', 'https://api.osv.dev'),")
        ->toContain("    |\n    | Literal values that look like secrets")
        ->not->toMatch('/[ \t]+\n/');

    $written = sys_get_temp_dir().'/risk-analyzer-config-'.bin2hex(random_bytes(4)).'.php';
    file_put_contents($written, $result['code']);
    $loaded = require $written;
    unlink($written);

    expect($loaded['routes']['admin_patterns'])->toBe(['admin'])
        ->and($loaded['routes']['ignore'])->toBe([])
        ->and((new ConfigSynchronizer)->sync((string) file_get_contents(__DIR__.'/../../config/risk-analyzer.php'), $result['code'])['added'])->toBe([]);
});

it('syncs the published config file from the command', function () {
    $root = $this->project(['risk-analyzer.php' => OLD_CONFIG]);
    $this->app->useConfigPath($root);

    $this->artisan('risk-analyzer:config-sync', ['--check' => true])
        ->expectsOutputToContain('routes.auth_flow_patterns')
        ->assertFailed();

    $this->artisan('risk-analyzer:config-sync', ['--dry-run' => true])->assertSuccessful();
    expect(file_get_contents($root.'/risk-analyzer.php'))->toBe(OLD_CONFIG);

    $this->artisan('risk-analyzer:config-sync')
        ->expectsOutputToContain('Added')
        ->assertSuccessful();

    expect(file_get_contents($root.'/risk-analyzer.php'))->toContain("'auth_flow_patterns' =>");

    $this->artisan('risk-analyzer:config-sync', ['--check' => true])
        ->expectsOutputToContain('up to date')
        ->assertSuccessful();
});

it('does nothing when the config is not published', function () {
    $this->app->useConfigPath($this->project([]));

    $this->artisan('risk-analyzer:config-sync')
        ->expectsOutputToContain('not published')
        ->assertSuccessful();
});

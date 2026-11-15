<?php

use Illuminate\Support\Facades\Route;
use Siberfx\RiskAnalyzer\Finding;
use Siberfx\RiskAnalyzer\RiskAnalyzer;

/**
 * @return list<string> messages of unprotected-route findings
 */
function adminRouteMessages(): array
{
    app()->forgetInstance(RiskAnalyzer::class);

    return collect(app(RiskAnalyzer::class)->scan(only: ['unprotected-route'], baseline: false, offline: true, production: true)->findings)
        ->map(fn (Finding $finding) => $finding->message)
        ->values()
        ->all();
}

it('reports an SPA admin shell and its unprotected API until routes.ignore covers it', function () {
    Route::get('admin/{any?}', fn () => 'spa')->where('any', '.*');
    Route::get('admin/api/users', fn () => 'json')->name('admin.api.users');

    expect(adminRouteMessages())->toHaveCount(2);

    config()->set('risk-analyzer.routes.ignore', ['admin/*' => 'React admin, the API checks itself']);

    expect(adminRouteMessages())->toBe([]);
});

it('skips admin detection entirely when admin_patterns is empty', function () {
    Route::get('admin/users', fn () => 'users');
    config()->set('risk-analyzer.routes.admin_patterns', []);

    expect(adminRouteMessages())->toBe([]);
});

it('excludes an admin folder of the frontend with frontend.exclude', function () {
    $root = $this->project([
        'resources/js/admin/Panel.jsx' => "export default () => <div dangerouslySetInnerHTML={{ __html: location.hash }} />;\n",
        'resources/js/shop/Page.jsx' => "export default () => <div dangerouslySetInnerHTML={{ __html: location.hash }} />;\n",
    ]);
    config()->set('risk-analyzer.frontend.exclude', ['node_modules', 'resources/js/admin']);
    app()->forgetInstance(RiskAnalyzer::class);

    $files = collect(app(RiskAnalyzer::class)->scan(only: ['frontend'], baseline: false, offline: true, basePath: $root)->findings)
        ->pluck('file')
        ->unique()
        ->values()
        ->all();

    expect($files)->toBe(['resources/js/shop/Page.jsx']);
});

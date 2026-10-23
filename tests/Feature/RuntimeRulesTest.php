<?php

use Illuminate\Foundation\Http\Middleware\PreventRequestForgery;
use Illuminate\Support\Facades\Route;
use Siberfx\RiskAnalyzer\Finding;
use Siberfx\RiskAnalyzer\RiskAnalyzer;

function runtimeFindings(string $rule, bool $production = true): array
{
    return collect(app(RiskAnalyzer::class)->scan(only: [$rule], production: $production, baseline: false)->findings)
        ->map(fn (Finding $finding) => [$finding->severity->value, $finding->message])
        ->all();
}

afterEach(function () {
    if (class_exists(PreventRequestForgery::class)) {
        PreventRequestForgery::flushState();
    }
});

it('flags debug mode only in production', function () {
    config()->set('app.debug', true);

    expect(runtimeFindings('debug-mode'))->toContain(['critical', 'APP_DEBUG is true in production.'])
        ->and(runtimeFindings('debug-mode', production: false))->toBeEmpty();
});

it('checks the encryption key', function () {
    config()->set('app.key', '');
    expect(runtimeFindings('encryption-key')[0][0])->toBe('critical');

    config()->set('app.key', 'base64:'.base64_encode('too-short'));
    expect(runtimeFindings('encryption-key')[0])->toBe(['high', 'APP_KEY is not a valid key for AES-256-CBC.']);
});

it('flags a production key copied from .env.example', function () {
    $key = config('app.key');
    $root = $this->project(['.env.example' => "APP_NAME=Laravel\nAPP_KEY={$key}\n"]);

    $findings = app(RiskAnalyzer::class)->scan(only: ['encryption-key'], production: true, baseline: false, basePath: $root)->findings;

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->message)->toContain('.env.example');
});

it('checks session cookie flags', function () {
    config()->set('session.http_only', false);
    config()->set('session.secure', false);
    config()->set('session.same_site', 'none');

    $severities = array_column(runtimeFindings('session-cookies'), 0);

    expect($severities)->toBe(['high', 'high', 'medium']);
});

it('flags wildcard CORS with credentials', function () {
    config()->set('cors', ['paths' => ['api/*'], 'allowed_origins' => ['*'], 'supports_credentials' => true]);

    expect(runtimeFindings('cors-policy'))->toBe([['high', 'CORS allows any origin and supports credentials.']]);
});

it('flags unescaped CORS origin patterns', function () {
    config()->set('cors', ['allowed_origins' => [], 'allowed_origins_patterns' => ['#^https://example.com$#']]);

    expect(runtimeFindings('cors-policy')[0][0])->toBe('medium');
});

it('flags cheap bcrypt settings', function () {
    config()->set('hashing.driver', 'bcrypt');
    config()->set('hashing.bcrypt.rounds', 4);

    expect(runtimeFindings('password-hashing'))->toBe([['medium', 'bcrypt uses 4 rounds.']]);
});

it('flags a catch-all CSRF exclusion', function () {
    PreventRequestForgery::except(['*']);

    expect(runtimeFindings('csrf-exclusions')[0][0])->toBe('critical');
});

it('matches CSRF exclusions against real routes', function () {
    PreventRequestForgery::except(['webhooks/*', 'account/*']);

    Route::middleware('web')->group(function () {
        Route::post('webhooks/stripe', fn () => 'ok');
        Route::middleware('auth')->post('account/delete', fn () => 'ok');
        Route::get('account/show', fn () => 'ok');
        Route::post('profile', fn () => 'ok');
    });

    expect(runtimeFindings('csrf-exclusions'))->toBe([
        ['high', "POST account/delete is excluded from CSRF verification by 'account/*' and uses session authentication."],
        ['low', "POST webhooks/stripe is excluded from CSRF verification by 'webhooks/*'."],
    ]);
});

it('flags admin routes without authentication and auth routes without throttling', function () {
    Route::middleware('web')->group(function () {
        Route::get('admin/users', fn () => 'list');
        Route::middleware(['auth', 'can:admin'])->get('admin/settings', fn () => 'ok');
        Route::post('login', fn () => 'ok');
        Route::middleware('throttle:5,1')->post('forgot-password', fn () => 'ok');
        Route::get('dashboard', fn () => 'home')->middleware('auth');
    });

    Route::middlewareGroup('secure', ['auth']);
    Route::middleware('secure')->get('panel/reports', fn () => 'ok');

    $messages = array_column(runtimeFindings('unprotected-route'), 1);

    expect($messages)->toBe([
        'GET|HEAD admin/users looks like an admin route but has no authentication middleware.',
        'POST login accepts credentials or codes without rate limiting.',
    ]);
});

it('flags dev tools required for production and debug routes', function () {
    $root = $this->project(['composer.json' => json_encode(['require' => ['php' => '^8.4', 'barryvdh/laravel-debugbar' => '^3.0']])]);
    config()->set('debugbar.enabled', true);
    Route::get('_debugbar/open', fn () => 'x');

    $findings = collect(app(RiskAnalyzer::class)->scan(only: ['dev-tools-exposed'], production: true, baseline: false, basePath: $root)->findings)
        ->map(fn ($f) => $f->severity->value)->all();

    expect($findings)->toBe(['critical', 'high', 'medium']);
});

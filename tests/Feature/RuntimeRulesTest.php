<?php

use Illuminate\Foundation\Http\Middleware\PreventRequestForgery;
use Illuminate\Foundation\Http\Middleware\VerifyCsrfToken;
use Illuminate\Support\Facades\Route;
use Siberfx\RiskAnalyzer\Attributes\RiskAnalyzerIgnore;
use Siberfx\RiskAnalyzer\Finding;
use Siberfx\RiskAnalyzer\RiskAnalyzer;
use Symfony\Component\Process\Process;

/**
 * The CSRF middleware of the installed Laravel version (renamed in Laravel 13).
 */
function csrfMiddleware(): string
{
    return class_exists(PreventRequestForgery::class) ? PreventRequestForgery::class : VerifyCsrfToken::class;
}

function runtimeFindings(string $rule, bool $production = true): array
{
    return collect(app(RiskAnalyzer::class)->scan(only: [$rule], production: $production, baseline: false)->findings)
        ->map(fn (Finding $finding) => [$finding->severity->value, $finding->message])
        ->all();
}

final class IgnoredMethodController
{
    #[RiskAnalyzerIgnore('unprotected-route', reason: 'OAuth callback')]
    public function callback(): string
    {
        return 'ok';
    }

    public function other(): string
    {
        return 'ok';
    }
}

abstract class BaseAdminController
{
    public function __invoke(): string
    {
        return 'ok';
    }
}

#[RiskAnalyzerIgnore]
final class IgnoredClassController extends BaseAdminController {}

/**
 * unprotected-route findings without the trailing "(file:line)" of the route's handler.
 */
function routeFindings(): array
{
    return array_map(fn (array $finding) => [$finding[0], preg_replace('/ \([^()]+:\d+\)$/', '', $finding[1])], runtimeFindings('unprotected-route'));
}

afterEach(function () {
    if (method_exists(csrfMiddleware(), 'flushState')) {
        csrfMiddleware()::flushState();
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
    csrfMiddleware()::except(['*']);

    expect(runtimeFindings('csrf-exclusions')[0][0])->toBe('critical');
});

it('matches CSRF exclusions against real routes', function () {
    csrfMiddleware()::except(['webhooks/*', 'account/*']);

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

    $messages = array_column(routeFindings(), 1);

    expect($messages)->toBe([
        'GET|HEAD admin/users looks like an admin route but has no authentication middleware.',
        'POST login accepts credentials or codes without rate limiting.',
    ]);
});

it('points admin route findings at the closure or controller that handles them', function () {
    $line = __LINE__ + 1;
    Route::get('admin/users', fn () => 'list');

    expect(runtimeFindings('unprotected-route')[0][1])->toEndWith("RuntimeRulesTest.php:{$line})");
});

it('checks OAuth callbacks and webhooks for rate limiting and signatures instead of auth', function () {
    Route::get('admin/auth/google/callback', fn () => 'ok');
    Route::middleware('throttle:10,1')->get('admin/auth/github/callback', fn () => 'ok');
    Route::post('admin/webhooks/stripe', fn () => 'ok');
    Route::middleware('signed')->post('admin/webhooks/mollie', fn () => 'ok');

    expect(routeFindings())->toBe([
        ['low', 'GET|HEAD admin/auth/google/callback is an OAuth/SSO callback; public by design, but it has no rate limiting.'],
        ['low', 'POST admin/webhooks/stripe is a public webhook with no signature-verification middleware.'],
    ]);
});

it('judges SPA catch-all routes by the API routes they call', function () {
    Route::get('admin/{any?}', fn () => view('welcome'));
    Route::middleware('auth:sanctum')->get('api/admin/users', fn () => []);

    expect(routeFindings())->toBe([
        ['info', 'GET|HEAD admin/{any?} serves a single-page app shell publicly; its 1 API routes require authentication.'],
    ]);

    Route::get('api/admin/stats', fn () => []);

    expect(routeFindings())->toBe([
        ['high', 'GET|HEAD admin/{any?} serves a single-page app whose API routes have no authentication: GET|HEAD api/admin/stats.'],
        ['high', 'GET|HEAD api/admin/stats looks like an admin route but has no authentication middleware.'],
    ]);
});

it('flags SPA catch-alls whose API cannot be found, and only for wildcard parameters', function () {
    Route::get('dashboard/{path}', fn () => 'spa')->where('path', '.*');
    Route::get('admin/users/{user}', fn () => 'user');

    expect(routeFindings())->toBe([
        ['high', 'GET|HEAD admin/users/{user} looks like an admin route but has no authentication middleware.'],
        ['low', 'GET|HEAD dashboard/{path} serves a single-page app shell without authentication, and API routes under api/dashboard or dashboard/api could not be found to check.'],
    ]);
});

it('skips routes whose handler has #[RiskAnalyzerIgnore], and routes in the routes.ignore config', function () {
    Route::get('admin/public', #[RiskAnalyzerIgnore('unprotected-route', reason: 'status page')] fn () => 'ok');
    Route::get('admin/everything', #[RiskAnalyzerIgnore] fn () => 'ok');
    Route::get('admin/other-rule', #[RiskAnalyzerIgnore('csrf-exclusions')] fn () => 'ok');
    Route::get('admin/callback-method', [IgnoredMethodController::class, 'callback']);
    Route::get('admin/other-method', [IgnoredMethodController::class, 'other']);
    Route::get('admin/whole-class', IgnoredClassController::class);
    Route::get('admin/sso/start', fn () => 'ok')->name('admin.sso.start');
    Route::get('admin/preview', fn () => 'ok');
    config()->set('risk-analyzer.routes.ignore', ['admin.sso.*' => 'SSO entry point', 'admin/preview']);

    expect(array_column(routeFindings(), 1))->toBe([
        'GET|HEAD admin/other-rule looks like an admin route but has no authentication middleware.',
        'GET|HEAD admin/other-method looks like an admin route but has no authentication middleware.',
    ]);
});

it('keeps routes with #[RiskAnalyzerIgnore] working when the package is not installed', function () {
    // A plain PHP process without Composer's autoloader stands in for composer install --no-dev.
    $script = $this->project(['routes.php' => <<<'PHP'
        <?php

        use Siberfx\RiskAnalyzer\Attributes\RiskAnalyzerIgnore;

        #[RiskAnalyzerIgnore('unprotected-route', reason: 'OAuth callback')]
        final class CallbackController
        {
            #[RiskAnalyzerIgnore]
            public function __invoke(): string
            {
                return 'controller';
            }
        }

        $closure = #[RiskAnalyzerIgnore('unprotected-route')] fn () => 'closure';

        // Laravel reads its own attributes (e.g. controller middleware) the same way.
        $reflected = count((new ReflectionClass(CallbackController::class))->getAttributes(Illuminate\Routing\Attributes\Controllers\Middleware::class));

        echo class_exists(RiskAnalyzerIgnore::class, false) ? 'loaded' : 'not loaded', ' ', (new CallbackController)(), ' ', $closure(), ' ', $reflected;
        PHP]).'/routes.php';

    $process = new Process([PHP_BINARY, '-n', $script]);
    $process->run();

    expect($process->getErrorOutput())->toBe('')
        ->and($process->getOutput())->toBe('not loaded controller closure 0');
});

it('flags dev tools required for production and debug routes', function () {
    $root = $this->project(['composer.json' => json_encode(['require' => ['php' => '^8.4', 'barryvdh/laravel-debugbar' => '^3.0']])]);
    config()->set('debugbar.enabled', true);
    Route::get('_debugbar/open', fn () => 'x');

    $findings = collect(app(RiskAnalyzer::class)->scan(only: ['dev-tools-exposed'], production: true, baseline: false, basePath: $root)->findings)
        ->map(fn ($f) => $f->severity->value)->all();

    expect($findings)->toBe(['critical', 'high', 'medium']);
});

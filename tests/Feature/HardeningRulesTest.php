<?php

use Illuminate\Http\Middleware\TrustProxies;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\URL;
use Siberfx\RiskAnalyzer\Finding;
use Siberfx\RiskAnalyzer\RiskAnalyzer;

/**
 * @return list<array{string, string}> severity, message
 */
function hardeningFindings(string $rule, bool $production = true, bool $offline = false): array
{
    app()->forgetInstance(RiskAnalyzer::class);

    return collect(app(RiskAnalyzer::class)->scan(only: [$rule], production: $production, offline: $offline, baseline: false)->findings)
        ->map(fn (Finding $finding) => [$finding->severity->value, $finding->message])
        ->all();
}

/**
 * @param  array<string, string>  $headers
 */
function pageWithHeaders(array $headers): void
{
    Route::get('/', fn () => response('home', 200, $headers));
}

const SAFE_HEADERS = [
    'X-Frame-Options' => 'SAMEORIGIN',
    'Strict-Transport-Security' => 'max-age=31536000; includeSubDomains',
    'X-Content-Type-Options' => 'nosniff',
    'Content-Security-Policy' => "default-src 'self'; script-src 'self' 'nonce-abc' 'unsafe-inline'",
    'Referrer-Policy' => 'strict-origin-when-cross-origin',
];

afterEach(fn () => TrustProxies::flushState());

it('reports missing security headers set by the app', function () {
    config()->set('app.url', 'https://example.com');
    pageWithHeaders([]);

    expect(hardeningFindings('security-headers'))->toBe([
        ['medium', 'The app does not set X-Frame-Options or a CSP frame-ancestors directive, so other sites can frame its pages (clickjacking).'],
        ['medium', 'The app does not set Strict-Transport-Security, so browsers may still try plain HTTP first.'],
        ['low', 'The app does not set X-Content-Type-Options: nosniff, so browsers may guess content types (MIME sniffing).'],
        ['low', 'The app does not set a Content-Security-Policy, which limits the damage of an XSS bug.'],
        ['low', 'The app does not set Referrer-Policy.'],
    ]);
});

it('accepts a hardened response and only checks in production', function () {
    config()->set('app.url', 'https://example.com');
    pageWithHeaders(SAFE_HEADERS);

    expect(hardeningFindings('security-headers'))->toBe([]);

    pageWithHeaders([]);
    expect(hardeningFindings('security-headers', production: false))->toBe([]);
});

it('flags weak header values', function () {
    config()->set('app.url', 'https://example.com');
    pageWithHeaders([
        ...SAFE_HEADERS,
        'X-Frame-Options' => null,
        'Content-Security-Policy' => "frame-ancestors 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'",
        'Strict-Transport-Security' => 'max-age=3600',
        'Referrer-Policy' => 'unsafe-url',
    ]);

    expect(hardeningFindings('security-headers'))->toBe([
        ['low', 'Strict-Transport-Security max-age is 3600 seconds, less than six months.'],
        ['low', "The Content-Security-Policy allows 'unsafe-inline' and 'unsafe-eval' scripts, so it does not stop injected scripts."],
        ['low', 'Referrer-Policy is unsafe-url, so full URLs (with tokens in query strings) leak to other sites.'],
    ]);
});

it('skips HSTS on plain HTTP and reports a failing page as info', function () {
    config()->set('app.url', 'http://example.com');
    pageWithHeaders([...SAFE_HEADERS, 'Strict-Transport-Security' => null]);

    expect(hardeningFindings('security-headers'))->toBe([]);

    Route::get('/', fn () => throw new RuntimeException('no database'));

    expect(hardeningFindings('security-headers'))->toBe([
        ['info', 'Security headers could not be checked: http://example.com/ answered HTTP 500.'],
    ]);

    config()->set('risk-analyzer.http.probe_path', false);
    expect(hardeningFindings('security-headers'))->toBe([]);
});

it('checks the live site when probe_url is set, including web server headers', function () {
    config()->set('risk-analyzer.http.probe_url', 'https://example.com');
    Http::fake(['example.com' => Http::response('home', 200, [
        ...SAFE_HEADERS,
        'X-Powered-By' => 'PHP/8.4.3',
        'Server' => 'nginx/1.18.0',
    ])]);

    expect(hardeningFindings('security-headers'))->toBe([
        ['low', 'The x-powered-by header reveals "PHP/8.4.3".'],
        ['low', 'The server header reveals "nginx/1.18.0".'],
    ]);

    config()->set('risk-analyzer.http.probe_url', 'https://example.org');
    Http::fake(['example.org' => Http::response('home', 200, ['Server' => 'nginx'])]);
    expect(hardeningFindings('security-headers')[0])->toBe(['medium', 'https://example.org does not send X-Frame-Options or a CSP frame-ancestors directive, so other sites can frame its pages (clickjacking).'])
        ->and(hardeningFindings('security-headers', offline: true))->toBe([]);
});

it('flags trusting every proxy', function () {
    expect(hardeningFindings('trusted-proxies'))->toBe([]);

    TrustProxies::at(['10.0.0.0/8']);
    expect(hardeningFindings('trusted-proxies'))->toBe([]);

    TrustProxies::at('*');
    expect(hardeningFindings('trusted-proxies', production: false))->toBe([
        ['medium', "trustProxies(at: ...) trusts every proxy ('*'), so any client can set X-Forwarded-For and spoof its IP address."],
    ]);
});

it('flags an http APP_URL and forced http in production', function () {
    config()->set('app.url', 'http://example.com');

    expect(hardeningFindings('insecure-app-url'))->toBe([
        ['medium', 'APP_URL is http://example.com, so generated links, redirects, signed URLs and mails use plain HTTP.'],
    ])->and(hardeningFindings('insecure-app-url', production: false))->toBe([]);

    URL::forceHttps();
    expect(hardeningFindings('insecure-app-url'))->toBe([]);

    URL::forceScheme('http');
    expect(hardeningFindings('insecure-app-url'))->toBe([
        ['medium', "URL::forceScheme('http') makes every generated URL use plain HTTP."],
    ]);

    URL::forceScheme(null);
    config()->set('app.url', 'http://localhost');
    expect(hardeningFindings('insecure-app-url'))->toBe([]);
});

it('flags database connections to public hosts without TLS', function () {
    $ca = defined('Pdo\Mysql::ATTR_SSL_CA') ? constant('Pdo\Mysql::ATTR_SSL_CA') : 1008;

    config()->set('database.connections', [
        'local' => ['driver' => 'mysql', 'host' => '127.0.0.1'],
        'docker' => ['driver' => 'mysql', 'host' => 'mysql'],
        'vpc' => ['driver' => 'mysql', 'host' => '10.0.3.12'],
        'k8s' => ['driver' => 'pgsql', 'host' => 'postgres.db.svc.cluster.local'],
        'socket' => ['driver' => 'mysql', 'host' => '', 'unix_socket' => '/var/run/mysqld/mysqld.sock'],
        'sqlite' => ['driver' => 'sqlite', 'database' => ':memory:'],
        'rds' => ['driver' => 'mysql', 'host' => 'app.abc123.eu-west-1.rds.amazonaws.com', 'options' => [$ca => null]],
        'rds_tls' => ['driver' => 'mysql', 'host' => 'app.abc123.eu-west-1.rds.amazonaws.com', 'options' => [$ca => '/etc/ssl/rds.pem']],
        'supabase' => ['driver' => 'pgsql', 'host' => 'db.example.supabase.co', 'sslmode' => 'prefer'],
        'neon' => ['driver' => 'pgsql', 'url' => 'postgres://user:secret@ep-1.eu-central-1.aws.neon.tech/app?sslmode=require'],
        'split' => ['driver' => 'pgsql', 'read' => ['host' => ['10.0.0.5', '203.0.113.7']], 'sslmode' => 'disable'],
    ]);

    expect(hardeningFindings('database-tls'))->toBe([
        ['medium', "Database connection 'rds' reaches app.abc123.eu-west-1.rds.amazonaws.com without TLS (no SSL CA configured)."],
        ['medium', "Database connection 'supabase' reaches db.example.supabase.co with sslmode=prefer, which allows an unencrypted, unverified connection."],
        ['medium', "Database connection 'split' reaches 203.0.113.7 with sslmode=disable, which allows an unencrypted, unverified connection."],
    ])->and(hardeningFindings('database-tls', production: false))->toBe([]);
});

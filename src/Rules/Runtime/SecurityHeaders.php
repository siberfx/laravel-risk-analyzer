<?php

namespace Siberfx\RiskAnalyzer\Rules\Runtime;

use Illuminate\Contracts\Http\Kernel as HttpKernel;
use Illuminate\Http\Client\Factory as Http;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Facade;
use Siberfx\RiskAnalyzer\Category;
use Siberfx\RiskAnalyzer\Finding;
use Siberfx\RiskAnalyzer\Rules\AbstractProjectRule;
use Siberfx\RiskAnalyzer\ScanContext;
use Siberfx\RiskAnalyzer\Severity;
use Throwable;

final class SecurityHeaders extends AbstractProjectRule
{
    private const int SIX_MONTHS = 15552000;

    public function id(): string
    {
        return 'security-headers';
    }

    public function title(): string
    {
        return 'Missing security headers';
    }

    public function description(): string
    {
        return 'Response headers of one page in production: clickjacking protection (X-Frame-Options or CSP frame-ancestors), Strict-Transport-Security, X-Content-Type-Options, Content-Security-Policy (and unsafe-inline/unsafe-eval scripts), Referrer-Policy, and version-revealing X-Powered-By/Server. The page is requested through the app (http.probe_path) or from the live site (http.probe_url, which also sees headers added by the web server).';
    }

    public function category(): Category
    {
        return Category::Runtime;
    }

    public function severity(): Severity
    {
        return Severity::Medium;
    }

    public function run(ScanContext $context): iterable
    {
        if (! $context->production) {
            return;
        }

        $live = $context->config('http.probe_url');
        $live = is_string($live) && $live !== '' ? $live : null;

        if ($live !== null && $context->offline) {
            return;
        }

        $path = $context->config('http.probe_path', '/');

        if ($live === null && (! is_string($path) || $path === '')) {
            return;
        }

        $url = $live ?? rtrim((string) $context->settings()->get('app.url', 'http://localhost'), '/').'/'.ltrim((string) $path, '/');

        try {
            [$status, $headers] = $live !== null ? $this->fetchLive($context, $url) : $this->fetchInternal($context, $url);
        } catch (Throwable $exception) {
            yield $this->finding("Security headers could not be checked: requesting {$url} failed ({$exception->getMessage()}).", Severity::Info,
                $this->probeHint($live), anchor: 'headers.probe');

            return;
        }

        if ($status >= 500) {
            yield $this->finding("Security headers could not be checked: {$url} answered HTTP {$status}.", Severity::Info,
                $this->probeHint($live), anchor: 'headers.probe');

            return;
        }

        yield from $this->check($headers, $url, $live !== null);
    }

    /**
     * @param  array<string, string>  $headers  lower-cased names
     * @return iterable<Finding>
     */
    private function check(array $headers, string $url, bool $live): iterable
    {
        $subject = $live ? $url.' does not send' : 'The app does not set';
        $elsewhere = $live ? '' : ' If your web server or CDN adds it, set risk-analyzer.http.probe_url to check the live site instead.';
        $csp = $headers['content-security-policy'] ?? null;
        $meta = ['url' => $url, 'live' => $live];

        if (! isset($headers['x-frame-options']) && ! str_contains(strtolower((string) $csp), 'frame-ancestors')) {
            yield $this->finding("{$subject} X-Frame-Options or a CSP frame-ancestors directive, so other sites can frame its pages (clickjacking).", null,
                "Send X-Frame-Options: SAMEORIGIN, or Content-Security-Policy: frame-ancestors 'self'.{$elsewhere}", anchor: 'headers.frame', meta: $meta);
        }

        if (str_starts_with(strtolower($url), 'https://')) {
            $hsts = $headers['strict-transport-security'] ?? null;
            preg_match('/max-age\s*=\s*"?(\d+)/i', (string) $hsts, $maxAge);

            if ($hsts === null) {
                yield $this->finding("{$subject} Strict-Transport-Security, so browsers may still try plain HTTP first.", null,
                    "Send Strict-Transport-Security: max-age=31536000; includeSubDomains.{$elsewhere}", anchor: 'headers.hsts', meta: $meta);
            } elseif ((int) ($maxAge[1] ?? 0) < self::SIX_MONTHS) {
                yield $this->finding('Strict-Transport-Security max-age is '.(int) ($maxAge[1] ?? 0).' seconds, less than six months.', Severity::Low,
                    'Use max-age=31536000 (one year) once HTTPS works everywhere.', anchor: 'headers.hsts-short', meta: $meta);
            }
        }

        if (strtolower(trim((string) ($headers['x-content-type-options'] ?? ''))) !== 'nosniff') {
            yield $this->finding("{$subject} X-Content-Type-Options: nosniff, so browsers may guess content types (MIME sniffing).", Severity::Low,
                "Send X-Content-Type-Options: nosniff.{$elsewhere}", anchor: 'headers.nosniff', meta: $meta);
        }

        if ($csp === null) {
            $reportOnly = isset($headers['content-security-policy-report-only']) ? ' (only a report-only policy, which blocks nothing)' : '';

            yield $this->finding("{$subject} a Content-Security-Policy{$reportOnly}, which limits the damage of an XSS bug.", Severity::Low,
                "Add a Content-Security-Policy, e.g. with spatie/laravel-csp; start in report-only mode.{$elsewhere}", anchor: 'headers.csp', meta: $meta);
        } elseif (($unsafe = $this->unsafeScripts($csp)) !== []) {
            yield $this->finding('The Content-Security-Policy allows '.implode(' and ', $unsafe).' scripts, so it does not stop injected scripts.', Severity::Low,
                "Use nonces or hashes instead of 'unsafe-inline', and remove 'unsafe-eval'.", anchor: 'headers.csp-unsafe', meta: $meta);
        }

        $referrer = strtolower(trim((string) ($headers['referrer-policy'] ?? '')));

        if ($referrer === '' || $referrer === 'unsafe-url') {
            yield $this->finding($referrer === '' ? "{$subject} Referrer-Policy." : 'Referrer-Policy is unsafe-url, so full URLs (with tokens in query strings) leak to other sites.', Severity::Low,
                "Send Referrer-Policy: strict-origin-when-cross-origin.{$elsewhere}", anchor: 'headers.referrer', meta: $meta);
        }

        foreach (['x-powered-by', 'server'] as $name) {
            $value = $headers[$name] ?? null;

            if ($value !== null && ($name === 'x-powered-by' || preg_match('/\d/', $value) === 1)) {
                yield $this->finding("The {$name} header reveals \"{$value}\".", Severity::Low,
                    $name === 'x-powered-by' ? 'Set expose_php = Off in php.ini.' : 'Hide the version in the web server (server_tokens off in nginx, ServerTokens Prod in Apache).',
                    anchor: 'headers.'.$name, meta: $meta);
            }
        }
    }

    /**
     * @return list<string>
     */
    private function unsafeScripts(string $csp): array
    {
        $directives = [];

        foreach (explode(';', strtolower($csp)) as $directive) {
            $parts = preg_split('/\s+/', trim($directive), -1, PREG_SPLIT_NO_EMPTY) ?: [];

            if ($parts !== []) {
                $directives[array_shift($parts)] = $parts;
            }
        }

        $sources = $directives['script-src'] ?? $directives['default-src'] ?? [];
        // 'unsafe-inline' is ignored by browsers when a nonce or hash is present.
        $hasNonce = array_any($sources, fn (string $source) => preg_match("/^'(nonce|sha256|sha384|sha512)-/", $source) === 1);

        return array_values(array_filter([
            in_array("'unsafe-inline'", $sources, true) && ! $hasNonce ? "'unsafe-inline'" : null,
            in_array("'unsafe-eval'", $sources, true) ? "'unsafe-eval'" : null,
        ]));
    }

    /**
     * @return array{int, array<string, string>}
     */
    private function fetchLive(ScanContext $context, string $url): array
    {
        $response = $context->app->make(Http::class)->timeout((int) $context->config('http.timeout', 10))->withoutRedirecting()->get($url);
        $headers = [];

        foreach ($response->headers() as $name => $values) {
            $headers[strtolower((string) $name)] = implode(', ', (array) $values);
        }

        return [$response->status(), $headers];
    }

    /**
     * One GET through the HTTP kernel. The console app's request binding is restored afterwards.
     *
     * @return array{int, array<string, string>}
     */
    private function fetchInternal(ScanContext $context, string $url): array
    {
        $app = $context->app;
        $previous = $app->bound('request') ? $app->make('request') : null;

        try {
            $response = $app->make(HttpKernel::class)->handle(Request::create($url, 'GET'));
        } finally {
            if ($previous !== null) {
                $app->instance('request', $previous);
            }

            Facade::clearResolvedInstance('request');
        }

        $headers = [];

        foreach ($response->headers->all() as $name => $values) {
            $headers[strtolower((string) $name)] = implode(', ', array_map('strval', $values));
        }

        return [$response->getStatusCode(), $headers];
    }

    private function probeHint(?string $live): string
    {
        return $live !== null
            ? 'Check that risk-analyzer.http.probe_url is reachable from where the scan runs.'
            : 'Point risk-analyzer.http.probe_path at a page that renders without a database or session (e.g. /up), set http.probe_url to check the live site, or set probe_path to false.';
    }
}

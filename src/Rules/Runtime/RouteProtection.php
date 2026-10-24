<?php

namespace Siberfx\RiskAnalyzer\Rules\Runtime;

use Illuminate\Routing\Route;
use Illuminate\Support\Str;
use Siberfx\RiskAnalyzer\Category;
use Siberfx\RiskAnalyzer\Finding;
use Siberfx\RiskAnalyzer\Rules\AbstractProjectRule;
use Siberfx\RiskAnalyzer\ScanContext;
use Siberfx\RiskAnalyzer\Severity;
use Siberfx\RiskAnalyzer\Support\RouteInspector;

final class RouteProtection extends AbstractProjectRule
{
    public function id(): string
    {
        return 'unprotected-route';
    }

    public function title(): string
    {
        return 'Unprotected routes';
    }

    public function description(): string
    {
        return 'Admin-looking routes (admin, dashboard, panel...) without authentication middleware, and login/password/OTP endpoints without rate limiting. OAuth/SSO callbacks, webhooks and SPA catch-all routes are public by design and are checked for what matters to them instead. Uses the registered route table with middleware groups expanded.';
    }

    public function category(): Category
    {
        return Category::Runtime;
    }

    public function severity(): Severity
    {
        return Severity::High;
    }

    public function run(ScanContext $context): iterable
    {
        $authMiddleware = array_values((array) $context->config('routes.auth_middleware', []));
        $admin = $this->pattern((array) $context->config('routes.admin_patterns', []));
        $sensitive = $this->pattern((array) $context->config('routes.sensitive_patterns', []));
        $authFlow = $this->pattern((array) $context->config('routes.auth_flow_patterns', []));
        $ignore = $this->ignorePatterns((array) $context->config('routes.ignore', []));
        $routes = iterator_to_array((new RouteInspector($context->router()))->routes($this->id()), false);

        foreach ($routes as $route) {
            if ($this->ignoredByConfig($route, $ignore)) {
                continue;
            }

            $subject = $route['uri'].' '.($route['name'] ?? '');
            $isSensitive = $sensitive !== null && preg_match($sensitive, $subject) === 1;

            if ($admin !== null && preg_match($admin, $subject) && ! $isSensitive && ! $this->isProtected($route, $authMiddleware)) {
                if ($authFlow !== null && preg_match($authFlow, $subject) === 1) {
                    yield from $this->authFlow($context, $route);
                } elseif ($route['methods'] === ['GET'] && RouteInspector::catchAllParameter($route['route']) !== null) {
                    yield $this->spaShell($context, $route, $routes, $authMiddleware);
                } else {
                    yield $this->finding("{$route['location']} looks like an admin route but has no authentication middleware.{$this->definedAt($context, $route)}", null,
                        'Put the route in a group with the auth middleware (and an authorization check such as can:). If it is public on purpose, mark it with ->riskAnalyzerIgnore(\'unprotected-route\', \'reason\').',
                        anchor: 'admin.'.$route['location'], meta: ['route' => $route['location']]);
                }
            }

            if ($isSensitive && RouteInspector::changesState($route['methods']) && ! RouteInspector::has($route['middleware'], ['throttle'])) {
                yield $this->finding("{$route['location']} accepts credentials or codes without rate limiting.", Severity::Medium,
                    'Add throttle middleware (e.g. ->middleware(\'throttle:5,1\')) to slow down brute-force attempts.',
                    anchor: 'throttle.'.$route['location'], meta: ['route' => $route['location']]);
            }
        }
    }

    /**
     * OAuth/SSO callbacks and webhooks cannot sit behind auth; check rate limiting and signatures instead.
     *
     * @param  array{route: Route, uri: string, name: ?string, methods: list<string>, middleware: list<string>, location: string}  $route
     * @return iterable<Finding>
     */
    private function authFlow(ScanContext $context, array $route): iterable
    {
        $meta = ['route' => $route['location']];

        if (preg_match('/webhook/i', $route['uri'].' '.($route['name'] ?? '')) === 1) {
            if (RouteInspector::changesState($route['methods']) && ! RouteInspector::has($route['middleware'], ['signed'])
                && ! array_any($route['middleware'], fn (string $name) => preg_match('/(Signature|Webhook)/i', $name) === 1)) {
                yield $this->finding("{$route['location']} is a public webhook with no signature-verification middleware.{$this->definedAt($context, $route)}", Severity::Low,
                    'Verify the provider\'s signature (in middleware or the controller) before trusting the payload.',
                    anchor: 'webhook.'.$route['location'], meta: $meta);
            }

            return;
        }

        if (! RouteInspector::has($route['middleware'], ['throttle'])) {
            yield $this->finding("{$route['location']} is an OAuth/SSO callback; public by design, but it has no rate limiting.{$this->definedAt($context, $route)}", Severity::Low,
                'Add throttle middleware, and make sure the callback checks the OAuth state (Socialite does unless you call stateless()).',
                anchor: 'auth-flow.'.$route['location'], meta: $meta);
        }
    }

    /**
     * A catch-all that serves a Vue/React/Inertia shell has nothing to protect itself; the API it calls does.
     *
     * @param  array{route: Route, uri: string, name: ?string, methods: list<string>, middleware: list<string>, location: string}  $route
     * @param  list<array{route: Route, uri: string, name: ?string, methods: list<string>, middleware: list<string>, location: string}>  $routes
     * @param  list<string>  $authMiddleware
     */
    private function spaShell(ScanContext $context, array $route, array $routes, array $authMiddleware): Finding
    {
        $prefix = str_contains($route['uri'], '/') ? trim(Str::beforeLast($route['uri'], '/'), '/') : '';
        $api = $prefix === '' ? [] : array_values(array_filter($routes, fn (array $candidate) => $candidate !== $route
            && (str_starts_with($candidate['uri'], "api/{$prefix}/") || str_starts_with($candidate['uri'], "{$prefix}/api/"))));
        $unprotected = array_values(array_filter($api, fn (array $candidate) => ! $this->isProtected($candidate, $authMiddleware)));
        $where = $this->definedAt($context, $route);
        $meta = ['route' => $route['location'], 'api_routes' => count($api), 'unprotected_api_routes' => array_column($unprotected, 'location')];
        $anchor = 'spa.'.$route['location'];

        if ($unprotected !== []) {
            $listed = implode(', ', array_slice(array_column($unprotected, 'location'), 0, 3)).(count($unprotected) > 3 ? ', ...' : '');

            return $this->finding("{$route['location']} serves a single-page app whose API routes have no authentication: {$listed}.{$where}", null,
                'Protect the API routes (auth:sanctum or auth, plus an authorization check). The shell route itself can stay public.',
                anchor: $anchor, meta: $meta);
        }

        if ($api === []) {
            $searched = $prefix === '' ? 'its API routes' : "API routes under api/{$prefix} or {$prefix}/api";

            return $this->finding("{$route['location']} serves a single-page app shell without authentication, and {$searched} could not be found to check.{$where}", Severity::Low,
                'The shell can be public; make sure every API endpoint the app calls requires authentication (e.g. auth:sanctum).',
                anchor: $anchor, meta: $meta);
        }

        return $this->finding("{$route['location']} serves a single-page app shell publicly; its ".count($api).' API routes require authentication.'.$where, Severity::Info,
            'Anonymous visitors can download the admin bundle. Add auth to the shell route too if its code or route names should stay private.',
            anchor: $anchor, meta: $meta);
    }

    /**
     * @param  array{middleware: list<string>}  $route
     * @param  list<string>  $authMiddleware
     */
    private function isProtected(array $route, array $authMiddleware): bool
    {
        return RouteInspector::has($route['middleware'], $authMiddleware) || $this->hasCustomGuard($route['middleware']);
    }

    /**
     * Package dashboards (Telescope, Horizon, Pulse, Filament...) ship their own authorization middleware.
     *
     * @param  list<string>  $middleware
     */
    private function hasCustomGuard(array $middleware): bool
    {
        return array_any($middleware, fn (string $name) => preg_match('/(Authorize|Authenticate|Gate|Admin|Permission|Role)/', $name) === 1);
    }

    /**
     * @param  array{route: Route}  $route
     */
    private function definedAt(ScanContext $context, array $route): string
    {
        $source = RouteInspector::source($route['route']);

        return $source === null ? '' : ' ('.$context->relative($source[0]).':'.$source[1].')';
    }

    /**
     * 'routes.ignore' takes URI or route-name patterns, optionally keyed with a reason: ['admin/auth/*' => 'OAuth flow'].
     *
     * @param  array<int|string, mixed>  $ignore
     * @return list<string>
     */
    private function ignorePatterns(array $ignore): array
    {
        $patterns = [];

        foreach ($ignore as $key => $value) {
            $patterns[] = trim((string) (is_string($key) ? $key : $value), '/');
        }

        return array_values(array_filter($patterns));
    }

    /**
     * @param  array{uri: string, name: ?string}  $route
     * @param  list<string>  $patterns
     */
    private function ignoredByConfig(array $route, array $patterns): bool
    {
        return array_any($patterns, fn (string $pattern) => Str::is($pattern, trim($route['uri'], '/'))
            || ($route['name'] !== null && Str::is($pattern, $route['name'])));
    }

    /**
     * @param  array<int, string>  $words
     */
    private function pattern(array $words): ?string
    {
        $words = array_filter(array_map(fn ($word) => preg_quote((string) $word, '/'), $words));

        return $words === [] ? null : '/(^|[\/.\-_ ])('.implode('|', $words).')([\/.\-_ ]|$)/i';
    }
}

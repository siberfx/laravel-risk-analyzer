<?php

namespace Siberfx\RiskAnalyzer\Rules\Runtime;

use Siberfx\RiskAnalyzer\Category;
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
        return 'Admin-looking routes (admin, dashboard, panel...) without authentication middleware, and login/password/OTP endpoints without rate limiting. Uses the registered route table with middleware groups expanded.';
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
        $inspector = new RouteInspector($context->router());

        foreach ($inspector->routes() as $route) {
            $subject = $route['uri'].' '.($route['name'] ?? '');
            $isSensitive = $sensitive !== null && preg_match($sensitive, $subject) === 1;

            if ($admin !== null && preg_match($admin, $subject) && ! $isSensitive && ! RouteInspector::has($route['middleware'], $authMiddleware)
                && ! $this->hasCustomGuard($route['middleware'])) {
                yield $this->finding("{$route['location']} looks like an admin route but has no authentication middleware.", null,
                    'Put the route in a group with the auth middleware (and an authorization check such as can:).',
                    anchor: 'admin.'.$route['location'], meta: ['route' => $route['location']]);
            }

            if ($isSensitive && RouteInspector::changesState($route['methods']) && ! RouteInspector::has($route['middleware'], ['throttle'])) {
                yield $this->finding("{$route['location']} accepts credentials or codes without rate limiting.", Severity::Medium,
                    'Add throttle middleware (e.g. ->middleware(\'throttle:5,1\')) to slow down brute-force attempts.',
                    anchor: 'throttle.'.$route['location'], meta: ['route' => $route['location']]);
            }
        }
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
     * @param  array<int, string>  $words
     */
    private function pattern(array $words): ?string
    {
        $words = array_filter(array_map(fn ($word) => preg_quote((string) $word, '/'), $words));

        return $words === [] ? null : '/(^|[\/.\-_ ])('.implode('|', $words).')([\/.\-_ ]|$)/i';
    }
}

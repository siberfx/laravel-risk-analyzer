<?php

namespace Siberfx\RiskAnalyzer\Support;

use Closure;
use Illuminate\Routing\Route;
use Illuminate\Routing\Router;
use Illuminate\Support\Str;
use ReflectionFunction;
use ReflectionMethod;
use Throwable;

/**
 * Reads the registered routes with their middleware fully expanded
 * (groups resolved, controller middleware included).
 */
final class RouteInspector
{
    /**
     * Route action key written by the riskAnalyzerIgnore() route macro.
     */
    public const IGNORE_KEY = 'risk_analyzer_ignore';

    public function __construct(private readonly Router $router) {}

    /**
     * Routes marked with ->riskAnalyzerIgnore() for $rule are left out.
     *
     * @return iterable<array{route: Route, uri: string, name: ?string, methods: list<string>, middleware: list<string>, location: string}>
     */
    public function routes(?string $rule = null): iterable
    {
        foreach ($this->router->getRoutes()->getRoutes() as $route) {
            if ($rule !== null && self::ignores($route, $rule)) {
                continue;
            }

            yield [
                'route' => $route,
                'uri' => $route->uri(),
                'name' => $route->getName(),
                'methods' => array_values(array_diff($route->methods(), ['HEAD'])),
                'middleware' => $this->middleware($route),
                'location' => implode('|', $route->methods()).' '.$route->uri(),
            ];
        }
    }

    public static function ignores(Route $route, string $rule): bool
    {
        $ignore = $route->getAction(self::IGNORE_KEY);

        if (! is_array($ignore)) {
            return false;
        }

        $rules = (array) ($ignore['rules'] ?? []);

        return $rules === [] || in_array($rule, $rules, true);
    }

    /**
     * Where the route's closure or controller method is defined.
     *
     * @return array{0: string, 1: int}|null
     */
    public static function source(Route $route): ?array
    {
        try {
            $uses = $route->getAction('uses');

            $reflection = match (true) {
                $uses instanceof Closure => new ReflectionFunction($uses),
                is_string($uses) && str_contains($uses, '@') => new ReflectionMethod(...explode('@', $uses, 2)),
                is_string($uses) && method_exists($uses, '__invoke') => new ReflectionMethod($uses, '__invoke'),
                default => null,
            };
        } catch (Throwable) {
            return null;
        }

        $file = $reflection?->getFileName();

        return is_string($file) ? [$file, (int) $reflection->getStartLine()] : null;
    }

    /**
     * The parameter that swallows the rest of the URL, e.g. {any?} or {path} with where('path', '.*').
     */
    public static function catchAllParameter(Route $route): ?string
    {
        $last = Str::afterLast($route->uri(), '/');

        if (preg_match('/^\{(\w+)(\?)?\}$/', $last, $match) !== 1) {
            return null;
        }

        $constraint = (string) ($route->wheres[$match[1]] ?? '');

        if (str_contains($constraint, '.*') || str_contains($constraint, '.+')) {
            return $match[1];
        }

        $optional = ($match[2] ?? '') === '?';

        return $optional && in_array(strtolower($match[1]), ['any', 'all', 'path', 'catchall', 'catch_all', 'spa', 'vue', 'react'], true)
            ? $match[1]
            : null;
    }

    /**
     * @param  list<string>  $methods
     */
    public static function changesState(array $methods): bool
    {
        return array_diff($methods, ['GET', 'HEAD', 'OPTIONS']) !== [];
    }

    /**
     * Whether any middleware matches one of $names: "auth" matches "auth",
     * "auth:sanctum" and the Authenticate class.
     *
     * @param  list<string>  $middleware
     * @param  list<string>  $names
     */
    public static function has(array $middleware, array $names): bool
    {
        $classes = [
            'auth' => ['Illuminate\Auth\Middleware\Authenticate', 'App\Http\Middleware\Authenticate'],
            'auth.basic' => ['Illuminate\Auth\Middleware\AuthenticateWithBasicAuth'],
            'can' => ['Illuminate\Auth\Middleware\Authorize'],
            'signed' => ['Illuminate\Routing\Middleware\ValidateSignature'],
            'throttle' => ['Illuminate\Routing\Middleware\ThrottleRequests', 'Illuminate\Routing\Middleware\ThrottleRequestsWithRedis'],
            'password.confirm' => ['Illuminate\Auth\Middleware\RequirePassword'],
            'verified' => ['Illuminate\Auth\Middleware\EnsureEmailIsVerified'],
            'web' => [],
        ];

        foreach ($middleware as $entry) {
            $base = explode(':', $entry, 2)[0];

            foreach ($names as $name) {
                if ($base === $name || in_array($base, $classes[$name] ?? [], true)) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * @return list<string>
     */
    private function middleware(Route $route): array
    {
        try {
            $names = $route->gatherMiddleware();
        } catch (Throwable) {
            // Controller middleware may fail to resolve outside a request.
            $names = (array) ($route->getAction('middleware') ?? []);
        }

        $groups = $this->router->getMiddlewareGroups();
        $aliases = $this->router->getMiddleware();
        $expanded = [];
        $queue = array_values(array_filter($names, 'is_string'));
        $seen = [];

        while ($queue !== []) {
            $entry = array_shift($queue);

            if (isset($seen[$entry])) {
                continue;
            }

            $seen[$entry] = true;
            $expanded[] = $entry;

            if (isset($groups[$entry])) {
                array_push($queue, ...array_filter($groups[$entry], 'is_string'));

                continue;
            }

            $base = explode(':', $entry, 2)[0];
            $parameters = explode(':', $entry, 2)[1] ?? null;

            if (isset($aliases[$base]) && is_string($aliases[$base])) {
                $expanded[] = $aliases[$base].($parameters !== null ? ':'.$parameters : '');
            }
        }

        return $expanded;
    }
}

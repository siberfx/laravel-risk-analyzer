<?php

namespace Siberfx\RiskAnalyzer\Support;

use Closure;
use Illuminate\Routing\Route;
use Illuminate\Routing\Router;
use Illuminate\Support\Str;
use ReflectionClass;
use ReflectionFunction;
use ReflectionMethod;
use Siberfx\RiskAnalyzer\Attributes\RiskAnalyzerIgnore;
use Throwable;

/**
 * Reads the registered routes with their middleware fully expanded
 * (groups resolved, controller middleware included).
 */
final class RouteInspector
{
    public function __construct(private readonly Router $router) {}

    /**
     * Routes whose handler carries #[RiskAnalyzerIgnore] for $rule are left out.
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

    /**
     * #[RiskAnalyzerIgnore] on the route closure, the controller method or the controller class.
     */
    public static function ignores(Route $route, string $rule): bool
    {
        $handler = self::handler($route);

        if ($handler === null) {
            return false;
        }

        $attributes = $handler->getAttributes(RiskAnalyzerIgnore::class);

        // The route's controller class, not the method's declaring class: the method may be inherited.
        if ($handler instanceof ReflectionMethod && class_exists($controller = Str::before((string) $route->getAction('uses'), '@'))) {
            array_push($attributes, ...(new ReflectionClass($controller))->getAttributes(RiskAnalyzerIgnore::class));
        }

        foreach ($attributes as $attribute) {
            try {
                $rules = $attribute->newInstance()->rules;
            } catch (Throwable) {
                continue;
            }

            if ($rules === [] || in_array($rule, $rules, true)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Where the route's closure or controller method is defined.
     *
     * @return array{0: string, 1: int}|null
     */
    public static function source(Route $route): ?array
    {
        $handler = self::handler($route);
        $file = $handler?->getFileName();

        return is_string($file) ? [$file, (int) $handler->getStartLine()] : null;
    }

    private static function handler(Route $route): ReflectionFunction|ReflectionMethod|null
    {
        try {
            $uses = $route->getAction('uses');

            return match (true) {
                $uses instanceof Closure => new ReflectionFunction($uses),
                is_string($uses) && str_contains($uses, '@') => new ReflectionMethod(...explode('@', $uses, 2)),
                is_string($uses) && method_exists($uses, '__invoke') => new ReflectionMethod($uses, '__invoke'),
                default => null,
            };
        } catch (Throwable) {
            return null;
        }
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

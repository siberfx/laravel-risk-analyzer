<?php

namespace Siberfx\RiskAnalyzer\Support;

use Illuminate\Routing\Route;
use Illuminate\Routing\Router;
use Throwable;

/**
 * Reads the registered routes with their middleware fully expanded
 * (groups resolved, controller middleware included).
 */
final class RouteInspector
{
    public function __construct(private readonly Router $router) {}

    /**
     * @return iterable<array{route: Route, uri: string, name: ?string, methods: list<string>, middleware: list<string>, location: string}>
     */
    public function routes(): iterable
    {
        foreach ($this->router->getRoutes()->getRoutes() as $route) {
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

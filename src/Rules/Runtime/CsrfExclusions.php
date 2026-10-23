<?php

namespace Siberfx\RiskAnalyzer\Rules\Runtime;

use Illuminate\Support\Str;
use ReflectionClass;
use Siberfx\RiskAnalyzer\Category;
use Siberfx\RiskAnalyzer\Rules\AbstractProjectRule;
use Siberfx\RiskAnalyzer\ScanContext;
use Siberfx\RiskAnalyzer\Severity;
use Siberfx\RiskAnalyzer\Support\RouteInspector;

final class CsrfExclusions extends AbstractProjectRule
{
    /** CSRF middleware classes across Laravel 12 and 13. */
    private const array CLASSES = [
        'Illuminate\Foundation\Http\Middleware\PreventRequestForgery',
        'Illuminate\Foundation\Http\Middleware\VerifyCsrfToken',
        'App\Http\Middleware\VerifyCsrfToken',
    ];

    public function id(): string
    {
        return 'csrf-exclusions';
    }

    public function title(): string
    {
        return 'CSRF exclusions';
    }

    public function description(): string
    {
        return 'CSRF exclusions (validateCsrfTokens(except: [...]) or $except) matched against the real route table: catch-all patterns and state-changing web routes that end up unprotected.';
    }

    public function category(): Category
    {
        return Category::Runtime;
    }

    public function severity(): Severity
    {
        return Severity::Critical;
    }

    public function run(ScanContext $context): iterable
    {
        $patterns = $this->exclusions();

        foreach ($patterns as $pattern) {
            if (in_array(trim($pattern, '/'), ['*', ''], true) && $pattern !== '/') {
                yield $this->finding("CSRF protection is disabled for every URI (pattern '{$pattern}').", null,
                    'Exclude only the specific webhook URIs that cannot send a token, e.g. "stripe/webhook".', anchor: 'csrf.'.$pattern);

                return;
            }
        }

        if ($patterns !== []) {
            $inspector = new RouteInspector($context->router());

            foreach ($inspector->routes() as $route) {
                if (! RouteInspector::changesState($route['methods']) || ! RouteInspector::has($route['middleware'], ['web'])) {
                    continue;
                }

                $matched = array_find($patterns, fn (string $pattern) => Str::is(trim($pattern, '/'), trim($route['uri'], '/')));

                if ($matched === null) {
                    continue;
                }

                $authenticated = RouteInspector::has($route['middleware'], ['auth']);

                yield $this->finding(
                    "{$route['location']} is excluded from CSRF verification by '{$matched}'".($authenticated ? ' and uses session authentication.' : '.'),
                    $authenticated ? Severity::High : Severity::Low,
                    $authenticated
                        ? 'An authenticated, cookie-based route without CSRF can be triggered from any site. Remove it from the exclusions or authenticate it with a signature/token instead.'
                        : 'Make sure the endpoint verifies the caller another way (webhook signature, signed URL).',
                    anchor: 'csrf-route.'.$route['location'],
                    meta: ['route' => $route['location'], 'pattern' => $matched],
                );
            }
        }

        if ($this->staticValue('allowSameSite') === true) {
            yield $this->finding('CSRF checks accept any same-site request (preventRequestForgery(allowSameSite: true)), so sibling subdomains can forge requests.', Severity::Low,
                'Only allow same-site requests when you control every subdomain.', anchor: 'csrf.same-site');
        }
    }

    /**
     * @return list<string>
     */
    private function exclusions(): array
    {
        $patterns = [];

        foreach (self::CLASSES as $class) {
            if (! class_exists($class)) {
                continue;
            }

            $reflection = new ReflectionClass($class);

            if ($reflection->hasProperty('neverVerify')) {
                $patterns = [...$patterns, ...(array) $reflection->getProperty('neverVerify')->getValue()];
            }

            if ($reflection->hasProperty('except')) {
                $patterns = [...$patterns, ...(array) ($reflection->getProperty('except')->getDefaultValue() ?? [])];
            }
        }

        return array_values(array_unique(array_filter($patterns, 'is_string')));
    }

    private function staticValue(string $property): mixed
    {
        $class = self::CLASSES[0];

        if (! class_exists($class) || ! property_exists($class, $property)) {
            return null;
        }

        return (new ReflectionClass($class))->getProperty($property)->getValue();
    }
}

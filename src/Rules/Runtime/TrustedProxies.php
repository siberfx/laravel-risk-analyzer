<?php

namespace Siberfx\RiskAnalyzer\Rules\Runtime;

use Illuminate\Http\Middleware\TrustProxies;
use ReflectionClass;
use Siberfx\RiskAnalyzer\Category;
use Siberfx\RiskAnalyzer\Rules\AbstractProjectRule;
use Siberfx\RiskAnalyzer\ScanContext;
use Siberfx\RiskAnalyzer\Severity;
use Throwable;

final class TrustedProxies extends AbstractProjectRule
{
    /** App-level middleware from Laravel 10 and older skeletons. */
    private const array APP_CLASSES = ['App\Http\Middleware\TrustProxies'];

    public function id(): string
    {
        return 'trusted-proxies';
    }

    public function title(): string
    {
        return 'Every proxy trusted';
    }

    public function description(): string
    {
        return 'TrustProxies set to "*" or "**" (trustProxies(at: \'*\') in bootstrap/app.php, or $proxies in an app TrustProxies middleware), which lets any client spoof its IP address with X-Forwarded-For and defeats rate limits, IP allow-lists and logged addresses.';
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
        $sources = ['trustProxies(at: ...)' => $this->property(TrustProxies::class, 'alwaysTrustProxies', static: true)];

        foreach (self::APP_CLASSES as $class) {
            $sources["{$class}::\$proxies"] = $this->property($class, 'proxies', static: false);
        }

        $sources["config('trustedproxy.proxies')"] = $context->settings()->get('trustedproxy.proxies');

        foreach ($sources as $source => $proxies) {
            $wildcard = array_find((array) $proxies, fn (mixed $proxy) => in_array($proxy, ['*', '**', '0.0.0.0/0', '::/0'], true));

            if ($wildcard === null) {
                continue;
            }

            yield $this->finding("{$source} trusts every proxy ('{$wildcard}'), so any client can set X-Forwarded-For and spoof its IP address.", null,
                'List your load balancer\'s addresses or ranges instead (e.g. trustProxies(at: [\'10.0.0.0/8\'])). Keep the wildcard only if the app is reachable solely through a proxy that overwrites X-Forwarded-For.',
                anchor: 'trusted-proxies.'.$source, meta: ['source' => $source, 'proxies' => $proxies]);
        }
    }

    private function property(string $class, string $property, bool $static): mixed
    {
        try {
            if (! class_exists($class) || ! property_exists($class, $property)) {
                return null;
            }

            $reflection = (new ReflectionClass($class))->getProperty($property);

            return $static ? $reflection->getValue() : $reflection->getDefaultValue();
        } catch (Throwable) {
            return null;
        }
    }
}

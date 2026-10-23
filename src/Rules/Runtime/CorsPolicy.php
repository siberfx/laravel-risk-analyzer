<?php

namespace Siberfx\RiskAnalyzer\Rules\Runtime;

use Siberfx\RiskAnalyzer\Category;
use Siberfx\RiskAnalyzer\Rules\AbstractProjectRule;
use Siberfx\RiskAnalyzer\ScanContext;
use Siberfx\RiskAnalyzer\Severity;

final class CorsPolicy extends AbstractProjectRule
{
    public function id(): string
    {
        return 'cors-policy';
    }

    public function title(): string
    {
        return 'CORS policy';
    }

    public function description(): string
    {
        return 'Any origin allowed together with credentials (cookies), which lets every website make authenticated requests on behalf of your users; catch-all origin patterns.';
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
        $cors = (array) $context->settings()->get('cors', []);

        if ($cors === []) {
            return;
        }

        $origins = (array) ($cors['allowed_origins'] ?? []);
        $patterns = (array) ($cors['allowed_origins_patterns'] ?? []);
        $credentials = (bool) ($cors['supports_credentials'] ?? false);
        $wildcard = in_array('*', $origins, true) || array_any($patterns, fn ($pattern) => in_array(trim((string) $pattern, '#/~^$'), ['.*', '.+', '*'], true));

        if ($wildcard && $credentials) {
            yield $this->finding('CORS allows any origin and supports credentials.', null,
                'List your front-end origins in cors.allowed_origins, or turn off supports_credentials.', 'config/cors.php', anchor: 'cors.wildcard-credentials');

            return;
        }

        foreach ($patterns as $pattern) {
            // An unanchored or unescaped pattern like "example.com" also matches evil-example.com.
            if (is_string($pattern) && ! str_contains($pattern, '\.') && str_contains($pattern, '.')) {
                yield $this->finding("CORS origin pattern {$pattern} does not escape dots, so it matches more hosts than intended.", Severity::Medium,
                    'Escape dots and anchor the pattern: #^https://(.+\.)?example\.com$#', 'config/cors.php', anchor: 'cors.pattern.'.$pattern);
            }
        }

        if ($wildcard && $context->production) {
            yield $this->finding('CORS allows requests from any origin.', Severity::Low,
                'Fine for a public API; otherwise restrict cors.allowed_origins.', 'config/cors.php', anchor: 'cors.wildcard');
        }
    }
}

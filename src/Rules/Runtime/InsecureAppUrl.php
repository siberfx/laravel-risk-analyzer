<?php

namespace Siberfx\RiskAnalyzer\Rules\Runtime;

use Illuminate\Contracts\Routing\UrlGenerator;
use ReflectionProperty;
use Siberfx\RiskAnalyzer\Category;
use Siberfx\RiskAnalyzer\Rules\AbstractProjectRule;
use Siberfx\RiskAnalyzer\ScanContext;
use Siberfx\RiskAnalyzer\Severity;
use Throwable;

final class InsecureAppUrl extends AbstractProjectRule
{
    public function id(): string
    {
        return 'insecure-app-url';
    }

    public function title(): string
    {
        return 'Plain HTTP application URL';
    }

    public function description(): string
    {
        return 'APP_URL on http:// in production, or URL::forceScheme(\'http\'), so generated links, redirects, signed URLs and mails point to plain HTTP.';
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

        $forced = $this->forcedScheme($context);

        if ($forced === 'http://') {
            yield $this->finding('URL::forceScheme(\'http\') makes every generated URL use plain HTTP.', null,
                'Remove forceScheme(\'http\'), or force https instead (URL::forceHttps()).', anchor: 'app-url.forced-http');

            return;
        }

        $url = (string) $context->settings()->get('app.url', '');
        $host = strtolower((string) parse_url($url, PHP_URL_HOST));

        if ($forced === 'https://' || ! str_starts_with(strtolower($url), 'http://') || in_array($host, ['localhost', '127.0.0.1', '[::1]'], true)) {
            return;
        }

        yield $this->finding("APP_URL is {$url}, so generated links, redirects, signed URLs and mails use plain HTTP.", null,
            'Set APP_URL to the https:// address of the site (and redirect HTTP to HTTPS in the web server).', anchor: 'app-url.http');
    }

    private function forcedScheme(ScanContext $context): ?string
    {
        try {
            $generator = $context->app->make(UrlGenerator::class);
            $scheme = (new ReflectionProperty($generator, 'forceScheme'))->getValue($generator);

            return is_string($scheme) ? $scheme : null;
        } catch (Throwable) {
            return null;
        }
    }
}

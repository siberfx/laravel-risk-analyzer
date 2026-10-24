<?php

namespace Siberfx\RiskAnalyzer\Rules\Runtime;

use Siberfx\RiskAnalyzer\Category;
use Siberfx\RiskAnalyzer\Rules\AbstractProjectRule;
use Siberfx\RiskAnalyzer\ScanContext;
use Siberfx\RiskAnalyzer\Severity;
use Siberfx\RiskAnalyzer\Support\RouteInspector;

final class DevToolsExposure extends AbstractProjectRule
{
    /** Packages that should only ever be dev dependencies. */
    private const array DEV_ONLY = [
        'barryvdh/laravel-debugbar', 'fruitcake/laravel-debugbar', 'itsgoingd/clockwork', 'spatie/laravel-ray', 'spatie/ray',
        'beyondcode/laravel-dump-server', 'laravel/pail', 'spatie/laravel-ignition', 'filp/whoops', 'symfony/var-dumper-server',
    ];

    /** Route prefixes of debugging tools that must not be reachable in production. */
    private const array DEBUG_ROUTES = ['_ignition', '_debugbar', '__clockwork', 'clockwork'];

    public function id(): string
    {
        return 'dev-tools-exposed';
    }

    public function title(): string
    {
        return 'Development tools in production';
    }

    public function description(): string
    {
        return 'Debugbar, Clockwork, Ray, Ignition and similar packages required as production dependencies, debug tool routes registered in production, and Telescope recording in production.';
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
        $require = (array) ($context->readJson('composer.json')['require'] ?? []);

        foreach (self::DEV_ONLY as $package) {
            if (array_key_exists($package, $require)) {
                yield $this->finding("{$package} is a production dependency (\"require\").", Severity::Medium,
                    "Move it to require-dev: composer remove {$package} && composer require --dev {$package}",
                    'composer.json', anchor: 'require.'.$package);
            }
        }

        if (! $context->production) {
            return;
        }

        $config = $context->settings();

        if ($config->get('debugbar.enabled') === true) {
            yield $this->finding('Laravel Debugbar is enabled in production.', Severity::Critical,
                'Set DEBUGBAR_ENABLED=false and install the package with --dev.', anchor: 'debugbar.enabled');
        }

        if ($config->get('telescope.enabled') === true) {
            yield $this->finding('Telescope records requests in production; make sure its gate only lets admins in.', Severity::Low,
                'Review the viewTelescope gate in TelescopeServiceProvider, or disable Telescope in production.', anchor: 'telescope.enabled');
        }

        $inspector = new RouteInspector($context->router());
        $reported = [];

        foreach ($inspector->routes($this->id()) as $route) {
            $prefix = explode('/', $route['uri'])[0];

            if (in_array($prefix, self::DEBUG_ROUTES, true) && ! isset($reported[$prefix])) {
                $reported[$prefix] = true;

                yield $this->finding("Debug tool routes (/{$prefix}) are registered in production.", null,
                    'Install the tool as a dev dependency so it is not loaded with composer install --no-dev.', anchor: 'route.'.$prefix);
            }
        }
    }
}

<?php

namespace Siberfx\RiskAnalyzer;

use Illuminate\Routing\Route;
use Illuminate\Support\ServiceProvider;
use Siberfx\RiskAnalyzer\Console\BaselineCommand;
use Siberfx\RiskAnalyzer\Console\RulesCommand;
use Siberfx\RiskAnalyzer\Console\ScanCommand;
use Siberfx\RiskAnalyzer\Support\RouteInspector;

final class RiskAnalyzerServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../config/risk-analyzer.php', 'risk-analyzer');

        $this->app->singleton(RiskAnalyzer::class, fn ($app) => new RiskAnalyzer($app, (array) $app['config']->get('risk-analyzer', [])));

        // Route::get(...)->riskAnalyzerIgnore('unprotected-route', 'OAuth callback'); no rule ids ignores every route rule.
        Route::macro('riskAnalyzerIgnore', function (string|array $rules = [], ?string $reason = null) {
            /** @var Route $this */
            $this->action[RouteInspector::IGNORE_KEY] = ['rules' => array_values((array) $rules), 'reason' => $reason];

            return $this;
        });
    }

    public function boot(): void
    {
        if (! $this->app->runningInConsole()) {
            return;
        }

        $this->publishes([
            __DIR__.'/../config/risk-analyzer.php' => config_path('risk-analyzer.php'),
        ], 'risk-analyzer-config');

        $this->commands([
            ScanCommand::class,
            BaselineCommand::class,
            RulesCommand::class,
        ]);
    }
}

<?php

namespace Siberfx\RiskAnalyzer;

use Illuminate\Support\ServiceProvider;
use Siberfx\RiskAnalyzer\Console\BaselineCommand;
use Siberfx\RiskAnalyzer\Console\RulesCommand;
use Siberfx\RiskAnalyzer\Console\ScanCommand;

final class RiskAnalyzerServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../config/risk-analyzer.php', 'risk-analyzer');

        $this->app->singleton(RiskAnalyzer::class, fn ($app) => new RiskAnalyzer($app, (array) $app['config']->get('risk-analyzer', [])));
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

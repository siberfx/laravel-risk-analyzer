<?php

namespace Siberfx\RiskAnalyzer;

use Illuminate\Contracts\Foundation\CachesConfiguration;
use Illuminate\Support\ServiceProvider;
use Siberfx\RiskAnalyzer\Console\BaselineCommand;
use Siberfx\RiskAnalyzer\Console\ConfigSyncCommand;
use Siberfx\RiskAnalyzer\Console\RulesCommand;
use Siberfx\RiskAnalyzer\Console\ScanCommand;
use Siberfx\RiskAnalyzer\Support\ConfigMerger;

final class RiskAnalyzerServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        // Recursive, so options added to nested sections reach apps that published an older config.
        if (! ($this->app instanceof CachesConfiguration && $this->app->configurationIsCached())) {
            $config = $this->app->make('config');

            $config->set('risk-analyzer', ConfigMerger::merge(
                require __DIR__.'/../config/risk-analyzer.php',
                (array) $config->get('risk-analyzer', []),
            ));
        }

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
            ConfigSyncCommand::class,
            RulesCommand::class,
        ]);
    }
}

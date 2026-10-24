<?php

namespace Siberfx\RiskAnalyzer\Console;

use Illuminate\Console\Command;
use Siberfx\RiskAnalyzer\Support\ConfigSynchronizer;

final class ConfigSyncCommand extends Command
{
    protected $signature = 'risk-analyzer:config-sync
        {--dry-run : List the missing keys without writing the file}
        {--check : Fail when keys are missing, without writing the file (for CI)}';

    protected $description = 'Add options introduced by package updates to the published config/risk-analyzer.php';

    public function handle(): int
    {
        $path = config_path('risk-analyzer.php');

        if (! is_file($path)) {
            $this->components->info('The config is not published; the package defaults are used as they are.');

            return self::SUCCESS;
        }

        $published = (string) file_get_contents($path);
        $result = (new ConfigSynchronizer)->sync((string) file_get_contents(__DIR__.'/../../config/risk-analyzer.php'), $published);

        if ($result['added'] === []) {
            $this->components->info('config/risk-analyzer.php is up to date.');

            return self::SUCCESS;
        }

        if ($this->option('dry-run') || $this->option('check')) {
            $this->components->warn(count($result['added']).' option(s) missing from config/risk-analyzer.php:');
            $this->components->bulletList($result['added']);

            return $this->option('check') ? self::FAILURE : self::SUCCESS;
        }

        file_put_contents($path, $result['code']);

        $this->components->info('Added '.count($result['added']).' option(s) to config/risk-analyzer.php:');
        $this->components->bulletList($result['added']);

        return self::SUCCESS;
    }
}

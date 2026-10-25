<?php

namespace Siberfx\RiskAnalyzer\Console;

use Illuminate\Console\Command;
use InvalidArgumentException;
use Siberfx\RiskAnalyzer\Baseline;
use Siberfx\RiskAnalyzer\Console\Concerns\ScopeOptions;
use Siberfx\RiskAnalyzer\RiskAnalyzer;

final class BaselineCommand extends Command
{
    use ScopeOptions;

    protected $signature = 'risk-analyzer:baseline
        {--path= : Where to write the baseline (defaults to the configured path)}
        {--production : Treat the current environment as production}
        {--dev : Treat the current environment as development: skip production-only checks}
        {--offline : Skip network lookups (dependency advisories)}
        {--frontend=* : Only frontend checks (React, Vue, Angular) and their npm advisories; optionally the folders to scan instead of frontend.paths}
        {--infrastructure=* : Only Docker, compose, script and CI checks; optionally the folders to search instead of infrastructure.paths}';

    protected $description = 'Record the current findings as accepted, so only new ones fail future scans';

    public function handle(RiskAnalyzer $riskAnalyzer): int
    {
        if ($this->option('dev') && $this->option('production')) {
            $this->components->error('Use either --dev or --production, not both.');

            return self::INVALID;
        }

        try {
            $report = $riskAnalyzer->scan(
                production: match (true) {
                    (bool) $this->option('production') => true,
                    (bool) $this->option('dev') => false,
                    default => null,
                },
                offline: (bool) $this->option('offline'),
                baseline: false,
                frontend: $this->scopeOption('frontend'),
                infrastructure: $this->scopeOption('infrastructure'),
            );
        } catch (InvalidArgumentException $exception) {
            $this->components->error($exception->getMessage());

            return self::INVALID;
        }

        // Scanner errors are about this run, not accepted findings.
        $findings = array_filter($report->findings, fn ($finding) => $finding->rule !== 'scanner-error');
        $path = $riskAnalyzer->baselinePath(is_string($this->option('path')) && $this->option('path') !== '' ? $this->option('path') : null);
        $baseline = Baseline::fromFindings($findings);
        $baseline->save($path);

        $this->components->info("Baseline with {$baseline->count()} finding(s) written to {$path}.");
        $this->components->bulletList([
            'Commit the file; future scans only fail on findings that are not in it.',
            'Fixed findings drop out automatically the next time you regenerate it.',
        ]);

        return self::SUCCESS;
    }
}

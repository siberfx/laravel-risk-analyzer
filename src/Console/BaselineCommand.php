<?php

namespace Siberfx\RiskAnalyzer\Console;

use Illuminate\Console\Command;
use Siberfx\RiskAnalyzer\Baseline;
use Siberfx\RiskAnalyzer\RiskAnalyzer;

final class BaselineCommand extends Command
{
    protected $signature = 'risk-analyzer:baseline
        {--path= : Where to write the baseline (defaults to the configured path)}
        {--production : Treat the current environment as production}
        {--dev : Treat the current environment as development: skip production-only checks}
        {--offline : Skip network lookups (dependency advisories)}';

    protected $description = 'Record the current findings as accepted, so only new ones fail future scans';

    public function handle(RiskAnalyzer $riskAnalyzer): int
    {
        if ($this->option('dev') && $this->option('production')) {
            $this->components->error('Use either --dev or --production, not both.');

            return self::INVALID;
        }

        $report = $riskAnalyzer->scan(
            production: match (true) {
                (bool) $this->option('production') => true,
                (bool) $this->option('dev') => false,
                default => null,
            },
            offline: (bool) $this->option('offline'),
            baseline: false,
        );

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

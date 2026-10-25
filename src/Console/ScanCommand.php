<?php

namespace Siberfx\RiskAnalyzer\Console;

use Illuminate\Console\Command;
use InvalidArgumentException;
use RuntimeException;
use Siberfx\RiskAnalyzer\Console\Concerns\ScopeOptions;
use Siberfx\RiskAnalyzer\Finding;
use Siberfx\RiskAnalyzer\Report;
use Siberfx\RiskAnalyzer\Reporters\JsonReporter;
use Siberfx\RiskAnalyzer\Reporters\MarkdownReporter;
use Siberfx\RiskAnalyzer\Reporters\Reporter;
use Siberfx\RiskAnalyzer\Reporters\SarifReporter;
use Siberfx\RiskAnalyzer\RiskAnalyzer;
use Siberfx\RiskAnalyzer\Severity;
use Siberfx\RiskAnalyzer\Support\ChangedFiles;
use Symfony\Component\Console\Formatter\OutputFormatter;
use Symfony\Component\Console\Output\OutputInterface;

final class ScanCommand extends Command
{
    use ScopeOptions;

    protected $signature = 'risk-analyzer:scan
        {--format=console : console, json, sarif or markdown}
        {--output= : Write the report to this file (the console summary is still printed)}
        {--fail-on= : Lowest severity that fails the scan (critical, high, medium, low, info)}
        {--only=* : Only run these rule ids or categories (code, runtime, dependencies, filesystem)}
        {--skip=* : Skip these rule ids or categories}
        {--production : Treat the current environment as production}
        {--dev : Treat the current environment as development: skip production-only checks}
        {--offline : Skip network lookups (dependency advisories)}
        {--frontend=* : Only frontend checks (React, Vue, Angular) and their npm advisories; optionally the folders to scan instead of frontend.paths}
        {--infrastructure=* : Only Docker, compose, script and CI checks; optionally the folders to search instead of infrastructure.paths}
        {--changed= : Only scan code changed against a git ref (empty for uncommitted changes)}
        {--baseline= : Baseline file to use instead of the configured one}
        {--no-baseline : Ignore the baseline}
        {--show-baselined : List baselined findings too}';

    protected $description = 'Scan the application for security issues';

    public function handle(RiskAnalyzer $riskAnalyzer): int
    {
        if ($this->option('dev') && $this->option('production')) {
            $this->components->error('Use either --dev or --production, not both.');

            return self::INVALID;
        }

        $format = strtolower($this->stringOption('format') ?? 'console');
        $reporter = $this->reporter($format);

        if ($format !== 'console' && $reporter === null) {
            $this->components->error("Unknown format [{$format}]. Use console, json, sarif or markdown.");

            return self::INVALID;
        }

        try {
            $threshold = Severity::fromLoose($this->stringOption('fail-on') ?? (string) $riskAnalyzer->config('fail_on', 'high'));
            // --changed alone (empty) means uncommitted changes, like no ref.
            $files = $this->option('changed') !== null ? ChangedFiles::since($riskAnalyzer->basePath(), $this->stringOption('changed')) : null;

            $report = $riskAnalyzer->scan(
                only: $this->listOption('only'),
                skip: $this->listOption('skip'),
                production: $this->profile(),
                offline: (bool) $this->option('offline'),
                files: $files,
                baseline: $this->option('no-baseline') ? false : $this->stringOption('baseline'),
                frontend: $this->scopeOption('frontend'),
                infrastructure: $this->scopeOption('infrastructure'),
            );
        } catch (InvalidArgumentException|RuntimeException $exception) {
            $this->components->error($exception->getMessage());

            return self::INVALID;
        }

        if ($reporter !== null) {
            $rendered = $reporter->render($report);
            $output = $this->stringOption('output');

            if ($output !== null) {
                file_put_contents($output, $rendered);
                $this->renderConsole($report, $threshold, findings: false);
                $this->components->info("Report written to {$output}");
            } else {
                $this->output->write($rendered, newline: true, options: OutputInterface::OUTPUT_RAW);
            }
        } else {
            $this->renderConsole($report, $threshold);
        }

        return $report->passes($threshold) ? self::SUCCESS : self::FAILURE;
    }

    private function renderConsole(Report $report, Severity $threshold, bool $findings = true): void
    {
        $this->newLine();
        $this->line(sprintf(
            '  <fg=black;bg=cyan;options=bold> RISK ANALYZER </> <fg=gray>%d rules · %s · %.2fs</>',
            count($report->rules),
            match (true) {
                $report->production => 'production profile',
                (bool) $this->option('dev') => 'development profile (--dev)',
                default => 'non-production profile (use --production to apply production checks)',
            },
            $report->duration,
        ));

        foreach (['frontend' => $report->frontend, 'infrastructure' => $report->infrastructure] as $label => $folders) {
            if ($folders !== []) {
                $this->line("  <fg=gray>{$label}: ".OutputFormatter::escape(implode(', ', $folders)).'</>');
            }
        }

        $this->newLine();

        if ($findings) {
            $shown = $this->option('show-baselined') ? collect($report->findings) : $report->active();

            foreach ($shown as $finding) {
                $this->renderFinding($finding);
            }
        }

        $counts = collect($report->counts())
            ->map(fn (int $count, string $severity) => $count > 0
                ? '<fg='.Severity::from($severity)->color().";options=bold>{$count} {$severity}</>"
                : "<fg=gray>0 {$severity}</>")
            ->implode('<fg=gray> · </>');

        $baselined = $report->baselined()->count();
        $this->line('  '.$counts.($baselined > 0 ? "<fg=gray> ({$baselined} baselined)</>" : ''));
        $this->newLine();

        $failing = $report->failing($threshold)->count();

        if ($failing === 0) {
            $this->line("  <fg=black;bg=green;options=bold> PASS </> No findings at or above \"{$threshold->value}\".");
        } else {
            $this->line("  <fg=white;bg=red;options=bold> FAIL </> {$failing} finding(s) at or above \"{$threshold->value}\".");
        }

        $this->newLine();
    }

    private function renderFinding(Finding $finding): void
    {
        $color = $finding->severity->color();
        $label = str_pad(strtoupper($finding->severity->value), 8);

        $this->line(sprintf(
            '  <fg=%s;options=bold>%s</> <fg=gray>%s</>%s%s',
            $color,
            $label,
            $finding->rule,
            $finding->location() !== null ? '  <options=underscore>'.$finding->location().'</>' : '',
            $finding->baselined ? ' <fg=gray>(baselined)</>' : '',
        ));
        $this->line('           '.OutputFormatter::escape($finding->message));

        if ($finding->snippet !== null && $finding->line !== null) {
            $this->line('           <fg=gray>│</> <fg=white>'.OutputFormatter::escape(mb_strimwidth(trim($finding->snippet), 0, 140, '…')).'</>');
        }

        if ($finding->remediation !== null) {
            $this->line('           <fg=green>↳ '.OutputFormatter::escape($finding->remediation).'</>');
        }

        $this->newLine();
    }

    /**
     * --production and --dev force the profile; otherwise APP_ENV decides.
     */
    private function profile(): ?bool
    {
        return match (true) {
            (bool) $this->option('production') => true,
            (bool) $this->option('dev') => false,
            default => null,
        };
    }

    private function reporter(string $format): ?Reporter
    {
        return match ($format) {
            'json' => new JsonReporter,
            'sarif' => new SarifReporter,
            'markdown', 'md' => new MarkdownReporter,
            default => null,
        };
    }

    private function stringOption(string $name): ?string
    {
        $value = $this->option($name);

        return is_string($value) && $value !== '' ? $value : null;
    }

    /**
     * Accepts both --only=a --only=b and --only=a,b.
     *
     * @return list<string>
     */
    private function listOption(string $name): array
    {
        $values = [];

        foreach ((array) $this->option($name) as $value) {
            foreach (explode(',', (string) $value) as $item) {
                if (trim($item) !== '') {
                    $values[] = strtolower(trim($item));
                }
            }
        }

        return $values;
    }
}

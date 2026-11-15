<?php

namespace Siberfx\RiskAnalyzer\Console;

use Illuminate\Console\Command;
use Siberfx\RiskAnalyzer\RiskAnalyzer;
use Siberfx\RiskAnalyzer\ScanContext;
use Siberfx\RiskAnalyzer\Support\IgnoreInventory;
use Symfony\Component\Console\Output\OutputInterface;

final class IgnoresCommand extends Command
{
    protected $signature = 'risk-analyzer:ignores
        {--json : Print every ignore as JSON, to save as the snapshot for --check}
        {--check= : Fail when an ignore is not in this snapshot file (a file written with --json)}';

    protected $description = 'List every active ignore (config, route attributes, inline comments) with its reason';

    public function handle(RiskAnalyzer $riskAnalyzer): int
    {
        $context = $riskAnalyzer->context();
        $entries = IgnoreInventory::collect($context);

        if ($this->option('json')) {
            $this->output->write((string) json_encode($entries, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE)."\n", false, OutputInterface::OUTPUT_RAW);

            return self::SUCCESS;
        }

        if (is_string($snapshot = $this->option('check'))) {
            return $this->check($context, $entries, $snapshot);
        }

        $this->table(
            ['Kind', 'Where', 'Ignores', 'Reason'],
            array_map(fn (array $entry) => [
                $entry['kind'],
                $entry['where'],
                $this->appliesTo($entry),
                $entry['reason'] ?? '<fg=yellow>(no reason)</>',
            ], $entries),
        );

        $withoutReason = count(array_filter($entries, fn (array $entry) => $entry['reason'] === null));
        $this->line(count($entries).' active ignore(s), '.$withoutReason.' without a reason.');

        return self::SUCCESS;
    }

    /**
     * @param  list<array<string, mixed>>  $entries
     */
    private function check(ScanContext $context, array $entries, string $file): int
    {
        $path = $context->basePath($file);
        $snapshot = is_file($path) ? json_decode((string) file_get_contents($path), true) : null;

        if (! is_array($snapshot)) {
            $this->error("Snapshot [{$file}] is missing or not valid JSON. Create it with: php artisan risk-analyzer:ignores --json > {$file}");

            return self::INVALID;
        }

        $added = IgnoreInventory::added($entries, $snapshot);

        if ($added === []) {
            $this->info("No ignores were added since {$file}.");

            return self::SUCCESS;
        }

        $this->error(count($added).' new ignore(s) not in '.$file.'. Review them, then regenerate the snapshot.');

        foreach ($added as $entry) {
            $this->line("  {$entry['kind']} · {$entry['where']} · ".$this->appliesTo($entry).' · '.($entry['reason'] ?? '(no reason)'));
        }

        $this->line("Update it with: php artisan risk-analyzer:ignores --json > {$file}");

        return self::FAILURE;
    }

    /**
     * @param  array<string, mixed>  $entry
     */
    private function appliesTo(array $entry): string
    {
        // An inline ignore's target is its file, which the Where column already shows.
        $rules = implode(', ', $entry['rules']);

        return $entry['kind'] === 'inline' ? $rules : $entry['target'].' · '.$rules;
    }
}

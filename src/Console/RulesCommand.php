<?php

namespace Siberfx\RiskAnalyzer\Console;

use Illuminate\Console\Command;
use Siberfx\RiskAnalyzer\Contracts\Rule;
use Siberfx\RiskAnalyzer\RiskAnalyzer;

final class RulesCommand extends Command
{
    protected $signature = 'risk-analyzer:rules {--details : Show what each rule looks for}';

    protected $description = 'List the enabled Risk Analyzer rules';

    public function handle(RiskAnalyzer $riskAnalyzer): int
    {
        $rules = collect($riskAnalyzer->rules())->sortBy(fn (Rule $rule) => [$rule->category()->value, $rule->id()]);

        if ($this->option('details')) {
            foreach ($rules->groupBy(fn (Rule $rule) => $rule->category()->label()) as $category => $group) {
                $this->newLine();
                $this->line("  <options=bold>{$category}</>");

                foreach ($group as $rule) {
                    $this->newLine();
                    $this->line("  <fg={$rule->severity()->color()}>{$rule->id()}</> · {$rule->title()}");
                    $this->line('  <fg=gray>'.wordwrap($rule->description(), 100, "\n  ").'</>');
                }
            }

            $this->newLine();

            return self::SUCCESS;
        }

        $this->table(
            ['Rule', 'Category', 'Max severity', 'Title'],
            $rules->map(fn (Rule $rule) => [$rule->id(), $rule->category()->value, $rule->severity()->value, $rule->title()])->values()->all(),
        );

        return self::SUCCESS;
    }
}

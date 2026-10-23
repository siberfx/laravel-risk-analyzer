<?php

namespace Siberfx\RiskAnalyzer\Reporters;

use Siberfx\RiskAnalyzer\Finding;
use Siberfx\RiskAnalyzer\Report;

/**
 * Markdown for pull-request comments and $GITHUB_STEP_SUMMARY.
 */
final class MarkdownReporter implements Reporter
{
    private const array ICONS = [
        'critical' => '🟣', 'high' => '🔴', 'medium' => '🟠', 'low' => '🔵', 'info' => '⚪',
    ];

    public function render(Report $report): string
    {
        $active = $report->active();
        $lines = ['## 🛡️ Risk Analyzer security scan', ''];

        if ($active->isEmpty()) {
            $lines[] = '✅ No new findings across '.count($report->rules).' rules.';
        } else {
            $lines[] = '| Severity | Count |';
            $lines[] = '| --- | ---: |';

            foreach ($report->counts() as $severity => $count) {
                if ($count > 0) {
                    $lines[] = '| '.self::ICONS[$severity].' '.ucfirst($severity)." | {$count} |";
                }
            }

            $lines[] = '';
            $lines[] = '| | Rule | Location | Finding |';
            $lines[] = '| --- | --- | --- | --- |';

            foreach ($active as $finding) {
                $lines[] = $this->row($finding);
            }
        }

        if ($report->baselined()->isNotEmpty()) {
            $lines[] = '';
            $lines[] = "_{$report->baselined()->count()} baselined finding(s) not shown._";
        }

        return implode("\n", $lines)."\n";
    }

    private function row(Finding $finding): string
    {
        $escape = fn (string $text) => str_replace(['|', "\n"], ['\|', ' '], $text);

        return sprintf(
            '| %s | `%s` | %s | %s |',
            self::ICONS[$finding->severity->value],
            $finding->rule,
            $finding->location() !== null ? '`'.$finding->location().'`' : '—',
            $escape($finding->message).($finding->remediation ? '<br><sub>'.$escape($finding->remediation).'</sub>' : ''),
        );
    }
}

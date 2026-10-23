<?php

namespace Siberfx\RiskAnalyzer\Reporters;

use Siberfx\RiskAnalyzer\Contracts\Rule;
use Siberfx\RiskAnalyzer\Finding;
use Siberfx\RiskAnalyzer\Report;

/**
 * SARIF 2.1.0, as consumed by GitHub code scanning, GitLab and most IDEs.
 */
final class SarifReporter implements Reporter
{
    public function render(Report $report): string
    {
        $rules = array_values($report->rules);
        $index = array_flip(array_map(fn (Rule $rule) => $rule->id(), $rules));

        $results = array_map(fn (Finding $finding) => array_filter([
            'ruleId' => $finding->rule,
            'ruleIndex' => $index[$finding->rule] ?? null,
            'level' => $finding->severity->sarifLevel(),
            'message' => ['text' => $finding->message.($finding->remediation ? "\nFix: {$finding->remediation}" : '')],
            'locations' => $finding->file !== null ? [[
                'physicalLocation' => array_filter([
                    'artifactLocation' => ['uri' => $finding->file],
                    'region' => $finding->line !== null ? ['startLine' => $finding->line] : null,
                ]),
            ]] : null,
            'partialFingerprints' => ['risk-analyzer/v1' => $finding->fingerprint()],
            'baselineState' => $finding->baselined ? 'unchanged' : 'new',
            'properties' => ['severity' => $finding->severity->value, 'security-severity' => $finding->severity->securityScore()],
        ], fn ($value) => $value !== null), $report->findings);

        return json_encode([
            '$schema' => 'https://json.schemastore.org/sarif-2.1.0.json',
            'version' => '2.1.0',
            'runs' => [[
                'tool' => [
                    'driver' => [
                        'name' => 'Risk Analyzer',
                        'informationUri' => 'https://github.com/siberfx/laravel-risk-analyzer',
                        'semanticVersion' => '1.0.0',
                        'rules' => array_map(fn (Rule $rule) => [
                            'id' => $rule->id(),
                            'name' => str_replace(' ', '', ucwords(str_replace('-', ' ', $rule->id()))),
                            'shortDescription' => ['text' => $rule->title()],
                            'fullDescription' => ['text' => $rule->description()],
                            'defaultConfiguration' => ['level' => $rule->severity()->sarifLevel()],
                            'properties' => [
                                'tags' => ['security', $rule->category()->value],
                                'security-severity' => $rule->severity()->securityScore(),
                            ],
                        ], $rules),
                    ],
                ],
                'results' => $results,
            ]],
        ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
    }
}

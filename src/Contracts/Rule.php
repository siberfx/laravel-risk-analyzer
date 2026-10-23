<?php

namespace Siberfx\RiskAnalyzer\Contracts;

use Siberfx\RiskAnalyzer\Category;
use Siberfx\RiskAnalyzer\Severity;

interface Rule
{
    /**
     * Stable kebab-case id, used in config, baselines and ignore comments.
     */
    public function id(): string;

    public function title(): string;

    /**
     * What the rule looks for and why it matters (shown by risk-analyzer:rules and in SARIF).
     */
    public function description(): string;

    public function category(): Category;

    /**
     * The highest severity this rule reports.
     */
    public function severity(): Severity;
}

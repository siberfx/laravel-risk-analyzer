<?php

namespace Siberfx\RiskAnalyzer\Reporters;

use Siberfx\RiskAnalyzer\Report;

final class JsonReporter implements Reporter
{
    public function render(Report $report): string
    {
        return json_encode($report, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
    }
}

<?php

namespace Siberfx\RiskAnalyzer\Reporters;

use Siberfx\RiskAnalyzer\Report;

interface Reporter
{
    public function render(Report $report): string;
}

<?php

namespace Siberfx\RiskAnalyzer\Contracts;

use Siberfx\RiskAnalyzer\Finding;
use Siberfx\RiskAnalyzer\ScanContext;

/**
 * A rule that inspects the project as a whole: configuration, routes,
 * lock files, the filesystem...
 */
interface ProjectRule extends Rule
{
    /**
     * @return iterable<Finding>
     */
    public function run(ScanContext $context): iterable;
}

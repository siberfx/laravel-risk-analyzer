<?php

namespace Siberfx\RiskAnalyzer\Rules;

use Siberfx\RiskAnalyzer\Contracts\ProjectRule;
use Siberfx\RiskAnalyzer\Finding;
use Siberfx\RiskAnalyzer\Severity;

abstract class AbstractProjectRule implements ProjectRule
{
    /**
     * @param  array<string, mixed>  $meta
     */
    protected function finding(
        string $message,
        ?Severity $severity = null,
        ?string $remediation = null,
        ?string $file = null,
        ?int $line = null,
        ?string $anchor = null,
        array $meta = [],
    ): Finding {
        return new Finding(
            rule: $this->id(),
            severity: $severity ?? $this->severity(),
            message: $message,
            file: $file,
            line: $line,
            snippet: $anchor,
            remediation: $remediation,
            meta: $meta,
        );
    }
}

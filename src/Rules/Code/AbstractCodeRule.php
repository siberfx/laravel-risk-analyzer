<?php

namespace Siberfx\RiskAnalyzer\Rules\Code;

use PhpParser\Node;
use Siberfx\RiskAnalyzer\Category;
use Siberfx\RiskAnalyzer\Code\FileScope;
use Siberfx\RiskAnalyzer\Contracts\CodeRule;
use Siberfx\RiskAnalyzer\Finding;
use Siberfx\RiskAnalyzer\Severity;

abstract class AbstractCodeRule implements CodeRule
{
    public function category(): Category
    {
        return Category::Code;
    }

    /**
     * Severity for a sink argument: the rule's severity when user input
     * reaches it, $dynamic when it is merely built at runtime, null when it
     * is a literal.
     */
    protected function sinkSeverity(FileScope $file, ?Node $argument, ?Severity $dynamic = Severity::Medium): ?Severity
    {
        if ($argument === null) {
            return null;
        }

        if ($file->taint->isTainted($argument)) {
            return $this->severity();
        }

        return $file->taint->isDynamic($argument) ? $dynamic : null;
    }

    /**
     * @param  array<string, mixed>  $meta
     */
    protected function report(
        FileScope $file,
        Node $node,
        string $message,
        ?Severity $severity = null,
        ?string $remediation = null,
        array $meta = [],
    ): Finding {
        return $file->finding($this->id(), $node, $severity ?? $this->severity(), $message, $remediation, $meta);
    }
}

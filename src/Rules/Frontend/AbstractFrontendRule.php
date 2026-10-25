<?php

namespace Siberfx\RiskAnalyzer\Rules\Frontend;

use Siberfx\RiskAnalyzer\Category;
use Siberfx\RiskAnalyzer\Finding;
use Siberfx\RiskAnalyzer\Frontend\FrontendSource;
use Siberfx\RiskAnalyzer\Rules\AbstractProjectRule;
use Siberfx\RiskAnalyzer\ScanContext;
use Siberfx\RiskAnalyzer\Severity;

/**
 * A pattern-based rule over the frontend sources (frontend.paths or
 * --frontend). There is no JavaScript parser, so rules judge what they can
 * see on the matched expression and report variables for review.
 */
abstract class AbstractFrontendRule extends AbstractProjectRule
{
    public function category(): Category
    {
        return Category::Frontend;
    }

    public function run(ScanContext $context): iterable
    {
        foreach ($context->frontendFiles() as $path) {
            $source = $context->read($path);

            if ($source === null) {
                continue;
            }

            $file = new FrontendSource($path, $source);

            foreach ($this->inspect($file) as $finding) {
                if ($finding->line === null || ! $file->isIgnored($finding->rule, $finding->line)) {
                    yield $finding;
                }
            }
        }
    }

    /**
     * @return iterable<Finding>
     */
    abstract protected function inspect(FrontendSource $file): iterable;

    /**
     * @param  array<string, mixed>  $meta
     */
    protected function report(
        FrontendSource $file,
        int $line,
        string $message,
        ?Severity $severity = null,
        ?string $remediation = null,
        array $meta = [],
    ): Finding {
        return $this->finding($message, $severity, $remediation, $file->path, $line, $file->line($line), $meta);
    }

    /**
     * Shortens an expression for a message.
     */
    protected function excerpt(string $expression): string
    {
        return mb_strimwidth((string) preg_replace('/\s+/', ' ', trim($expression)), 0, 80, '…');
    }
}

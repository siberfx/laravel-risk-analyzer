<?php

namespace Siberfx\RiskAnalyzer\Rules\Infrastructure;

use Siberfx\RiskAnalyzer\Category;
use Siberfx\RiskAnalyzer\Finding;
use Siberfx\RiskAnalyzer\Infrastructure\InfrastructureFile;
use Siberfx\RiskAnalyzer\Rules\AbstractProjectRule;
use Siberfx\RiskAnalyzer\ScanContext;
use Siberfx\RiskAnalyzer\Severity;

/**
 * A pattern-based rule over the infrastructure files under
 * infrastructure.paths: Dockerfiles, compose files, shell scripts,
 * Makefiles, Envoy files and GitHub Actions workflows.
 */
abstract class AbstractInfrastructureRule extends AbstractProjectRule
{
    /** @var list<string> secrets.allow */
    protected array $allow = [];

    public function category(): Category
    {
        return Category::Infrastructure;
    }

    public function run(ScanContext $context): iterable
    {
        $this->allow = array_values(array_map('strval', (array) $context->config('secrets.allow', [])));

        foreach ($context->infrastructureFiles() as $path) {
            if (! in_array(InfrastructureFile::kind($path), $this->kinds(), true) || ($source = $context->read($path)) === null) {
                continue;
            }

            $file = new InfrastructureFile($path, $source);

            foreach ($this->inspect($file, $context) as $finding) {
                if ($finding->line === null || ! $file->isIgnored($finding->rule, $finding->line)) {
                    yield $finding;
                }
            }
        }
    }

    /**
     * @return list<string> InfrastructureFile kinds this rule reads
     */
    abstract protected function kinds(): array;

    /**
     * @return iterable<Finding>
     */
    abstract protected function inspect(InfrastructureFile $file, ScanContext $context): iterable;

    /**
     * @param  array<string, mixed>  $meta
     */
    protected function report(
        InfrastructureFile $file,
        int $line,
        string $message,
        ?Severity $severity = null,
        ?string $remediation = null,
        array $meta = [],
    ): Finding {
        return $this->finding($message, $severity, $remediation, $file->path, $line, $file->line($line), $meta);
    }
}

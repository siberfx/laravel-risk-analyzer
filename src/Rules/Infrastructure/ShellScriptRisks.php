<?php

namespace Siberfx\RiskAnalyzer\Rules\Infrastructure;

use Siberfx\RiskAnalyzer\Infrastructure\InfrastructureFile;
use Siberfx\RiskAnalyzer\Infrastructure\ShellChecks;
use Siberfx\RiskAnalyzer\ScanContext;
use Siberfx\RiskAnalyzer\Severity;

final class ShellScriptRisks extends AbstractInfrastructureRule
{
    public function id(): string
    {
        return 'shell-script-risks';
    }

    public function title(): string
    {
        return 'Risky commands in scripts and Makefiles';
    }

    public function description(): string
    {
        return 'Shell scripts (.sh, .bash, .zsh), Makefiles and Envoy files: secrets and tokens written into the script, database passwords on the command line, credentials in URLs, curl | sh, chmod 777, TLS checks turned off, eval of variables, and rm -r on a variable path that deletes from / when the variable is empty.';
    }

    public function severity(): Severity
    {
        return Severity::Critical;
    }

    protected function kinds(): array
    {
        return [InfrastructureFile::SHELL];
    }

    protected function inspect(InfrastructureFile $file, ScanContext $context): iterable
    {
        foreach (ShellChecks::inspect($file, $this->allow) as $issue) {
            yield $this->report($file, $issue['line'], $issue['message'], $issue['severity'], $issue['remediation']);
        }
    }
}

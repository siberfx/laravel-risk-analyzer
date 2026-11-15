<?php

namespace Siberfx\RiskAnalyzer\Rules\Infrastructure;

use Siberfx\RiskAnalyzer\Infrastructure\AptChecks;
use Siberfx\RiskAnalyzer\Infrastructure\InfrastructureFile;
use Siberfx\RiskAnalyzer\ScanContext;
use Siberfx\RiskAnalyzer\Severity;

final class AptHardening extends AbstractInfrastructureRule
{
    public function id(): string
    {
        return 'apt-hardening';
    }

    public function title(): string
    {
        return 'APT sources and signature checks in Dockerfiles and scripts';
    }

    public function description(): string
    {
        return 'Dockerfiles, shell scripts and GitHub Actions workflows that add APT sources marked trusted=yes (high), turn off repository or certificate checks with Acquire::AllowInsecureRepositories or Verify-Peer (high), or use plain http:// package mirrors (medium).';
    }

    public function severity(): Severity
    {
        return Severity::High;
    }

    protected function kinds(): array
    {
        return [InfrastructureFile::DOCKERFILE, InfrastructureFile::SHELL, InfrastructureFile::WORKFLOW];
    }

    protected function inspect(InfrastructureFile $file, ScanContext $context): iterable
    {
        foreach (AptChecks::inspect($file) as $issue) {
            yield $this->report($file, $issue['line'], $issue['message'], $issue['severity'], $issue['remediation']);
        }
    }
}

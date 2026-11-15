<?php

namespace Siberfx\RiskAnalyzer\Rules\Filesystem;

use Closure;
use Siberfx\RiskAnalyzer\Category;
use Siberfx\RiskAnalyzer\Rules\AbstractProjectRule;
use Siberfx\RiskAnalyzer\ScanContext;
use Siberfx\RiskAnalyzer\Severity;
use Siberfx\RiskAnalyzer\Support\AptSettings;

/**
 * Reads the APT configuration of the machine running the scan. Only Debian and
 * Ubuntu hosts have one; everywhere else the rule yields nothing.
 */
final class AptConfiguration extends AbstractProjectRule
{
    /**
     * @param  (Closure(): array{files: array<string, string>, os: array<string, string>}|null)|null  $host  reads /etc/apt by default
     */
    public function __construct(private readonly ?Closure $host = null) {}

    public function id(): string
    {
        return 'apt-configuration';
    }

    public function title(): string
    {
        return 'APT configuration on this Debian or Ubuntu host';
    }

    public function description(): string
    {
        return 'On a Debian or Ubuntu machine, the APT settings in /etc/apt: plain http:// sources combined with a non-zero Acquire::Retries (the condition of CVE-2026-109518; Debian 12 and Ubuntu 22.04 retry by default), sources marked trusted=yes, and turned-off repository or certificate checks.';
    }

    public function category(): Category
    {
        return Category::Filesystem;
    }

    public function severity(): Severity
    {
        return Severity::Medium;
    }

    public function run(ScanContext $context): iterable
    {
        $host = $this->host !== null ? ($this->host)() : $this->readHost();

        if ($host === null) {
            return;
        }

        foreach (AptSettings::assess($host['files'], $host['os']) as $issue) {
            yield $this->finding($issue['message'], $issue['severity'], $issue['remediation'], anchor: $issue['anchor']);
        }
    }

    /**
     * @return array{files: array<string, string>, os: array<string, string>}|null
     */
    private function readHost(): ?array
    {
        if (PHP_OS_FAMILY !== 'Linux' || ! is_dir('/etc/apt')) {
            return null;
        }

        $files = [];

        foreach (['/etc/apt/apt.conf' => 'apt.conf', '/etc/apt/sources.list' => 'sources.list'] as $path => $name) {
            if (is_file($path)) {
                $files[$name] = (string) file_get_contents($path);
            }
        }

        foreach (['apt.conf.d' => 'apt.conf.d', 'sources.list.d' => 'sources.list.d'] as $folder => $name) {
            foreach (glob("/etc/apt/{$folder}/*") ?: [] as $path) {
                if (is_file($path)) {
                    $files[$name.'/'.basename($path)] = (string) file_get_contents($path);
                }
            }
        }

        $os = is_file('/etc/os-release') ? parse_ini_string((string) file_get_contents('/etc/os-release')) : false;

        return ['files' => $files, 'os' => is_array($os) ? $os : []];
    }
}

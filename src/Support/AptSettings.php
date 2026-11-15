<?php

namespace Siberfx\RiskAnalyzer\Support;

use Siberfx\RiskAnalyzer\Infrastructure\AptChecks;
use Siberfx\RiskAnalyzer\Severity;

/**
 * Judges the APT configuration of a Debian or Ubuntu host: the files under
 * /etc/apt, and the retry count APT uses. Pure, so tests can feed it text.
 */
final class AptSettings
{
    /**
     * @param  array<string, string>  $files  relative name => contents: apt.conf, apt.conf.d/*, sources.list, sources.list.d/*
     * @param  array<string, string>  $os  /etc/os-release
     * @return list<array{anchor: string, message: string, severity: Severity, remediation: string}>
     */
    public static function assess(array $files, array $os): array
    {
        ksort($files);

        $issues = [];
        [$retries, $origin] = self::defaultRetries($os);
        $httpSources = 0;
        $httpFiles = [];

        foreach ($files as $name => $contents) {
            $isConfig = str_starts_with($name, 'apt.conf');

            if (! $isConfig && ! str_starts_with($name, 'sources.list')) {
                continue;
            }

            $text = self::enabled($name, $contents);

            if ($isConfig && preg_match_all('/Acquire::Retries\s+"?(\d+)"?\s*;/', $text, $matches) > 0) {
                $retries = (int) end($matches[1]);
                $origin = "set in /etc/apt/{$name}";
            }

            if (preg_match(AptChecks::TRUSTED, $text) === 1) {
                $issues[] = [
                    'anchor' => 'apt.trusted.'.$name,
                    'message' => "/etc/apt/{$name} marks a repository trusted=yes, so its packages are installed without a signature check.",
                    'severity' => Severity::High,
                    'remediation' => 'Remove trusted=yes and sign the repository: add its key under /etc/apt/keyrings and reference it with signed-by=.',
                ];
            }

            if (preg_match(AptChecks::INSECURE, $text) === 1) {
                $issues[] = [
                    'anchor' => 'apt.insecure.'.$name,
                    'message' => "/etc/apt/{$name} turns off repository or certificate checks (AllowInsecureRepositories or Verify-Peer).",
                    'severity' => Severity::High,
                    'remediation' => 'Remove the setting and fix the signature or certificate problem at its source.',
                ];
            }

            $count = preg_match_all(AptChecks::HTTP_SOURCE, $text);

            if ($count > 0) {
                $httpSources += $count;
                $httpFiles[] = "/etc/apt/{$name}";
            }
        }

        // The advisory's condition: plain-HTTP sources and a non-zero retry count.
        if ($httpSources > 0 && $retries > 0) {
            $issues[] = [
                'anchor' => 'apt.retries-over-http',
                'message' => "APT fetches packages over plain http:// ({$httpSources} source(s) in ".implode(', ', $httpFiles).") and retries failed downloads (Acquire::Retries {$retries}, {$origin}). This is the setup the CVE-2026-109518 advisory describes, where a man-in-the-middle on the path to the mirror can manipulate the traffic.",
                'severity' => Severity::Medium,
                'remediation' => 'Switch every APT source to https://, which removes the on-path manipulation. Set Acquire::Retries "0" only as a temporary workaround where https is not possible, since it turns off retries.',
            ];
        }

        return $issues;
    }

    /**
     * Debian 12 and Ubuntu 22.04 onward retry failed downloads 3 times by default; older releases do not.
     *
     * @param  array<string, string>  $os
     * @return array{0: int, 1: string}
     */
    private static function defaultRetries(array $os): array
    {
        $id = $os['ID'] ?? '';
        $version = $os['VERSION_ID'] ?? '';
        $name = $os['PRETTY_NAME'] ?? 'this system';

        $affected = ($id === 'debian' && version_compare($version, '12', '>='))
            || ($id === 'ubuntu' && version_compare($version, '22.04', '>='));

        return [$affected ? 3 : 0, "the default for {$name}"];
    }

    /**
     * The text APT would act on: comments removed, and for deb822 .sources files only the stanzas that are enabled.
     */
    private static function enabled(string $name, string $contents): string
    {
        $text = (string) preg_replace('~^\s*(?://|#).*$~m', '', $contents);

        if (! str_ends_with($name, '.sources')) {
            return $text;
        }

        $stanzas = preg_split('/\R\s*\R/', $text) ?: [];

        return implode("\n\n", array_filter($stanzas, fn (string $stanza) => preg_match('/^Enabled:\s*(no|false|0)\s*$/mi', $stanza) !== 1));
    }
}

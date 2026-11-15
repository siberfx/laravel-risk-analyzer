<?php

namespace Siberfx\RiskAnalyzer\Infrastructure;

use Siberfx\RiskAnalyzer\Severity;

/**
 * APT settings that skip package signature checks or fetch packages over plain
 * HTTP. Shared by the infrastructure rule (Dockerfiles, scripts, workflows) and
 * the host rule that reads /etc/apt.
 */
final class AptChecks
{
    /** deb [trusted=yes] …, and Trusted: yes in deb822 .sources files. */
    public const string TRUSTED = '/\[[^\]\n]*\btrusted=yes\b[^\]\n]*\]|^\s*Trusted:\s*yes\b/mi';

    /** Acquire::AllowInsecureRepositories "true" and Acquire::https::Verify-Peer "false". */
    public const string INSECURE = '/Acquire::(?:AllowInsecureRepositories|AllowDowngradeToInsecureRepositories)[\s"\'=]+(?:true|yes|1)\b|Acquire::[\w:\-]*Verify-Peer[\s"\'=]+(?:false|no|0)\b/i';

    /** deb http://…, deb [arch=amd64] http://…, and URIs: http://… in deb822 files. */
    public const string HTTP_SOURCE = '/\bdeb(?:-src)?\s+(?:\[[^\]\n]*\]\s*)*http:\/\/|(?i:\bURIs:)[ \t]*(?:\S+[ \t]+)*http:\/\//';

    /**
     * @return list<array{line: int, message: string, severity: Severity, remediation: string}>
     */
    public static function inspect(InfrastructureFile $file): array
    {
        $found = [];
        $add = function (int $line, string $message, Severity $severity, string $remediation) use (&$found): void {
            $found[] = ['line' => $line, 'message' => $message, 'severity' => $severity, 'remediation' => $remediation];
        };

        foreach ($file->matches(self::TRUSTED) as $match) {
            $add($match['line'], 'An APT source is marked trusted=yes, so its packages are installed without a signature check.', Severity::High,
                'Remove trusted=yes and sign the repository: add its key under /etc/apt/keyrings and reference it with signed-by=.');
        }

        foreach ($file->matches(self::INSECURE) as $match) {
            $add($match['line'], 'APT is set to accept unsigned repositories or to skip certificate checks.', Severity::High,
                'Remove the setting. Fix the signature or certificate problem at its source instead of turning the check off.');
        }

        foreach ($file->matches(self::HTTP_SOURCE) as $match) {
            $add($match['line'], 'An APT source uses plain http://, so packages are downloaded unencrypted and an attacker on the network path to the mirror can alter the traffic.', Severity::Medium,
                'Use https:// for the mirror. Debian and Ubuntu serve their archives over HTTPS; keep signed-by= so every package is still verified.');
        }

        return $found;
    }
}

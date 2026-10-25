<?php

namespace Siberfx\RiskAnalyzer\Infrastructure;

use Siberfx\RiskAnalyzer\Severity;
use Siberfx\RiskAnalyzer\Support\Secrets;

/**
 * Risky shell commands, shared by shell scripts, Makefiles, Envoy files and
 * Dockerfile RUN instructions.
 */
final class ShellChecks
{
    private const string SECRET_VARIABLE = '/(PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY|ACCESS_KEY|PRIVATE_KEY|CREDENTIALS?)/i';

    /**
     * @param  list<string>  $allow  literal values that are fine to commit (secrets.allow)
     * @return list<array{line: int, message: string, severity: Severity, remediation: string}>
     */
    public static function inspect(InfrastructureFile $file, array $allow = []): array
    {
        $found = [];
        $add = function (int $line, string $message, Severity $severity, string $remediation) use (&$found): void {
            $found[] = ['line' => $line, 'message' => $message, 'severity' => $severity, 'remediation' => $remediation];
        };

        foreach ($file->matches('/\b(curl|wget)\b[^|\n;]*\|\s*(?:sudo\s+(?:-\S+\s+)*)?(?:ba|z|da|k)?sh\b/') as $match) {
            $add($match['line'], "A script downloaded with {$match['groups'][1]} is piped straight into a shell.", Severity::Medium,
                'Download the script, verify its checksum or signature, then run it; or install a pinned package version.');
        }

        foreach ($file->matches('/\bchmod\s+(?:-\S+\s+)*(0?777|a\+rwx|ugo\+rwx|o\+w)\b/') as $match) {
            $add($match['line'], "chmod {$match['groups'][1]} makes files writable by every user.", Severity::Medium,
                'Give write access to the owner (and group) only: chown the folder to the web server user and use 755/644, or 775/664 for storage and bootstrap/cache.');
        }

        $insecure = [
            '/\bcurl\b[^\n]*?\s(-k|--insecure)\b/' => 'curl -k',
            '/\bwget\b[^\n]*--no-check-certificate/' => 'wget --no-check-certificate',
            '/\bgit\s+(?:-c\s+|config\s+(?:--global\s+)?)http\.sslVerify[\s=]+false\b/i' => 'git http.sslVerify false',
            '/\b(?:npm|yarn|pnpm)\s+config\s+set\s+strict-ssl\s+false\b/' => 'strict-ssl false',
            '/\bGIT_SSL_NO_VERIFY=\S/' => 'GIT_SSL_NO_VERIFY',
            '/\bNODE_TLS_REJECT_UNAUTHORIZED=["\']?0/' => 'NODE_TLS_REJECT_UNAUTHORIZED=0',
            '/\bcomposer\s+config\s+(?:-g\s+)?(?:secure-http|disable-tls)\s+(?:false|true)\b/' => 'composer TLS settings',
        ];

        foreach ($insecure as $pattern => $label) {
            foreach ($file->matches($pattern) as $match) {
                $add($match['line'], "TLS certificate checks are turned off ({$label}).", Severity::Medium,
                    'Keep certificate verification on; install the CA certificate (ca-certificates, NODE_EXTRA_CA_CERTS) if a proxy or private CA is in the way.');
            }
        }

        // mysql -pS3cret, mysqldump --password=S3cret
        foreach ($file->matches('/\b(?:mysql|mysqldump|mysqladmin|mariadb|mariadb-dump)\b[^\n]*?\s(?:-p|--password=)([^\s$\'"`-][^\s\'"`]*)/') as $match) {
            // -proot for a throwaway CI database is not a secret worth reporting.
            if (Secrets::looksReal($match['groups'][1], $allow)) {
                $add($match['line'], 'A database password is written on the command line.', Severity::High,
                    'Read it from the environment or an option file (--defaults-extra-file, MYSQL_PWD from a secret) instead of committing it.');
            }
        }

        // export AWS_SECRET_ACCESS_KEY=..., DB_PASSWORD="...", Makefile TOKEN := ...
        foreach ($file->matches('/(?<![\w$])(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*(?:=|:=|\?=)\s*([\'"]?)([^\s\'"$`{(][^\s\'"]*)\2/') as $match) {
            [, $name, , $value] = $match['groups'];

            if (preg_match(self::SECRET_VARIABLE, $name) && ! preg_match('/(_FILE|_PATH|_NAME|_URL|_HOST|_PORT|_USER|_ID)$/i', $name)
                && (Secrets::tokenFormat($value) !== null || Secrets::looksReal($value, $allow))) {
                $add($match['line'], "{$name} is set to a literal secret.", Severity::High,
                    'Inject it at runtime (CI secrets, a secret manager, an untracked .env) instead of committing it.');
            }
        }

        // https://user:password@host
        foreach ($file->matches('#\b[a-z][a-z0-9+.\-]*://([^/\s:@\'"$]+):([^@\s/\'"$]{3,})@#i') as $match) {
            if (! in_array($match['groups'][2], $allow, true)) {
                $add($match['line'], "A URL carries the credentials of '{$match['groups'][1]}'.", Severity::High,
                    'Pass credentials through a secret (environment variable, credential helper, netrc from a secret) rather than in the URL.');
            }
        }

        foreach ($file->matches('/[\'"=\s]((?:AKIA|ASIA)[0-9A-Z]{16}|(?:sk|rk)_live_[0-9a-zA-Z]{20,}|gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,}|xox[abposr]-[0-9A-Za-z-]{10,}|sk-ant-[A-Za-z0-9_\-]{20,}|glpat-[A-Za-z0-9_\-]{20,})/') as $match) {
            $label = Secrets::tokenFormat($match['groups'][1]) ?? 'Access token';

            if (! in_array($match['groups'][1], $allow, true)) {
                $add($match['line'], "{$label} committed in a script.", Severity::Critical,
                    'Revoke and rotate it, then inject it at runtime from your CI or secret manager.');
            }
        }

        foreach ($file->matches('/(?<![\w-])eval\s+["\']?\$/') as $match) {
            $add($match['line'], 'eval runs the contents of a variable as shell code.', Severity::Medium,
                'Call the command directly with quoted arguments, or use a case statement for the allowed values.');
        }

        // rm -rf "$DIR/" deletes from / when DIR is empty; ${DIR:?} aborts instead.
        foreach ($file->matches('/\brm\s+-[a-zA-Z]*[rR][a-zA-Z]*\s+(?:-\S+\s+)*["\']?\$(?:\{(\w+)\}|\((\w+)\)|(\w+))["\']?\//') as $match) {
            $variable = $match['groups'][1] ?: ($match['groups'][2] ?: $match['groups'][3]);

            if (in_array($variable, ['CURDIR', 'PWD'], true)) {
                continue;
            }

            $add($match['line'], "rm -r on \${$variable}: if it is empty or unset this deletes from the current directory or /.", Severity::Low,
                "Use \${{$variable}:?} so the command aborts when the variable is empty, and add set -u.");
        }

        return $found;
    }
}

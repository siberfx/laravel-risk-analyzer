<?php

namespace Siberfx\RiskAnalyzer\Rules\Filesystem;

use Siberfx\RiskAnalyzer\Category;
use Siberfx\RiskAnalyzer\Finding;
use Siberfx\RiskAnalyzer\Rules\AbstractProjectRule;
use Siberfx\RiskAnalyzer\ScanContext;
use Siberfx\RiskAnalyzer\Severity;
use Siberfx\RiskAnalyzer\Support\Secrets;
use Symfony\Component\Process\Process;

final class SecretsInVersionControl extends AbstractProjectRule
{
    private const string SENSITIVE = '#(^|/)(\.env(\.(?!example$|dist$|testing$|ci$)[^/]+)?|auth\.json|id_rsa|id_ed25519|oauth-(private|public)\.key|[^/]+\.(pem|p12|pfx|key)|\.npmrc|\.pypirc|credentials\.json|service-account[^/]*\.json)$#';

    public function id(): string
    {
        return 'secrets-in-git';
    }

    public function title(): string
    {
        return 'Secrets in version control';
    }

    public function description(): string
    {
        return 'Files committed to git that hold credentials: .env files, Passport/OAuth keys, auth.json, private keys, cloud service-account files. Templates (*.example, *.dist), committed vendor/ code and certificates without a private key are skipped; in Symfony projects .env and .env.<env> are only reported when they contain a real-looking secret (low for .env.dev/.env.test). Asks git what is tracked; falls back to checking .gitignore when git is unavailable.';
    }

    public function category(): Category
    {
        return Category::Filesystem;
    }

    public function severity(): Severity
    {
        return Severity::Critical;
    }

    public function run(ScanContext $context): iterable
    {
        $tracked = $this->trackedFiles($context);

        if ($tracked === null) {
            yield from $this->checkGitignore($context);

            return;
        }

        foreach ($tracked as $path) {
            if (! preg_match(self::SENSITIVE, $path) || str_starts_with($path, 'tests/') || str_contains($path, '/fixtures/')) {
                continue;
            }

            $severity = $this->credentialSeverity($context, $path);

            if ($severity !== null) {
                yield $this->finding("{$path} is committed to the repository.", $severity,
                    'Remove it from the index (git rm --cached '.$path.'), add it to .gitignore and rotate every secret it contained: it stays in the git history.',
                    $path, anchor: $path);
            }
        }
    }

    /**
     * How serious a committed sensitive-looking file is, or null when it holds no credentials.
     */
    private function credentialSeverity(ScanContext $context, string $path): ?Severity
    {
        // Templates, and dependencies someone committed (vendor/ with a CA bundle...).
        if (preg_match('/\.(example|dist|sample|template)$/', $path) || preg_match('#(^|/)(vendor|node_modules)/#', $path)) {
            return null;
        }

        // Package manager rc files are often committed for harmless settings (ignore-scripts, registry).
        if (preg_match('#(^|/)\.(npmrc|pypirc)$#', $path)) {
            return preg_match('/(_authToken|_auth|_password|password|token)\s*[=:]/i', (string) $context->read($path)) === 1 ? $this->severity() : null;
        }

        // Certificates and CA bundles are public; only private keys are secrets (Passport's key is one by name).
        if (preg_match('/\.(pem|key)$/', $path) && ! str_contains(basename($path), 'private')) {
            return str_contains((string) $context->read($path), 'PRIVATE KEY') ? $this->severity() : null;
        }

        // Symfony commits .env and .env.<env> with defaults by design; secrets belong in .env.local.
        if (preg_match('#(^|/)\.env(\.[^/]+)?$#', $path) && ! str_ends_with($path, '.local') && $this->isSymfony($context)) {
            if (! $this->holdsSecretValue((string) $context->read($path))) {
                return null;
            }

            return preg_match('#(^|/)\.env\.(dev|test)$#', $path) ? Severity::Low : Severity::Medium;
        }

        return $this->severity();
    }

    private function isSymfony(ScanContext $context): bool
    {
        $require = (array) ($context->readJson('composer.json')['require'] ?? []);

        return isset($require['symfony/framework-bundle']) || isset($require['symfony/dotenv']);
    }

    /**
     * An env file with a real-looking secret: APP_SECRET=..., or a password inside a DSN.
     */
    private function holdsSecretValue(string $contents): bool
    {
        foreach (preg_split('/\R/', $contents) ?: [] as $line) {
            if (! preg_match('/^\s*(?:export\s+)?([A-Z0-9_]+)\s*=\s*["\']?([^"\'\s#]*)/', $line, $match)) {
                continue;
            }

            [, $name, $value] = $match;

            if (preg_match('#://[^:/@\s]+:([^@\s]{3,})@#', $value, $dsn) && Secrets::looksReal($dsn[1])) {
                return true;
            }

            if (preg_match(Secrets::SECRET_NAME, $name) && (Secrets::tokenFormat($value) !== null || Secrets::looksReal($value))) {
                return true;
            }
        }

        return false;
    }

    /**
     * @return list<string>|null
     */
    private function trackedFiles(ScanContext $context): ?array
    {
        if (! is_dir($context->basePath('.git')) && ! is_file($context->basePath('.git'))) {
            return null;
        }

        $process = new Process(['git', 'ls-files', '-z'], $context->basePath(), timeout: 30);

        try {
            $process->run();
        } catch (\Throwable) {
            return null;
        }

        if (! $process->isSuccessful()) {
            return null;
        }

        return array_values(array_filter(explode("\0", $process->getOutput())));
    }

    /**
     * @return iterable<Finding>
     */
    private function checkGitignore(ScanContext $context): iterable
    {
        $ignore = $context->read('.gitignore');

        if ($ignore === null) {
            return;
        }

        $lines = array_map('trim', preg_split('/\R/', $ignore) ?: []);

        if (array_intersect($lines, ['.env', '/.env', '.env*', '/.env*', '*.env']) === []) {
            yield $this->finding('.env is not listed in .gitignore.', Severity::High,
                'Add /.env (and /.env.backup, /.env.production) to .gitignore.', '.gitignore', anchor: 'gitignore.env');
        }
    }
}

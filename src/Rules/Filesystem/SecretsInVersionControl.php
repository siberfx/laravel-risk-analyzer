<?php

namespace Siberfx\RiskAnalyzer\Rules\Filesystem;

use Siberfx\RiskAnalyzer\Category;
use Siberfx\RiskAnalyzer\Finding;
use Siberfx\RiskAnalyzer\Rules\AbstractProjectRule;
use Siberfx\RiskAnalyzer\ScanContext;
use Siberfx\RiskAnalyzer\Severity;
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
        return 'Files committed to git that hold credentials: .env files, Passport/OAuth keys, auth.json, private keys, cloud service-account files. Asks git what is tracked; falls back to checking .gitignore when git is unavailable.';
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
            if (preg_match(self::SENSITIVE, $path) && ! str_starts_with($path, 'tests/') && ! str_contains($path, '/fixtures/')
                && $this->mayHoldCredentials($context, $path)) {
                yield $this->finding("{$path} is committed to the repository.", null,
                    'Remove it from the index (git rm --cached '.$path.'), add it to .gitignore and rotate every secret it contained: it stays in the git history.',
                    $path, anchor: $path);
            }
        }
    }

    /**
     * Package manager rc files are often committed for harmless settings
     * (ignore-scripts, registry); only report them when they hold a token.
     */
    private function mayHoldCredentials(ScanContext $context, string $path): bool
    {
        if (! preg_match('#(^|/)\.(npmrc|pypirc)$#', $path)) {
            return true;
        }

        return preg_match('/(_authToken|_auth|_password|password|token)\s*[=:]/i', (string) $context->read($path)) === 1;
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

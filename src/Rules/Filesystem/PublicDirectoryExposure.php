<?php

namespace Siberfx\RiskAnalyzer\Rules\Filesystem;

use FilesystemIterator;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use Siberfx\RiskAnalyzer\Category;
use Siberfx\RiskAnalyzer\Rules\AbstractProjectRule;
use Siberfx\RiskAnalyzer\ScanContext;
use Siberfx\RiskAnalyzer\Severity;
use SplFileInfo;

final class PublicDirectoryExposure extends AbstractProjectRule
{
    /** Pattern on the file name => [what it is, severity]. */
    private const array SENSITIVE = [
        '/^\.env(\..+)?$/' => ['an environment file', Severity::Critical],
        '/^\.git$/' => ['a git repository', Severity::Critical],
        '/\.(sql|sqlite|db|dump)(\.gz|\.zip)?$/i' => ['a database dump', Severity::Critical],
        '/\.(pem|key|p12|pfx)$/i' => ['a private key or certificate bundle', Severity::Critical],
        '/^(auth\.json|id_rsa|id_ed25519)$/' => ['a credentials file', Severity::Critical],
        '/\.(zip|tar|tgz|tar\.gz|rar|7z|bak|old|orig|swp)$/i' => ['a backup or archive', Severity::High],
        '/^(phpinfo|info|test|debug|adminer|phpmyadmin)\.php$/i' => ['a diagnostic script', Severity::High],
        '/\.log$/i' => ['a log file', Severity::Medium],
        '/^(composer\.(json|lock)|package(-lock)?\.json|yarn\.lock)$/' => ['a dependency manifest', Severity::Low],
    ];

    public function id(): string
    {
        return 'public-exposure';
    }

    public function title(): string
    {
        return 'Sensitive files in public/';
    }

    public function description(): string
    {
        return 'Files the web server serves as-is from public/: environment files, .git, database dumps, keys, backups, phpinfo/adminer scripts and logs.';
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
        $public = $context->basePath('public');

        if (! is_dir($public)) {
            return;
        }

        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($public, FilesystemIterator::SKIP_DOTS),
            RecursiveIteratorIterator::SELF_FIRST,
        );
        $iterator->setMaxDepth(3);

        /** @var SplFileInfo $file */
        foreach ($iterator as $file) {
            $relative = $context->relative($file->getPathname());

            // Skip the storage symlink and build output.
            if (preg_match('#^public/(storage|build|vendor)/#', $relative)) {
                continue;
            }

            foreach (self::SENSITIVE as $pattern => [$label, $severity]) {
                if (preg_match($pattern, $file->getFilename())) {
                    yield $this->finding("{$relative} is {$label} inside the web root.", $severity,
                        'Move it out of public/ (or delete it) and block dotfiles in the web server config.',
                        $relative, anchor: $relative);

                    break;
                }
            }
        }
    }
}

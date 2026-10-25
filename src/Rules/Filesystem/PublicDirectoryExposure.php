<?php

namespace Siberfx\RiskAnalyzer\Rules\Filesystem;

use FilesystemIterator;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use Siberfx\RiskAnalyzer\Category;
use Siberfx\RiskAnalyzer\Finding;
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

    /** Uploads on a linked disk: archives and manifests are normal there, executable scripts are not. */
    private const array LINKED = [
        '/\.(php\d?|phtml|phar|pht)$/i' => ['a PHP file the web server may execute', Severity::Critical],
        '/^\.env(\..+)?$/' => ['an environment file', Severity::Critical],
        '/\.(sql|sqlite|db|dump)(\.gz|\.zip)?$/i' => ['a database dump', Severity::Critical],
        '/\.(pem|key|p12|pfx)$/i' => ['a private key or certificate bundle', Severity::Critical],
        '/^(auth\.json|id_rsa|id_ed25519)$/' => ['a credentials file', Severity::Critical],
        '/\.log$/i' => ['a log file', Severity::Medium],
        '/^\.htaccess$/' => ['an .htaccess file that can change how the server treats the folder', Severity::High],
    ];

    /** Files looked at per linked folder, so huge upload folders stay fast. */
    private const int LINKED_LIMIT = 20000;

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
        return 'Files the web server serves as-is from public/: environment files, .git, database dumps, keys, backups, phpinfo/adminer scripts and logs. Folders linked into public/ (filesystems.links, e.g. public/storage) are checked for PHP files, dumps, keys, logs and .htaccess. Built source maps (*.js.map, *.css.map) are reported as low.';
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

        yield from $this->linkedFolders($context);
        yield from $this->sourceMaps($context);
    }

    /**
     * Built source maps (public/build/assets/*.js.map...) publish the original
     * frontend source. One finding per folder: the file names are hashed.
     *
     * @return iterable<Finding>
     */
    private function sourceMaps(ScanContext $context): iterable
    {
        $iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($context->basePath('public'), FilesystemIterator::SKIP_DOTS));
        $iterator->setMaxDepth(4);
        $maps = [];

        /** @var SplFileInfo $file */
        foreach ($iterator as $file) {
            $relative = $context->relative($file->getPathname());

            if (preg_match('/\.(js|mjs|css)\.map$/', $relative) && ! str_starts_with($relative, 'public/storage/')) {
                $maps[dirname($relative)][] = $relative;
            }
        }

        foreach ($maps as $folder => $files) {
            sort($files);

            yield $this->finding(
                count($files) === 1 ? "{$files[0]} is a source map: it publishes the original frontend source." : "{$folder} holds ".count($files).' source maps (e.g. '.basename($files[0]).'): they publish the original frontend source.',
                Severity::Low,
                'Build without source maps for production (build.sourcemap: false in vite.config, the default), or upload them to your error tracker and delete them from public/.',
                $files[0],
                anchor: 'source-maps:'.$folder,
            );
        }
    }

    /**
     * Targets of filesystems.links inside public/ (php artisan storage:link), when the link exists.
     *
     * @return iterable<Finding>
     */
    private function linkedFolders(ScanContext $context): iterable
    {
        $public = str_replace('\\', '/', $context->basePath('public'));

        foreach ((array) $context->settings()->get('filesystems.links', []) as $link => $target) {
            $link = str_replace('\\', '/', (string) $link);
            $target = str_replace('\\', '/', (string) $target);

            if (! str_starts_with($link, $public.'/') || ! file_exists($link) || ! is_dir($target)) {
                continue;
            }

            $url = substr($link, strlen($public));
            $iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($target, FilesystemIterator::SKIP_DOTS));
            $iterator->setMaxDepth(8);
            $seen = 0;

            /** @var SplFileInfo $file */
            foreach ($iterator as $file) {
                if (++$seen > self::LINKED_LIMIT) {
                    break;
                }

                foreach (self::LINKED as $pattern => [$label, $severity]) {
                    if (preg_match($pattern, $file->getFilename())) {
                        $relative = $context->relative($file->getPathname());
                        $served = $url.substr(str_replace('\\', '/', $file->getPathname()), strlen($target));

                        yield $this->finding("{$relative} is {$label}, served at {$served}.", $severity,
                            'Delete it, validate upload extensions (mimes:/extensions: rules), and stop the web server from running PHP under '.$url.'.',
                            $relative, anchor: $relative);

                        break;
                    }
                }
            }
        }
    }
}

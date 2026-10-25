<?php

namespace Siberfx\RiskAnalyzer;

use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Routing\Router;
use Illuminate\Support\Arr;
use RecursiveCallbackFilterIterator;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use Siberfx\RiskAnalyzer\Infrastructure\InfrastructureFile;
use SplFileInfo;

/**
 * Everything a rule needs to know about the scan it is part of.
 */
final class ScanContext
{
    private readonly string $basePath;

    /** @var list<string>|null */
    private ?array $infrastructureFiles = null;

    /**
     * @param  array<string, mixed>  $config  the "risk-analyzer" config
     * @param  list<string>|null  $onlyFiles  relative paths; limits code rules to these files (--changed)
     * @param  list<string>|null  $frontendPaths  folders that replace frontend.paths (--frontend)
     */
    public function __construct(
        public readonly Application $app,
        string $basePath,
        public readonly array $config,
        public readonly bool $production = false,
        public readonly bool $offline = false,
        public readonly ?array $onlyFiles = null,
        public readonly ?array $frontendPaths = null,
    ) {
        $this->basePath = rtrim(str_replace('\\', '/', $basePath), '/');
    }

    public function basePath(string $path = ''): string
    {
        if (self::isAbsolute($path)) {
            return rtrim(str_replace('\\', '/', $path), '/');
        }

        return $path === '' ? $this->basePath : $this->basePath.'/'.ltrim($path, '/');
    }

    public static function isAbsolute(string $path): bool
    {
        return preg_match('#^([a-zA-Z]:)?[\\\\/]#', $path) === 1;
    }

    public function relative(string $absolute): string
    {
        $absolute = str_replace('\\', '/', $absolute);

        return str_starts_with($absolute, $this->basePath.'/')
            ? substr($absolute, strlen($this->basePath) + 1)
            : $absolute;
    }

    /**
     * A value from the "risk-analyzer" config.
     */
    public function config(string $key, mixed $default = null): mixed
    {
        return Arr::get($this->config, $key, $default);
    }

    /**
     * The application's configuration repository.
     */
    public function settings(): Repository
    {
        return $this->app->make(Repository::class);
    }

    public function router(): Router
    {
        return $this->app->make(Router::class);
    }

    public function exists(string $path): bool
    {
        return file_exists($this->basePath($path));
    }

    public function read(string $path): ?string
    {
        $file = $this->basePath($path);

        return is_file($file) ? (file_get_contents($file) ?: null) : null;
    }

    /**
     * @return array<mixed>|null
     */
    public function readJson(string $path): ?array
    {
        $contents = $this->read($path);

        if ($contents === null) {
            return null;
        }

        $data = json_decode($contents, true);

        return is_array($data) ? $data : null;
    }

    /**
     * Source files under the configured code paths, as relative paths.
     *
     * @param  list<string>  $suffixes  e.g. ['.php'] or ['.blade.php']
     * @return iterable<string>
     */
    public function files(array $suffixes): iterable
    {
        yield from $this->walk(
            (array) $this->config('paths', []),
            (array) $this->config('exclude', []),
            fn (string $relative) => $this->matchesSuffix($relative, $suffixes),
        );
    }

    /**
     * Folders holding the frontend sources (React, Vue, Angular...): the
     * --frontend folders when given, otherwise frontend.paths. Relative to
     * the project root unless absolute.
     *
     * @return list<string>
     */
    public function frontendRoots(): array
    {
        return $this->roots($this->frontendPaths ?? (array) $this->config('frontend.paths', []));
    }

    /**
     * Dockerfiles, compose files, shell scripts, Makefiles, Envoy files and
     * GitHub Actions workflows under infrastructure.paths, as relative paths.
     *
     * @return list<string>
     */
    public function infrastructureFiles(): array
    {
        return $this->infrastructureFiles ??= iterator_to_array($this->walk(
            $this->roots((array) $this->config('infrastructure.paths', ['.'])),
            (array) $this->config('infrastructure.exclude', []),
            fn (string $relative) => InfrastructureFile::kind($relative) !== null,
        ), false);
    }

    /**
     * @param  array<mixed>  $paths
     * @return list<string>
     */
    private function roots(array $paths): array
    {
        return array_values(array_unique(array_map(function ($path) {
            $path = str_replace('\\', '/', (string) $path);

            // "." and "./client" are relative to the project root.
            return self::isAbsolute($path) ? rtrim($path, '/') : trim((string) preg_replace('#^\.(/|$)#', '', $path), '/');
        }, $paths)));
    }

    /**
     * Frontend source files (frontend.extensions) under frontendRoots(),
     * without minified bundles, type declarations and tests.
     *
     * @return iterable<string>
     */
    public function frontendFiles(): iterable
    {
        $extensions = array_values(array_map(fn ($extension) => '.'.ltrim((string) $extension, '.'), (array) $this->config('frontend.extensions', [])));

        yield from $this->walk(
            $this->frontendRoots(),
            (array) $this->config('frontend.exclude', []),
            fn (string $relative) => $this->matchesSuffix($relative, $extensions)
                && ! preg_match('/\.(min|d|spec|test|stories)\.[cm]?[jt]sx?$/', $relative),
        );
    }

    /**
     * @param  array<mixed>  $roots
     * @param  array<mixed>  $exclude
     * @param  callable(string): bool  $accept
     * @return iterable<string>
     */
    private function walk(array $roots, array $exclude, callable $accept): iterable
    {
        $exclude = array_values(array_map(fn ($path) => trim(str_replace('\\', '/', (string) $path), '/'), $exclude));
        $seen = [];

        foreach ($roots as $root) {
            $directory = $this->basePath(self::isAbsolute((string) $root) ? (string) $root : trim((string) $root, '/'));

            if (! is_dir($directory)) {
                continue;
            }

            // Exclusions apply inside the root, so an absolute root is not excluded by its own path.
            $excluded = fn (string $path) => $this->isExcluded($this->relative($path), $exclude)
                || $this->isExcluded(substr(str_replace('\\', '/', $path), strlen($directory) + 1), $exclude);

            // Excluded folders (vendor, node_modules...) are not entered at all.
            $iterator = new RecursiveIteratorIterator(new RecursiveCallbackFilterIterator(
                new RecursiveDirectoryIterator($directory, RecursiveDirectoryIterator::SKIP_DOTS),
                fn (SplFileInfo $file, string $path, RecursiveDirectoryIterator $iterator) => ! $iterator->hasChildren() || ! $excluded($file->getPathname().'/-'),
            ));

            /** @var SplFileInfo $file */
            foreach ($iterator as $file) {
                $relative = $this->relative($file->getPathname());

                if (isset($seen[$relative]) || ! $accept($relative) || $excluded($file->getPathname())) {
                    continue;
                }

                if ($this->onlyFiles !== null && ! in_array($relative, $this->onlyFiles, true)) {
                    continue;
                }

                $seen[$relative] = true;

                yield $relative;
            }
        }
    }

    /**
     * @param  list<string>  $suffixes
     */
    private function matchesSuffix(string $path, array $suffixes): bool
    {
        return array_any($suffixes, fn (string $suffix) => str_ends_with($path, $suffix));
    }

    /**
     * @param  list<string>  $exclude
     */
    private function isExcluded(string $path, array $exclude): bool
    {
        return array_any($exclude, fn (string $prefix) => $prefix !== '' && ($path === $prefix || str_starts_with($path, $prefix.'/')
            || str_contains('/'.$path, '/'.$prefix.'/')));
    }
}

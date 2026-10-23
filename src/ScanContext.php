<?php

namespace Siberfx\RiskAnalyzer;

use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Routing\Router;
use Illuminate\Support\Arr;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use SplFileInfo;

/**
 * Everything a rule needs to know about the scan it is part of.
 */
final class ScanContext
{
    private readonly string $basePath;

    /**
     * @param  array<string, mixed>  $config  the "risk-analyzer" config
     * @param  list<string>|null  $onlyFiles  relative paths; limits code rules to these files (--changed)
     */
    public function __construct(
        public readonly Application $app,
        string $basePath,
        public readonly array $config,
        public readonly bool $production = false,
        public readonly bool $offline = false,
        public readonly ?array $onlyFiles = null,
    ) {
        $this->basePath = rtrim(str_replace('\\', '/', $basePath), '/');
    }

    public function basePath(string $path = ''): string
    {
        return $path === '' ? $this->basePath : $this->basePath.'/'.ltrim($path, '/');
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
        $exclude = array_values(array_map(fn ($path) => trim(str_replace('\\', '/', (string) $path), '/'), (array) $this->config('exclude', [])));
        $seen = [];

        foreach ((array) $this->config('paths', []) as $root) {
            $directory = $this->basePath(trim($root, '/'));

            if (! is_dir($directory)) {
                continue;
            }

            $iterator = new RecursiveIteratorIterator(
                new RecursiveDirectoryIterator($directory, RecursiveDirectoryIterator::SKIP_DOTS),
            );

            /** @var SplFileInfo $file */
            foreach ($iterator as $file) {
                $relative = $this->relative($file->getPathname());

                if (isset($seen[$relative]) || ! $this->matchesSuffix($relative, $suffixes) || $this->isExcluded($relative, $exclude)) {
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

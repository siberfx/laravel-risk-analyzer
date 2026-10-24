<?php

namespace Siberfx\RiskAnalyzer\Support;

use Composer\Semver\VersionParser;
use Siberfx\RiskAnalyzer\ScanContext;
use Symfony\Component\Process\Process;
use Throwable;

/**
 * Finds the Node.js major versions a project pins or runs: version files,
 * package.json, Dockerfiles, compose files, GitHub Actions and the installed
 * binary. Aliases such as "lts/*" or "node:current" are skipped.
 */
final class NodeVersions
{
    /**
     * @return list<array{major: int, source: string, file: ?string, line: ?int}>
     */
    public static function detect(ScanContext $context, string|false|null $binary = 'node'): array
    {
        $found = [];

        foreach (['.nvmrc', '.node-version'] as $file) {
            $major = self::major(trim((string) $context->read($file)));

            if ($major !== null) {
                $found[] = self::entry($major, $file, 1);
            }
        }

        $package = $context->readJson('package.json') ?? [];

        if (is_string($package['engines']['node'] ?? null) && ($major = self::lowestMajor($package['engines']['node'])) !== null) {
            $found[] = self::entry($major, 'package.json', null, 'package.json engines.node');
        }

        if (is_string($package['volta']['node'] ?? null) && ($major = self::major($package['volta']['node'])) !== null) {
            $found[] = self::entry($major, 'package.json', null, 'package.json volta.node');
        }

        $patterns = [
            '/^\s*FROM\s+(?:--platform=\S+\s+)?(?:[\w.\-]+(?::\d+)?\/)*node:([^\s@]+)/im',
            '/^\s*image:\s*[\'"]?(?:[\w.\-]+(?::\d+)?\/)*node:([^\s\'"@]+)/im',
        ];

        foreach (self::files($context, ['Dockerfile*', '*.Dockerfile', 'docker/*/Dockerfile*', 'docker/Dockerfile*', 'docker-compose*.yml', 'docker-compose*.yaml', 'compose*.yml', 'compose*.yaml']) as $file) {
            foreach ($patterns as $pattern) {
                foreach (self::matches($context, $file, $pattern) as [$value, $line]) {
                    if (($major = self::major($value)) !== null) {
                        $found[] = self::entry($major, $file, $line);
                    }
                }
            }
        }

        foreach (self::files($context, ['.github/workflows/*.yml', '.github/workflows/*.yaml']) as $file) {
            foreach (self::matches($context, $file, '/^\s*-?\s*node-version:\s*(.+)$/m') as [$value, $line]) {
                // node-version: 20 | '20.x' | [18, 20]; expressions like ${{ matrix.node }} are skipped.
                if (str_contains($value, '${{')) {
                    continue;
                }

                foreach (preg_split('/[\s,\[\]\'"]+/', $value, -1, PREG_SPLIT_NO_EMPTY) ?: [] as $version) {
                    if (($major = self::major($version)) !== null) {
                        $found[] = self::entry($major, $file, $line);
                    }
                }
            }
        }

        if (is_string($binary) && $binary !== '' && ($major = self::installed($binary)) !== null) {
            $found[] = self::entry($major, null, null, "installed {$binary}");
        }

        return $found;
    }

    /**
     * "20", "v20.11.1", "20-alpine", "20.x" => 20; "lts/*", "current", "node" => null.
     */
    public static function major(string $version): ?int
    {
        return preg_match('/^v?(\d+)(?:$|[.\-x])/i', trim($version), $match) === 1 ? (int) $match[1] : null;
    }

    /**
     * The lowest major a range allows: ">=18" => 18, "^20 || ^22" => 20.
     */
    public static function lowestMajor(string $range): ?int
    {
        try {
            $lower = (new VersionParser)->parseConstraints(trim($range))->getLowerBound();

            if (! $lower->isZero()) {
                return (int) explode('.', $lower->getVersion())[0];
            }
        } catch (Throwable) {
            // npm-only syntax composer does not parse: take the lowest number.
        }

        preg_match_all('/(?<![<\d.])(\d+)(?:\.[\dx*]+)*/i', $range, $matches);

        return $matches[1] === [] ? null : min(array_map('intval', $matches[1]));
    }

    private static function installed(string $binary): ?int
    {
        try {
            $process = new Process([$binary, '--version']);
            $process->setTimeout(5);
            $process->run();

            return $process->isSuccessful() ? self::major(trim($process->getOutput())) : null;
        } catch (Throwable) {
            return null;
        }
    }

    /**
     * @return array{major: int, source: string, file: ?string, line: ?int}
     */
    private static function entry(int $major, ?string $file, ?int $line, ?string $source = null): array
    {
        return [
            'major' => $major,
            'source' => $source ?? ($line !== null ? "{$file}:{$line}" : (string) $file),
            'file' => $file,
            'line' => $line,
        ];
    }

    /**
     * @param  list<string>  $patterns  globs relative to the project root
     * @return list<string>
     */
    private static function files(ScanContext $context, array $patterns): array
    {
        $files = [];

        foreach ($patterns as $pattern) {
            foreach (glob($context->basePath($pattern)) ?: [] as $path) {
                if (is_file($path)) {
                    $files[$context->relative($path)] = true;
                }
            }
        }

        return array_keys($files);
    }

    /**
     * @return list<array{string, int}> captured value and its line number
     */
    private static function matches(ScanContext $context, string $file, string $pattern): array
    {
        $contents = (string) $context->read($file);
        $results = [];

        if (preg_match_all($pattern, $contents, $matches, PREG_OFFSET_CAPTURE) > 0) {
            foreach ($matches[1] as [$value, $offset]) {
                $results[] = [trim($value), substr_count($contents, "\n", 0, $offset) + 1];
            }
        }

        return $results;
    }
}

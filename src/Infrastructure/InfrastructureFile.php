<?php

namespace Siberfx\RiskAnalyzer\Infrastructure;

use Siberfx\RiskAnalyzer\Code\FileScope;
use Siberfx\RiskAnalyzer\Code\Taint;

/**
 * A Dockerfile, compose file, shell script, Makefile, Envoy file or GitHub
 * Actions workflow. Rules match patterns against $code, the source with
 * "#" comments blanked out so that offsets and line numbers stay the same.
 */
final class InfrastructureFile
{
    public const string DOCKERFILE = 'dockerfile';

    public const string COMPOSE = 'compose';

    public const string SHELL = 'shell';

    public const string WORKFLOW = 'workflow';

    public readonly string $code;

    public readonly string $kind;

    private readonly FileScope $scope;

    public function __construct(
        public readonly string $path,
        public readonly string $source,
    ) {
        $this->kind = self::kind($path) ?? self::SHELL;
        $this->scope = new FileScope($path, $source, new Taint);
        // Envoy files are Blade with shell inside @task; their comments are {{-- --}}.
        $this->code = str_ends_with($path, '.blade.php') ? $source : (string) preg_replace_callback(
            '/(?<=^|[ \t])#(?!\{)[^\r\n]*/m',
            fn (array $match) => (string) preg_replace('/[^\r\n]/', ' ', $match[0]),
            $source,
        );
    }

    /**
     * The kind of infrastructure file at $path, or null for anything else.
     */
    public static function kind(string $path): ?string
    {
        $name = basename($path);

        return match (true) {
            preg_match('/^(Dockerfile|Containerfile)([.\-].+)?$|\.(Dockerfile|dockerfile|Containerfile)$/', $name) === 1 => self::DOCKERFILE,
            preg_match('/^(docker-)?compose([.\-][\w.\-]+)?\.ya?ml$/', $name) === 1 => self::COMPOSE,
            preg_match('#(^|/)\.github/workflows/[^/]+\.ya?ml$#', $path) === 1 => self::WORKFLOW,
            preg_match('/\.(sh|bash|zsh)$|^(GNU)?[Mm]akefile$|\.mk$|^Envoy\.blade\.php$/', $name) === 1 => self::SHELL,
            default => null,
        };
    }

    /**
     * Matches of $pattern in the code, with the line each starts on.
     *
     * @return iterable<array{line: int, groups: array<int|string, string>}>
     */
    public function matches(string $pattern): iterable
    {
        preg_match_all($pattern, $this->code, $matches, PREG_SET_ORDER | PREG_OFFSET_CAPTURE | PREG_UNMATCHED_AS_NULL);

        foreach ($matches as $match) {
            yield [
                'line' => substr_count($this->code, "\n", 0, (int) $match[0][1]) + 1,
                'groups' => array_map(fn (array $group) => (string) $group[0], $match),
            ];
        }
    }

    /**
     * @return list<string> the code, one entry per line
     */
    public function lines(): array
    {
        return preg_split('/\R/', $this->code) ?: [];
    }

    public function line(int $line): ?string
    {
        return $this->scope->line($line);
    }

    public function isIgnored(string $rule, int $line): bool
    {
        return $this->scope->isIgnored($rule, $line);
    }

    /**
     * A production compose file (docker-compose.prod.yml, compose.production.yaml...).
     */
    public function isProduction(): bool
    {
        return preg_match('/(^|[.\-_])(prod|production|live)([.\-_]|$)/i', basename($this->path, '.yml')) === 1
            || preg_match('/(^|[.\-_])(prod|production|live)([.\-_]|$)/i', basename($this->path, '.yaml')) === 1;
    }
}

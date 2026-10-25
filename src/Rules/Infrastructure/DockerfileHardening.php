<?php

namespace Siberfx\RiskAnalyzer\Rules\Infrastructure;

use Siberfx\RiskAnalyzer\Finding;
use Siberfx\RiskAnalyzer\Infrastructure\InfrastructureFile;
use Siberfx\RiskAnalyzer\Infrastructure\ShellChecks;
use Siberfx\RiskAnalyzer\ScanContext;
use Siberfx\RiskAnalyzer\Severity;
use Siberfx\RiskAnalyzer\Support\Secrets;

final class DockerfileHardening extends AbstractInfrastructureRule
{
    private const string SECRET_NAME = '/(PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY|ACCESS_KEY|PRIVATE_KEY|CREDENTIALS?|APP_KEY)/i';

    private const string NOT_SECRET = '/(_FILE|_PATH|_NAME|_URL|_HOST|_PORT|_USER|_ID|_DIR)$/i';

    public function id(): string
    {
        return 'dockerfile-hardening';
    }

    public function title(): string
    {
        return 'Dockerfile hardening';
    }

    public function description(): string
    {
        return 'Dockerfiles: secrets in ENV (high) or passed as build ARGs (medium), which end up in the image; COPY . without a .dockerignore that keeps .env out; ADD of remote URLs without --checksum; base images without a tag or on :latest; a final stage that runs as root; plus the shell checks (curl | sh, chmod 777, TLS checks off, inline passwords) on RUN lines.';
    }

    public function severity(): Severity
    {
        return Severity::High;
    }

    protected function kinds(): array
    {
        return [InfrastructureFile::DOCKERFILE];
    }

    protected function inspect(InfrastructureFile $file, ScanContext $context): iterable
    {
        $stages = [];
        $user = null;
        $from = null;
        $runLines = [];

        foreach ($this->instructions($file) as [$line, $instruction, $arguments, $end]) {
            switch ($instruction) {
                case 'RUN':
                    array_push($runLines, ...range($line, $end));

                    break;

                case 'FROM':
                    preg_match('/^(?:--\S+\s+)*(\S+)(?:\s+AS\s+(\S+))?/i', $arguments, $match);
                    $image = $match[1] ?? '';
                    $user = null;
                    $from = $line;

                    if (isset($match[2])) {
                        $stages[] = strtolower($match[2]);
                    }

                    if ($image === '' || strtolower($image) === 'scratch' || str_contains($image, '$') || in_array(strtolower($image), $stages, true) || str_contains($image, '@sha256:')) {
                        break;
                    }

                    $name = basename($image);
                    $tag = str_contains($name, ':') ? substr($name, strpos($name, ':') + 1) : null;

                    if ($tag === null || $tag === 'latest') {
                        yield $this->report($file, $line, "Base image {$image} is not pinned to a version, so rebuilds silently pick up new (and possibly breaking or compromised) images.", Severity::Low,
                            'Pin a version tag (php:8.4-fpm-alpine), or a digest (@sha256:...) for reproducible builds.');
                    }

                    break;

                case 'USER':
                    $user = trim($arguments);

                    break;

                case 'ADD':
                    if (preg_match('#(?:^|\s)https?://#', $arguments) && ! str_contains($arguments, '--checksum')) {
                        yield $this->report($file, $line, 'ADD downloads a remote file without verifying it.', Severity::Medium,
                            'Use ADD --checksum=sha256:... or download with curl and check the hash in the same RUN.');
                    }

                    yield from $this->copiesContext($file, $context, $line, $arguments);

                    break;

                case 'COPY':
                    yield from $this->copiesContext($file, $context, $line, $arguments);

                    break;

                case 'ENV':
                case 'ARG':
                    foreach ($this->variables($instruction, $arguments) as [$name, $value]) {
                        if (! preg_match(self::SECRET_NAME, $name) || preg_match(self::NOT_SECRET, $name)) {
                            continue;
                        }

                        if ($instruction === 'ARG') {
                            yield $this->report($file, $line, "Build argument {$name} looks like a secret; build arguments are stored in the image history (docker history).", Severity::Medium,
                                'Mount it for the one RUN that needs it: RUN --mount=type=secret,id='.strtolower($name).' ... and docker build --secret.');
                        } elseif (str_contains($value, '$')) {
                            yield $this->report($file, $line, "ENV {$name} copies a build value into the image, where anyone who can pull it reads it.", Severity::Medium,
                                'Pass the secret when the container starts (environment, secrets: in compose, your orchestrator\'s secret store) instead of baking it in.');
                        } elseif (Secrets::tokenFormat($value) !== null || Secrets::looksReal($value, $this->allow)) {
                            yield $this->report($file, $line, "ENV {$name} bakes a secret into the image.", Severity::High,
                                'Rotate it and pass it when the container starts (environment, compose secrets, your orchestrator\'s secret store).');
                        }
                    }

                    break;
            }
        }

        // Only the final stage decides who the container runs as.
        if ($from !== null && ($user === null || in_array(strtolower(explode(':', $user)[0]), ['root', '0'], true))) {
            yield $this->report($file, $from, $user === null ? 'The final stage has no USER instruction, so the container runs as root.' : "The final stage runs as {$user}.", Severity::Low,
                'Add USER www-data (or another unprivileged user) after installing packages. php-fpm images can keep the master as root only if the pool runs as www-data.');
        }

        // ENV and ARG secrets are judged above, with Docker-specific advice.
        foreach (ShellChecks::inspect($file, $this->allow) as $issue) {
            if (! in_array($issue['line'], $runLines, true)) {
                continue;
            }

            yield $this->report($file, $issue['line'], $issue['message'], $issue['severity'], $issue['remediation']);
        }
    }

    /**
     * Instructions with continuation lines joined.
     *
     * @return list<array{int, string, string, int}> start line, upper-cased instruction, arguments, end line
     */
    private function instructions(InfrastructureFile $file): array
    {
        $instructions = [];
        $current = null;

        foreach ($file->lines() as $index => $text) {
            if ($current !== null) {
                $current[2] .= ' '.trim(rtrim($text), '\\');
            } elseif (preg_match('/^\s*([A-Za-z]+)\s+(.*)$/', $text, $match)) {
                $current = [$index + 1, strtoupper($match[1]), rtrim(rtrim($match[2]), '\\')];
            } else {
                continue;
            }

            if (! str_ends_with(rtrim($text), '\\')) {
                $instructions[] = [$current[0], $current[1], trim($current[2]), $index + 1];
                $current = null;
            }
        }

        if ($current !== null) {
            $instructions[] = [$current[0], $current[1], trim($current[2]), count($file->lines())];
        }

        return $instructions;
    }

    /**
     * ENV A=1 B="two", legacy ENV A some value, ARG NAME[=default].
     *
     * @return list<array{string, string}>
     */
    private function variables(string $instruction, string $arguments): array
    {
        if ($instruction === 'ENV' && ! preg_match('/^[\w.\-]+=/', $arguments)) {
            $parts = preg_split('/\s+/', $arguments, 2) ?: [];

            return isset($parts[0]) ? [[$parts[0], trim($parts[1] ?? '', '"\'')]] : [];
        }

        preg_match_all('/([A-Za-z_][\w.\-]*)(?:=("[^"]*"|\'[^\']*\'|\S*))?/', $arguments, $matches, PREG_SET_ORDER);

        return array_map(fn (array $match) => [$match[1], trim($match[2] ?? '', '"\'')], $matches);
    }

    /**
     * COPY . /var/www without a .dockerignore keeping .env out of the image.
     *
     * @return iterable<Finding>
     */
    private function copiesContext(InfrastructureFile $file, ScanContext $context, int $line, string $arguments): iterable
    {
        $paths = array_values(array_filter(preg_split('/\s+/', $arguments) ?: [], fn (string $part) => ! str_starts_with($part, '--')));
        array_pop($paths);

        if (! array_intersect($paths, ['.', './', '*'])) {
            return;
        }

        $directory = dirname($file->path) === '.' ? '' : dirname($file->path).'/';
        $candidates = array_unique([$directory.basename($file->path).'.dockerignore', $directory.'.dockerignore', '.dockerignore']);
        $ignore = null;

        foreach ($candidates as $candidate) {
            if (($ignore = $context->read($candidate)) !== null) {
                break;
            }
        }

        if ($ignore === null) {
            yield $this->report($file, $line, 'COPY . copies the whole build context and there is no .dockerignore, so .env, .git and logs can end up in the image.', Severity::Medium,
                'Add a .dockerignore with at least .env, .env.*, .git, node_modules, vendor, storage/logs and storage/framework.');

            return;
        }

        $ignoresEnv = preg_match('/^\s*(\*\*\/)?\.env(\*|\.\*)?\s*$|^\s*\*\s*$/m', $ignore) === 1;

        if (! $ignoresEnv && ($context->exists($directory.'.env') || $context->exists('.env'))) {
            yield $this->report($file, $line, 'COPY . copies .env into the image: .dockerignore does not exclude it.', Severity::High,
                'Add .env and .env.* to .dockerignore and rotate any secrets from images you already pushed.');
        }
    }
}

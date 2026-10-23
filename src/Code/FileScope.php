<?php

namespace Siberfx\RiskAnalyzer\Code;

use PhpParser\Node;
use Siberfx\RiskAnalyzer\Finding;
use Siberfx\RiskAnalyzer\Severity;

/**
 * The file currently being analysed, handed to every code rule.
 */
final class FileScope
{
    /** @var list<string> */
    private array $lines;

    /** @var array<int, list<string>|true>|null */
    private ?array $ignores = null;

    public function __construct(
        public readonly string $path,
        public readonly string $source,
        public readonly Taint $taint,
        /** Line offset when the source is a fragment of a larger file (Blade echoes). */
        private readonly int $lineOffset = 0,
    ) {
        $this->lines = preg_split('/\R/', $source) ?: [];
    }

    public function isConfigFile(): bool
    {
        return str_starts_with($this->path, 'config/');
    }

    public function line(int $line): ?string
    {
        return $this->lines[$line - 1 - $this->lineOffset] ?? null;
    }

    /**
     * Builds a finding located at $node.
     *
     * @param  array<string, mixed>  $meta
     */
    public function finding(
        string $rule,
        Node $node,
        Severity $severity,
        string $message,
        ?string $remediation = null,
        array $meta = [],
    ): Finding {
        $line = $node->getStartLine() + $this->lineOffset;

        return new Finding(
            rule: $rule,
            severity: $severity,
            message: $message,
            file: $this->path,
            line: $line,
            snippet: $this->line($line) ?? null,
            remediation: $remediation,
            meta: $meta,
        );
    }

    /**
     * Inline suppression: a "risk-analyzer-ignore" comment on the same line or the
     * line above, optionally limited to rule ids and followed by a reason:
     *
     *   // risk-analyzer-ignore sql-injection -- table name comes from an enum
     */
    public function isIgnored(string $rule, int $line): bool
    {
        $this->ignores ??= $this->parseIgnores();

        foreach ([$line - $this->lineOffset, $line - $this->lineOffset - 1] as $candidate) {
            $ignore = $this->ignores[$candidate] ?? null;

            if ($ignore === true || (is_array($ignore) && in_array($rule, $ignore, true))) {
                return true;
            }
        }

        return false;
    }

    /**
     * @return array<int, list<string>|true>
     */
    private function parseIgnores(): array
    {
        $ignores = [];

        foreach ($this->lines as $index => $text) {
            if (! preg_match('/risk-analyzer-ignore\b(.*)$/i', $text, $match)) {
                continue;
            }

            $ids = preg_split('/\s*--|\*\/|--}}/', $match[1], 2)[0] ?? '';
            $ids = array_values(array_filter(
                preg_split('/[\s,:]+/', strtolower($ids)) ?: [],
                fn (string $id) => preg_match('/^[a-z0-9]+(-[a-z0-9]+)*$/', $id) === 1,
            ));

            $ignores[$index + 1] = $ids === [] || in_array('all', $ids, true) ? true : $ids;
        }

        return $ignores;
    }
}

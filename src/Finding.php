<?php

namespace Siberfx\RiskAnalyzer;

use JsonSerializable;

final class Finding implements JsonSerializable
{
    public bool $baselined = false;

    /**
     * @param  string  $rule  rule id, e.g. "sql-injection"
     * @param  string|null  $file  path relative to the project root
     * @param  string|null  $snippet  the offending source line, used for the fingerprint
     * @param  array<string, mixed>  $meta
     */
    public function __construct(
        public readonly string $rule,
        public Severity $severity,
        public readonly string $message,
        public readonly ?string $file = null,
        public readonly ?int $line = null,
        public readonly ?string $snippet = null,
        public readonly ?string $remediation = null,
        public readonly array $meta = [],
    ) {}

    /**
     * Stable identity of the finding. Line numbers are left out on purpose
     * so that a baseline survives code moving up or down a file.
     */
    public function fingerprint(): string
    {
        $anchor = $this->snippet !== null
            ? preg_replace('/\s+/', ' ', trim($this->snippet))
            : $this->message;

        return substr(hash('sha256', implode('|', [$this->rule, $this->file ?? '', $anchor])), 0, 16);
    }

    public function location(): ?string
    {
        if ($this->file === null) {
            return null;
        }

        return $this->line !== null ? "{$this->file}:{$this->line}" : $this->file;
    }

    /**
     * @return array<string, mixed>
     */
    public function jsonSerialize(): array
    {
        return [
            'rule' => $this->rule,
            'severity' => $this->severity->value,
            'message' => $this->message,
            'file' => $this->file,
            'line' => $this->line,
            'snippet' => $this->snippet !== null ? trim($this->snippet) : null,
            'remediation' => $this->remediation,
            'fingerprint' => $this->fingerprint(),
            'baselined' => $this->baselined,
            'meta' => $this->meta === [] ? new \stdClass : $this->meta,
        ];
    }
}

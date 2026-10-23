<?php

namespace Siberfx\RiskAnalyzer;

use JsonException;
use RuntimeException;

/**
 * A committed list of accepted findings. Findings whose fingerprint is in
 * the baseline are still reported, but never fail a scan.
 */
final class Baseline
{
    /**
     * @param  array<string, array{rule: string, file: ?string, message: string}>  $entries  keyed by fingerprint
     */
    public function __construct(private array $entries = []) {}

    public static function load(string $path): self
    {
        if (! is_file($path)) {
            return new self;
        }

        try {
            $data = json_decode((string) file_get_contents($path), true, flags: JSON_THROW_ON_ERROR);
        } catch (JsonException $exception) {
            throw new RuntimeException("Baseline {$path} is not valid JSON: {$exception->getMessage()}");
        }

        $entries = [];

        foreach ((array) ($data['findings'] ?? []) as $entry) {
            if (isset($entry['fingerprint'])) {
                $entries[(string) $entry['fingerprint']] = [
                    'rule' => (string) ($entry['rule'] ?? ''),
                    'file' => $entry['file'] ?? null,
                    'message' => (string) ($entry['message'] ?? ''),
                ];
            }
        }

        return new self($entries);
    }

    /**
     * @param  iterable<Finding>  $findings
     */
    public static function fromFindings(iterable $findings): self
    {
        $entries = [];

        foreach ($findings as $finding) {
            $entries[$finding->fingerprint()] = [
                'rule' => $finding->rule,
                'file' => $finding->file,
                'message' => $finding->message,
            ];
        }

        return new self($entries);
    }

    public function contains(Finding $finding): bool
    {
        return isset($this->entries[$finding->fingerprint()]);
    }

    public function count(): int
    {
        return count($this->entries);
    }

    public function save(string $path): void
    {
        ksort($this->entries);

        $findings = [];

        foreach ($this->entries as $fingerprint => $entry) {
            $findings[] = ['fingerprint' => $fingerprint, ...$entry];
        }

        usort($findings, fn (array $a, array $b) => [$a['rule'], $a['file'] ?? ''] <=> [$b['rule'], $b['file'] ?? '']);

        $json = json_encode([
            'tool' => 'siberfx/laravel-risk-analyzer',
            'note' => 'Accepted findings. Regenerate with: php artisan risk-analyzer:baseline',
            'findings' => $findings,
        ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);

        file_put_contents($path, $json.PHP_EOL);
    }
}

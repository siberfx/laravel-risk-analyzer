<?php

namespace Siberfx\RiskAnalyzer;

use Illuminate\Support\Collection;
use JsonSerializable;
use PHPUnit\Framework\Assert;
use Siberfx\RiskAnalyzer\Contracts\Rule;

final class Report implements JsonSerializable
{
    /**
     * @param  list<Finding>  $findings  sorted by severity, then location
     * @param  array<string, Rule>  $rules  rules that ran, by id
     */
    public function __construct(
        public readonly array $findings,
        public readonly array $rules,
        public readonly float $duration,
        public readonly bool $production,
    ) {}

    /**
     * Findings that are not in the baseline.
     *
     * @return Collection<int, Finding>
     */
    public function active(): Collection
    {
        return collect($this->findings)->reject(fn (Finding $finding) => $finding->baselined)->values();
    }

    /**
     * @return Collection<int, Finding>
     */
    public function baselined(): Collection
    {
        return collect($this->findings)->filter(fn (Finding $finding) => $finding->baselined)->values();
    }

    /**
     * Active findings at or above the threshold.
     *
     * @return Collection<int, Finding>
     */
    public function failing(Severity|string $threshold): Collection
    {
        $threshold = Severity::fromLoose($threshold);

        return $this->active()->filter(fn (Finding $finding) => $finding->severity->atLeast($threshold))->values();
    }

    public function passes(Severity|string $threshold): bool
    {
        return $this->failing($threshold)->isEmpty();
    }

    /**
     * @return array<string, int> active findings per severity, highest first
     */
    public function counts(): array
    {
        $counts = array_fill_keys(array_map(fn (Severity $severity) => $severity->value, Severity::ordered()), 0);

        foreach ($this->active() as $finding) {
            $counts[$finding->severity->value]++;
        }

        return $counts;
    }

    public function rule(string $id): ?Rule
    {
        return $this->rules[$id] ?? null;
    }

    /**
     * Test helper: fail when active findings at or above $threshold exist
     * (optionally only for one rule).
     */
    public function assertClean(Severity|string $threshold = Severity::Low, ?string $rule = null): self
    {
        $failing = $this->failing($threshold)
            ->when($rule !== null, fn (Collection $findings) => $findings->where('rule', $rule))
            ->map(fn (Finding $finding) => sprintf('[%s] %s %s %s', $finding->severity->value, $finding->rule, $finding->location() ?? '', $finding->message));

        Assert::assertTrue($failing->isEmpty(), "Risk Analyzer found security issues:\n".$failing->implode("\n"));

        return $this;
    }

    /**
     * @return array<string, mixed>
     */
    public function jsonSerialize(): array
    {
        return [
            'tool' => 'siberfx/laravel-risk-analyzer',
            'production' => $this->production,
            'duration' => round($this->duration, 3),
            'summary' => [
                ...$this->counts(),
                'baselined' => $this->baselined()->count(),
                'rules' => count($this->rules),
            ],
            'findings' => $this->findings,
        ];
    }
}

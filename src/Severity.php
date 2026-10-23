<?php

namespace Siberfx\RiskAnalyzer;

enum Severity: string
{
    case Critical = 'critical';
    case High = 'high';
    case Medium = 'medium';
    case Low = 'low';
    case Info = 'info';

    public function weight(): int
    {
        return match ($this) {
            self::Critical => 5,
            self::High => 4,
            self::Medium => 3,
            self::Low => 2,
            self::Info => 1,
        };
    }

    public function atLeast(self $threshold): bool
    {
        return $this->weight() >= $threshold->weight();
    }

    /**
     * SARIF result level.
     */
    public function sarifLevel(): string
    {
        return match ($this) {
            self::Critical, self::High => 'error',
            self::Medium => 'warning',
            self::Low, self::Info => 'note',
        };
    }

    /**
     * GitHub code scanning "security-severity" score (0.0 - 10.0).
     */
    public function securityScore(): string
    {
        return match ($this) {
            self::Critical => '9.5',
            self::High => '8.0',
            self::Medium => '5.5',
            self::Low => '3.0',
            self::Info => '0.0',
        };
    }

    public function color(): string
    {
        return match ($this) {
            self::Critical => 'magenta',
            self::High => 'red',
            self::Medium => 'yellow',
            self::Low => 'cyan',
            self::Info => 'gray',
        };
    }

    /**
     * @return list<self> highest first
     */
    public static function ordered(): array
    {
        return [self::Critical, self::High, self::Medium, self::Low, self::Info];
    }

    public static function fromLoose(self|string $value): self
    {
        if ($value instanceof self) {
            return $value;
        }

        return self::tryFrom(strtolower(trim($value)))
            ?? throw new \InvalidArgumentException("Unknown severity [{$value}]. Use one of: critical, high, medium, low, info.");
    }
}

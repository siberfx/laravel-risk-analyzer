<?php

namespace Siberfx\RiskAnalyzer\Rules\Dependencies;

use Illuminate\Support\Carbon;
use Siberfx\RiskAnalyzer\Category;
use Siberfx\RiskAnalyzer\Finding;
use Siberfx\RiskAnalyzer\Rules\AbstractProjectRule;
use Siberfx\RiskAnalyzer\ScanContext;
use Siberfx\RiskAnalyzer\Severity;

final class UnsupportedRuntime extends AbstractProjectRule
{
    /** Last day of security support. */
    public const array PHP = [
        '8.0' => '2023-11-26', '8.1' => '2025-12-31', '8.2' => '2026-12-31',
        '8.3' => '2027-12-31', '8.4' => '2028-12-31', '8.5' => '2029-12-31',
    ];

    public const array LARAVEL = [
        '9' => '2024-02-06', '10' => '2025-02-04', '11' => '2026-03-12', '12' => '2027-02-24', '13' => '2028-03-17',
    ];

    public function id(): string
    {
        return 'unsupported-runtime';
    }

    public function title(): string
    {
        return 'Unsupported PHP or Laravel';
    }

    public function description(): string
    {
        return 'PHP and Laravel versions past their security-support date (or within 90 days of it), which no longer get security patches.';
    }

    public function category(): Category
    {
        return Category::Dependencies;
    }

    public function severity(): Severity
    {
        return Severity::High;
    }

    public function run(ScanContext $context): iterable
    {
        $php = PHP_MAJOR_VERSION.'.'.PHP_MINOR_VERSION;
        $laravel = explode('.', $context->app->version())[0];

        yield from $this->check("PHP {$php}", self::PHP[$php] ?? null, 'php');
        yield from $this->check("Laravel {$laravel}", self::LARAVEL[$laravel] ?? null, 'laravel');
    }

    /**
     * @return iterable<Finding>
     */
    private function check(string $label, ?string $endOfSupport, string $anchor): iterable
    {
        if ($endOfSupport === null) {
            return;
        }

        $end = Carbon::parse($endOfSupport)->endOfDay();
        $now = Carbon::now();

        if ($now->greaterThan($end)) {
            yield $this->finding("{$label} stopped receiving security fixes on {$endOfSupport}.", null,
                'Upgrade to a supported release.', anchor: $anchor.'.eol');
        } elseif ($now->diffInDays($end) <= 90) {
            yield $this->finding("{$label} stops receiving security fixes on {$endOfSupport}.", Severity::Low,
                'Plan the upgrade now.', anchor: $anchor.'.eol-soon');
        }
    }
}

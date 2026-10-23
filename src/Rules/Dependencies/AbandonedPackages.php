<?php

namespace Siberfx\RiskAnalyzer\Rules\Dependencies;

use Siberfx\RiskAnalyzer\Category;
use Siberfx\RiskAnalyzer\Rules\AbstractProjectRule;
use Siberfx\RiskAnalyzer\ScanContext;
use Siberfx\RiskAnalyzer\Severity;
use Siberfx\RiskAnalyzer\Support\Lockfiles;

final class AbandonedPackages extends AbstractProjectRule
{
    public function id(): string
    {
        return 'abandoned-package';
    }

    public function title(): string
    {
        return 'Abandoned packages';
    }

    public function description(): string
    {
        return 'Composer packages their maintainers marked as abandoned, which no longer receive security fixes. Read from composer.lock, no network needed.';
    }

    public function category(): Category
    {
        return Category::Dependencies;
    }

    public function severity(): Severity
    {
        return Severity::Low;
    }

    public function run(ScanContext $context): iterable
    {
        foreach (Lockfiles::composer($context) as $package) {
            if ($package['abandoned'] === false) {
                continue;
            }

            $replacement = is_string($package['abandoned']) ? $package['abandoned'] : null;

            yield $this->finding(
                "{$package['name']} is abandoned".($replacement ? ", use {$replacement} instead." : '.'),
                null,
                $replacement ? "composer remove {$package['name']} && composer require {$replacement}" : 'Find a maintained alternative or fork it.',
                'composer.lock',
                anchor: $package['name'],
                meta: ['package' => $package['name'], 'replacement' => $replacement],
            );
        }
    }
}

<?php

namespace Siberfx\RiskAnalyzer\Support;

use Illuminate\Container\Container;

/**
 * The container behind standalone scans. It answers the few application
 * questions Laravel's console commands ask, without claiming to be a Laravel
 * application (so RiskAnalyzer::isLaravel() stays false).
 */
final class StandaloneContainer extends Container
{
    public function runningUnitTests(): bool
    {
        return false;
    }

    public function runningInConsole(): bool
    {
        return PHP_SAPI === 'cli' || PHP_SAPI === 'phpdbg';
    }
}

<?php

namespace Siberfx\RiskAnalyzer\Rules\Frontend;

use Siberfx\RiskAnalyzer\Frontend\FrontendSource;
use Siberfx\RiskAnalyzer\Severity;

final class FrontendDebug extends AbstractFrontendRule
{
    public function id(): string
    {
        return 'frontend-debug';
    }

    public function title(): string
    {
        return 'Debug code left in frontend code';
    }

    public function description(): string
    {
        return 'debugger statements (medium) and console.log/debug/trace/dir/table calls (low, one finding per file), which can print tokens, user data or API responses in visitors\' browser consoles.';
    }

    public function severity(): Severity
    {
        return Severity::Medium;
    }

    protected function inspect(FrontendSource $file): iterable
    {
        foreach ($file->matches('/(?<![\w$.\'"`])debugger\s*(;|$)/m') as $match) {
            yield $this->report($file, $match['line'], 'debugger statement left in.', null,
                'Remove it; esbuild/terser can also drop it in production builds (esbuild.drop: [\'debugger\'] in vite.config).');
        }

        $calls = [];

        foreach ($file->matches('/(?<![\w$.])console\s*\.\s*(log|debug|trace|dir|table)\s*\(/') as $match) {
            if (! $file->isIgnored($this->id(), $match['line'])) {
                $calls[] = $match['line'];
            }
        }

        if ($calls !== []) {
            // One finding per file, anchored on the file so baselines survive edits.
            yield $this->finding(
                count($calls) === 1
                    ? "console call left in on line {$calls[0]}."
                    : count($calls).' console calls left in (lines '.implode(', ', array_slice($calls, 0, 8)).(count($calls) > 8 ? ', …' : '').').',
                Severity::Low,
                'Remove them, or drop them from production builds (esbuild.drop: [\'console\'] or pure: [\'console.log\'] in vite.config).',
                $file->path,
                $calls[0],
                'console',
            );
        }
    }
}

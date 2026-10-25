<?php

namespace Siberfx\RiskAnalyzer\Rules\Frontend;

use Siberfx\RiskAnalyzer\Frontend\FrontendSource;
use Siberfx\RiskAnalyzer\Severity;

final class FrontendCodeExecution extends AbstractFrontendRule
{
    public function id(): string
    {
        return 'frontend-code-execution';
    }

    public function title(): string
    {
        return 'Dynamic code execution in frontend code';
    }

    public function description(): string
    {
        return 'eval(), new Function() and setTimeout/setInterval with a string, which run text as JavaScript. High when URL, route or message input is visible in the call, medium otherwise. They also force a Content-Security-Policy to allow \'unsafe-eval\'.';
    }

    public function severity(): Severity
    {
        return Severity::High;
    }

    protected function inspect(FrontendSource $file): iterable
    {
        $patterns = [
            '/(?<![\w$.])eval\s*\((?<args>[^\n]*)/' => 'eval()',
            '/(?<![\w$.])new\s+Function\s*\((?<args>[^\n]*)/' => 'new Function()',
            '/(?<![\w$.])(?:window\s*\.\s*)?(?<fn>setTimeout|setInterval)\s*\(\s*(?<args>[\'"`][^\n]*)/' => 'string timer',
        ];

        foreach ($patterns as $pattern => $call) {
            foreach ($file->matches($pattern) as $match) {
                $args = $match['groups']['args'];
                $name = $call === 'string timer' ? $match['groups']['fn'].'() with a string' : $call;
                $tainted = $file->hasInput($args);

                yield $this->report($file, $match['line'], $tainted
                    ? "URL or route input reaches {$name}, which runs it as code."
                    : "{$name} runs a string as code.", $tainted ? Severity::High : Severity::Medium,
                    $call === 'string timer'
                        ? 'Pass a function instead of a string: setTimeout(() => doWork(), 100).'
                        : 'Use JSON.parse() for data, or a lookup table of functions instead of building code from strings.');
            }
        }
    }
}

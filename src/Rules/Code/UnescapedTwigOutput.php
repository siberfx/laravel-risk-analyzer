<?php

namespace Siberfx\RiskAnalyzer\Rules\Code;

use Siberfx\RiskAnalyzer\Category;
use Siberfx\RiskAnalyzer\Code\FileScope;
use Siberfx\RiskAnalyzer\Code\Taint;
use Siberfx\RiskAnalyzer\Contracts\ProjectRule;
use Siberfx\RiskAnalyzer\Finding;
use Siberfx\RiskAnalyzer\ScanContext;
use Siberfx\RiskAnalyzer\Severity;

final class UnescapedTwigOutput implements ProjectRule
{
    /** Request data reachable from a Twig template: Symfony's app.request, TwigBridge's request()/old()/input_get() in Laravel. */
    private const string REQUEST = '/\bapp\.request\.(query|request|attributes|cookies|headers|get|getContent|content|server)\b|\bapp\.request\.(get|query)\s*\(|(?<![\w.])(request|old|input_get|input_old)\s*\(\s*[\'"]|(?<![\w.])request\s*\(\s*\)\s*\.\s*(input|query|get|all|post|cookie|header)\b/';

    public function id(): string
    {
        return 'xss-twig';
    }

    public function title(): string
    {
        return 'Unescaped Twig output';
    }

    public function description(): string
    {
        return 'Twig {{ ...|raw }} output and {% autoescape false %} blocks, in Symfony templates and Laravel apps using TwigBridge. Request data (app.request.query, request(\'q\'), request().input(), old()...) printed raw is high; other raw output is low so you can review what reaches it.';
    }

    public function category(): Category
    {
        return Category::Code;
    }

    public function severity(): Severity
    {
        return Severity::High;
    }

    public function run(ScanContext $context): iterable
    {
        foreach ($context->files(['.twig']) as $path) {
            $source = $context->read($path);

            if ($source === null || (! str_contains($source, 'raw') && ! str_contains($source, 'autoescape'))) {
                continue;
            }

            $file = new FileScope($path, $source, new Taint);

            preg_match_all('/\{\{-?\s*(.+?)\s*-?\}\}/s', $source, $echoes, PREG_SET_ORDER | PREG_OFFSET_CAPTURE);

            foreach ($echoes as $echo) {
                if (! preg_match('/\|\s*raw\b/', $echo[1][0])) {
                    continue;
                }

                $line = substr_count($source, "\n", 0, $echo[0][1]) + 1;
                $tainted = preg_match(self::REQUEST, $echo[1][0]) === 1;

                yield from $this->finding($file, $line, $tainted ? Severity::High : Severity::Low, $tainted
                    ? 'Request data is printed without escaping: {{ '.$echo[1][0].' }}'
                    : 'Raw output {{ '.$echo[1][0].' }} is not escaped; make sure the value is trusted or sanitised HTML.');
            }

            preg_match_all('/\{%-?\s*autoescape\s+false\s*-?%\}/', $source, $blocks, PREG_OFFSET_CAPTURE);

            foreach ($blocks[0] as [, $offset]) {
                yield from $this->finding($file, substr_count($source, "\n", 0, $offset) + 1, Severity::Medium,
                    'autoescape is turned off, so everything printed in this block is raw HTML.');
            }
        }
    }

    /**
     * @return iterable<Finding>
     */
    private function finding(FileScope $file, int $line, Severity $severity, string $message): iterable
    {
        if ($file->isIgnored($this->id(), $line)) {
            return;
        }

        yield new Finding(
            rule: $this->id(),
            severity: $severity,
            message: $message,
            file: $file->path,
            line: $line,
            snippet: $file->line($line),
            remediation: 'Let Twig escape the value (drop |raw). For user-authored HTML, sanitise it first (e.g. symfony/html-sanitizer with |sanitize_html) and print the result.',
        );
    }
}

<?php

namespace Siberfx\RiskAnalyzer\Rules\Code;

use PhpParser\Error;
use PhpParser\Node;
use PhpParser\Node\Stmt;
use PhpParser\Parser;
use PhpParser\ParserFactory;
use Siberfx\RiskAnalyzer\Category;
use Siberfx\RiskAnalyzer\Code\Ast;
use Siberfx\RiskAnalyzer\Code\FileScope;
use Siberfx\RiskAnalyzer\Code\Taint;
use Siberfx\RiskAnalyzer\Contracts\ProjectRule;
use Siberfx\RiskAnalyzer\Finding;
use Siberfx\RiskAnalyzer\ScanContext;
use Siberfx\RiskAnalyzer\Severity;

final class UnescapedBladeOutput implements ProjectRule
{
    /** Helpers that return HtmlString or framework-generated markup. */
    private const array SAFE_FUNCTIONS = ['csrf_field', 'method_field', 'vite', 'json_encode', 'svg', 'nl2br_e', 'e'];

    private const array SAFE_VARIABLES = ['slot', 'attributes', '__env', 'header', 'footer', 'icon'];

    private ?Parser $parser = null;

    public function id(): string
    {
        return 'xss-blade';
    }

    public function title(): string
    {
        return 'Unescaped Blade output';
    }

    public function description(): string
    {
        return 'Blade {!! !!} echoes. Request input (request(), old(), $request->...) printed raw is reported as high; other raw echoes are reported as low so you can review what reaches them.';
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
        foreach ($context->files(['.blade.php']) as $path) {
            $source = $context->read($path);

            if ($source === null || ! str_contains($source, '{!!')) {
                continue;
            }

            $file = new FileScope($path, $source, new Taint);

            preg_match_all('/(?<!@)\{!!\s*(.+?)\s*!!\}/s', $source, $matches, PREG_SET_ORDER | PREG_OFFSET_CAPTURE);

            foreach ($matches as $match) {
                $line = substr_count($source, "\n", 0, $match[0][1]) + 1;

                if ($file->isIgnored($this->id(), $line)) {
                    continue;
                }

                $finding = $this->inspectEcho($match[1][0], $file, $path, $line);

                if ($finding !== null) {
                    yield $finding;
                }
            }
        }
    }

    private function inspectEcho(string $expression, FileScope $file, string $path, int $line): ?Finding
    {
        $parsed = $this->parse($expression);

        if ($parsed !== null && $this->isSafe($parsed)) {
            return null;
        }

        $tainted = $parsed !== null && $file->taint->isTainted($parsed);

        return new Finding(
            rule: $this->id(),
            severity: $tainted ? Severity::High : Severity::Low,
            message: $tainted
                ? 'Request input is printed without escaping: {!! '.$expression.' !!}'
                : 'Raw output {!! '.$expression.' !!} is not escaped; make sure the value is trusted or sanitised HTML.',
            file: $path,
            line: $line,
            snippet: $file->line($line),
            remediation: 'Use {{ }} to escape. For user-authored HTML, sanitise it first (e.g. with an HTML purifier) and print the sanitised result.',
        );
    }

    private function isSafe(Node $node): bool
    {
        return match (true) {
            $node instanceof Node\Scalar => true,
            $node instanceof Node\Expr\ConstFetch, $node instanceof Node\Expr\ClassConstFetch => true,
            $node instanceof Node\Expr\FuncCall => (in_array(Ast::functionName($node), [...self::SAFE_FUNCTIONS, '__', 'trans', 'trans_choice'], true)
                && ! $this->hasTaintedArgs($node))
                // nl2br(e($text)), strip_tags(...): formatting applied to escaped text.
                || (in_array(Ast::functionName($node), ['nl2br', 'strtoupper', 'strtolower', 'ucfirst', 'trim'], true)
                    && ($first = Ast::arg($node, 0)) !== null && $this->isSafe($first)),
            $node instanceof Node\Expr\StaticCall => in_array(Ast::className($node), ['Js', 'Vite', 'Blade'], true),
            $node instanceof Node\Expr\Variable => in_array($node->name, self::SAFE_VARIABLES, true),
            $node instanceof Node\Expr\MethodCall, $node instanceof Node\Expr\PropertyFetch => $this->isSafe(Ast::chainRoot($node))
                && Ast::chainRoot($node) instanceof Node\Expr\Variable,
            default => false,
        };
    }

    private function hasTaintedArgs(Node\Expr\FuncCall $node): bool
    {
        return array_any($node->getArgs(), fn (Node\Arg $arg) => (new Taint)->isTainted($arg->value));
    }

    private function parse(string $expression): ?Node\Expr
    {
        $this->parser ??= (new ParserFactory)->createForHostVersion();

        try {
            $statements = $this->parser->parse('<?php '.$expression.';') ?? [];
        } catch (Error) {
            return null;
        }

        $first = $statements[0] ?? null;

        return $first instanceof Stmt\Expression ? $first->expr : null;
    }
}

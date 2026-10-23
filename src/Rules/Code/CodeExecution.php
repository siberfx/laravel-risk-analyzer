<?php

namespace Siberfx\RiskAnalyzer\Rules\Code;

use PhpParser\Node;
use PhpParser\Node\Expr;
use Siberfx\RiskAnalyzer\Code\Ast;
use Siberfx\RiskAnalyzer\Code\FileScope;
use Siberfx\RiskAnalyzer\Severity;

final class CodeExecution extends AbstractCodeRule
{
    public function id(): string
    {
        return 'code-execution';
    }

    public function title(): string
    {
        return 'Dynamic code execution';
    }

    public function description(): string
    {
        return 'eval(), assert() with a string, create_function(), include/require of a runtime path and calls through a user-chosen function name.';
    }

    public function severity(): Severity
    {
        return Severity::Critical;
    }

    public function inspect(Node $node, FileScope $file): iterable
    {
        if ($node instanceof Expr\Eval_) {
            $severity = $this->sinkSeverity($file, $node->expr, Severity::High);

            if ($severity !== null) {
                yield $this->report($file, $node, 'eval() executes a runtime string as PHP code.', $severity,
                    'Remove eval(). Use a lookup table, a strategy class or a template engine instead.');
            }

            return;
        }

        if ($node instanceof Expr\Include_ && $file->taint->isTainted($node->expr)) {
            yield $this->report($file, $node, 'Request input decides which file is included and executed.', null,
                'Map the input to a fixed list of files instead of building the path from it.');

            return;
        }

        $function = Ast::functionName($node);

        if ($function === 'create_function') {
            yield $this->report($file, $node, 'create_function() evaluates a string as PHP code.', Severity::High,
                'Use a closure instead.');

            return;
        }

        // $fn($arg) / call_user_func($request->input('callback'))
        $callable = match (true) {
            $node instanceof Expr\FuncCall && ! $node->name instanceof Node\Name => $node->name,
            in_array($function, ['call_user_func', 'call_user_func_array', 'array_map'], true) => Ast::arg($node, 0),
            in_array($function, ['usort', 'uasort', 'uksort', 'array_filter', 'array_walk'], true) => Ast::arg($node, 1),
            default => null,
        };

        if ($callable instanceof Expr && $file->taint->isTainted($callable)) {
            yield $this->report($file, $node, 'Request input chooses the function that gets called.', Severity::High,
                'Resolve the input through an allow-list of callables.');
        }
    }
}

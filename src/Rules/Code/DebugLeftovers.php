<?php

namespace Siberfx\RiskAnalyzer\Rules\Code;

use PhpParser\Node;
use PhpParser\Node\Expr;
use Siberfx\RiskAnalyzer\Code\Ast;
use Siberfx\RiskAnalyzer\Code\FileScope;
use Siberfx\RiskAnalyzer\Severity;

final class DebugLeftovers extends AbstractCodeRule
{
    private const array FUNCTIONS = ['dd', 'dump', 'ddd', 'ray', 'var_dump', 'debug_zval_dump', 'xdebug_break', 'debug_print_backtrace'];

    public function id(): string
    {
        return 'debug-leftover';
    }

    public function title(): string
    {
        return 'Debug code left in';
    }

    public function description(): string
    {
        return 'dd(), dump(), ray(), var_dump(), ->dd()/->dump() on queries and collections, print_r()/var_export() that echo, and phpinfo(), which leak internals when they reach production.';
    }

    public function severity(): Severity
    {
        return Severity::High;
    }

    public function inspect(Node $node, FileScope $file): iterable
    {
        $function = Ast::functionName($node);

        $finding = match (true) {
            $function === 'phpinfo' => ['phpinfo() exposes the full server configuration.', Severity::High],
            in_array($function, self::FUNCTIONS, true) => ["{$function}() left in application code.", Severity::Low],
            in_array($function, ['print_r', 'var_export'], true) && $node instanceof Expr\FuncCall && ! $this->returnsOutput($node) => ["{$function}() echoes its output.", Severity::Low],
            ($node instanceof Expr\MethodCall || $node instanceof Expr\NullsafeMethodCall)
                && in_array(Ast::methodName($node), ['dd', 'dump', 'ddrawsql', 'dumprawsql'], true) && $node->getArgs() === [] => ['->'.Ast::methodName($node).'() left in application code.', Severity::Low],
            default => null,
        };

        if ($finding !== null) {
            yield $this->report($file, $node, $finding[0], $finding[1], 'Remove it, or log through Log::debug() instead.');
        }
    }

    private function returnsOutput(Expr\FuncCall $node): bool
    {
        $return = Ast::arg($node, 1, 'return');

        return $return instanceof Expr\ConstFetch && strtolower($return->name->toString()) === 'true';
    }
}

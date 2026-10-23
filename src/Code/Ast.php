<?php

namespace Siberfx\RiskAnalyzer\Code;

use PhpParser\Node;
use PhpParser\Node\Expr;
use PhpParser\Node\Identifier;
use PhpParser\Node\Name;

/**
 * Small helpers for matching calls in the AST.
 */
final class Ast
{
    /**
     * Lower-cased function name of a call, or null for dynamic calls ($fn()).
     */
    public static function functionName(Node $node): ?string
    {
        if ($node instanceof Expr\FuncCall && $node->name instanceof Name) {
            return strtolower($node->name->getLast());
        }

        return null;
    }

    /**
     * Lower-cased method name of a method, nullsafe or static call.
     */
    public static function methodName(Node $node): ?string
    {
        if (($node instanceof Expr\MethodCall || $node instanceof Expr\NullsafeMethodCall || $node instanceof Expr\StaticCall)
            && $node->name instanceof Identifier) {
            return strtolower($node->name->toString());
        }

        return null;
    }

    /**
     * Short class name of a static call / class constant / new, e.g. "DB" for
     * both DB::raw() and \Illuminate\Support\Facades\DB::raw().
     */
    public static function className(Node $node): ?string
    {
        $class = match (true) {
            $node instanceof Expr\StaticCall, $node instanceof Expr\ClassConstFetch, $node instanceof Expr\New_ => $node->class,
            default => null,
        };

        return $class instanceof Name ? $class->getLast() : null;
    }

    /**
     * Walks a fluent chain ($a->b()->c()) down to its first link and returns
     * the class of the static call it starts with, if any:
     * Http::withHeaders([...])->get($url) gives "Http".
     */
    public static function chainRootClass(Node $node): ?string
    {
        $root = self::chainRoot($node);

        return $root instanceof Expr\StaticCall ? self::className($root) : null;
    }

    public static function chainRoot(Node $node): Node
    {
        while ($node instanceof Expr\MethodCall || $node instanceof Expr\NullsafeMethodCall
            || $node instanceof Expr\PropertyFetch || $node instanceof Expr\NullsafePropertyFetch) {
            $node = $node->var;
        }

        return $node;
    }

    /**
     * Whether the chain contains a call to one of $methods (lower-case).
     *
     * @param  list<string>  $methods
     */
    public static function chainHasMethod(Node $node, array $methods): bool
    {
        while ($node instanceof Expr\MethodCall || $node instanceof Expr\NullsafeMethodCall || $node instanceof Expr\StaticCall) {
            if (in_array(self::methodName($node), $methods, true)) {
                return true;
            }

            if ($node instanceof Expr\StaticCall) {
                return false;
            }

            $node = $node->var;
        }

        return false;
    }

    /**
     * Positional or named argument value.
     */
    public static function arg(Node $call, int $position, ?string $name = null): ?Expr
    {
        if (! $call instanceof Expr\CallLike || $call->isFirstClassCallable()) {
            return null;
        }

        $positional = 0;

        foreach ($call->getArgs() as $arg) {
            if ($arg->unpack) {
                return null;
            }

            if ($arg->name !== null) {
                if ($name !== null && $arg->name->toString() === $name) {
                    return $arg->value;
                }

                continue;
            }

            if ($positional === $position) {
                return $arg->value;
            }

            $positional++;
        }

        return null;
    }

    /**
     * Name of the variable, property or array key an expression is stored in:
     * "$token = ...", "$this->token = ...", "['token' => ...]".
     */
    public static function targetName(Node $node): ?string
    {
        return match (true) {
            $node instanceof Expr\Variable && is_string($node->name) => $node->name,
            $node instanceof Expr\PropertyFetch && $node->name instanceof Identifier => $node->name->toString(),
            $node instanceof Expr\StaticPropertyFetch && $node->name instanceof Node\VarLikeIdentifier => $node->name->toString(),
            $node instanceof Expr\ArrayDimFetch && $node->dim instanceof Node\Scalar\String_ => $node->dim->value,
            $node instanceof Node\ArrayItem && $node->key instanceof Node\Scalar\String_ => $node->key->value,
            $node instanceof Node\Arg && $node->name !== null => $node->name->toString(),
            default => null,
        };
    }

    public static function isFalse(?Node $node): bool
    {
        return ($node instanceof Expr\ConstFetch && strtolower($node->name->toString()) === 'false')
            || ($node instanceof Node\Scalar\Int_ && $node->value === 0);
    }

    public static function isConst(?Node $node, string $name): bool
    {
        return $node instanceof Expr\ConstFetch && strtoupper($node->name->getLast()) === $name;
    }

    /**
     * Whether $node uses the constant $name anywhere (e.g. inside a bitmask).
     */
    public static function usesConst(Node $node, string $name): bool
    {
        if (self::isConst($node, $name)) {
            return true;
        }

        if ($node instanceof Expr\BinaryOp) {
            return self::usesConst($node->left, $name) || self::usesConst($node->right, $name);
        }

        return false;
    }

    /**
     * Calls one of $functions anywhere below $node.
     *
     * @param  list<string>  $functions
     */
    public static function containsCall(Node $node, array $functions): bool
    {
        if (in_array(self::functionName($node), $functions, true)) {
            return true;
        }

        foreach ($node->getSubNodeNames() as $name) {
            $child = $node->{$name};

            foreach (is_array($child) ? $child : [$child] as $item) {
                if ($item instanceof Node && ! $item instanceof Node\FunctionLike && self::containsCall($item, $functions)) {
                    return true;
                }
            }
        }

        return false;
    }
}

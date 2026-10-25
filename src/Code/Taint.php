<?php

namespace Siberfx\RiskAnalyzer\Code;

use PhpParser\Node;
use PhpParser\Node\Expr;
use PhpParser\Node\Name;
use PhpParser\Node\Scalar;
use PhpParser\PrettyPrinter\Standard;

/**
 * Intra-procedural taint tracking.
 *
 * Follows user-controlled values (request input, superglobals, uploaded
 * file names...) through local variables inside a function body, so rules
 * can tell "user input reaches this sink" apart from "this sink receives a
 * value built at runtime" and from "this sink receives a literal".
 */
final class Taint
{
    private const array SUPERGLOBALS = ['_GET', '_POST', '_REQUEST', '_COOKIE', '_FILES', '_SERVER'];

    /** Request methods that hand back raw user input. */
    private const array SOURCE_METHODS = [
        'all', 'collect', 'cookie', 'except', 'fullurl', 'fullurlwithquery', 'get', 'getcontent', 'getpayload',
        'getrequesturi', 'header', 'input', 'json', 'keys', 'only', 'path', 'post', 'query', 'route', 'safe',
        'segment', 'segments', 'server', 'str', 'string', 'url', 'useragent', 'validated', 'host', 'gethost',
        // Symfony and Yii2
        'toarray', 'getbodyparam', 'getbodyparams', 'getqueryparam', 'getqueryparams', 'getrawbody', 'geturl', 'getheaders', 'getcookies',
    ];

    /** Methods that hand back user input whatever object they are called on. */
    private const array UNIVERSAL_SOURCE_METHODS = [
        'getclientoriginalname', 'getclientoriginalextension', 'getclientmimetype', 'getclientoriginalpath',
    ];

    /** Functions whose return value is safe whatever goes in. */
    private const array SANITIZERS = [
        'intval', 'floatval', 'boolval', 'abs', 'count', 'strlen', 'mb_strlen', 'is_numeric', 'is_int', 'is_string',
        'is_array', 'is_null', 'isset', 'empty', 'in_array', 'array_key_exists', 'ctype_digit', 'ctype_alnum',
        'ctype_alpha', 'escapeshellarg', 'escapeshellcmd', 'basename', 'e', 'htmlspecialchars', 'htmlentities',
        'strip_tags', 'md5', 'sha1', 'hash', 'hash_hmac', 'crc32', 'password_hash', 'password_verify', 'uniqid',
        'filter_var', 'urlencode', 'rawurlencode', 'bin2hex', 'base64_encode', 'json_encode', 'preg_match',
        'str_contains', 'str_starts_with', 'str_ends_with', 'max', 'min', 'round', 'floor', 'ceil', 'now', 'today',
        'csrf_token', 'route', 'url', 'asset', 'config', 'env', 'app', 'auth', 'trans', '__',
    ];

    /** Fluent methods that end a tainted chain with a safe value. */
    private const array SANITIZING_METHODS = [
        'tointeger', 'tofloat', 'toboolean', 'isempty', 'isnotempty', 'length', 'count', 'has', 'filled',
        'boolean', 'integer', 'float', 'date', 'enum', 'exists', 'missing', 'ismethod', 'is', 'contains',
        'startswith', 'endswith', 'hash', 'ip', 'user', 'method', 'wantsjson', 'ajax', 'expectsjson', 'issecure',
    ];

    /**
     * @var list<array{tainted: array<string, true>, requests: array<string, true>, literal: array<string, true>, validated: array<string, true>}>
     */
    private array $scopes = [];

    private ?Standard $printer = null;

    public function __construct()
    {
        $this->reset();
    }

    public function reset(): void
    {
        $this->scopes = [$this->emptyScope(['request' => true])];
    }

    public function enterFunction(Node\FunctionLike $function): void
    {
        $parent = end($this->scopes) ?: $this->emptyScope();

        // Closures and arrow functions see the variables of the enclosing scope.
        $scope = $function instanceof Expr\Closure || $function instanceof Expr\ArrowFunction
            ? $parent
            : $this->emptyScope();

        foreach ($function->getParams() as $param) {
            if (! $param->var instanceof Expr\Variable || ! is_string($param->var->name)) {
                continue;
            }

            $name = $param->var->name;

            if ($name === 'request' || $this->isRequestType($param->type)) {
                $scope['requests'][$name] = true;
            }
        }

        $this->scopes[] = $scope;
    }

    public function leaveFunction(): void
    {
        if (count($this->scopes) > 1) {
            array_pop($this->scopes);
        }
    }

    /**
     * Called before the children of $node are visited: taints foreach keys
     * and values of a tainted iterable, and treats $x as allow-listed inside
     * "if (in_array($x, [...])) { ... }".
     */
    public function enter(Node $node): void
    {
        if ($node instanceof Node\Stmt\Foreach_ && $this->isTainted($node->expr)) {
            foreach ([$node->keyVar, $node->valueVar] as $target) {
                if ($target !== null) {
                    $this->markTargets($target, tainted: true);
                }
            }
        }

        if ($node instanceof Node\Stmt\If_ && ($name = $this->guardedVariable($node->cond)) !== null) {
            $this->scopes[$this->current()]['validated'][$name] = true;
        }
    }

    /**
     * Called once the children of $node have been visited: records what an
     * assignment does (sinks inside the right-hand side still saw the old
     * state), and treats $x as allow-listed after
     * "if (! in_array($x, [...])) { abort/return/reassign }".
     */
    public function leave(Node $node): void
    {
        if ($node instanceof Expr\Assign || $node instanceof Expr\AssignRef) {
            $this->assign($node->var, $node->expr, append: false);
        } elseif ($node instanceof Expr\AssignOp) {
            $this->assign($node->var, $node->expr, append: true);
        }

        if (! $node instanceof Node\Stmt\If_) {
            return;
        }

        if ($this->guardedVariable($node->cond) !== null) {
            unset($this->scopes[$this->current()]['validated'][$this->guardedVariable($node->cond)]);
        } elseif ($node->cond instanceof Expr\BooleanNot && ($name = $this->guardedVariable($node->cond->expr)) !== null) {
            $this->scopes[$this->current()]['validated'][$name] = true;
        }
    }

    /**
     * Whether the value can carry user-controlled data.
     */
    public function isTainted(?Node $node): bool
    {
        return match (true) {
            $node === null => false,
            $node instanceof Expr\Variable => is_string($node->name)
                && (in_array($node->name, self::SUPERGLOBALS, true) || $this->scopeHas('tainted', $node->name)),
            $node instanceof Expr\ArrayDimFetch => $this->taintedDimFetch($node),
            $node instanceof Expr\PropertyFetch, $node instanceof Expr\NullsafePropertyFetch => $this->isRequest($node->var) || $this->isTainted($node->var),
            $node instanceof Expr\FuncCall => $this->taintedFuncCall($node),
            $node instanceof Expr\MethodCall, $node instanceof Expr\NullsafeMethodCall => $this->taintedMethodCall($node),
            $node instanceof Expr\StaticCall => $this->taintedStaticCall($node),
            $node instanceof Expr\Cast\Int_, $node instanceof Expr\Cast\Double, $node instanceof Expr\Cast\Bool_ => false,
            $node instanceof Expr\Cast => $this->isTainted($node->expr),
            $node instanceof Expr\BinaryOp\Concat, $node instanceof Expr\BinaryOp\Coalesce => $this->isTainted($node->left) || $this->isTainted($node->right),
            $node instanceof Expr\BinaryOp => false,
            $node instanceof Expr\Ternary => ($this->isAllowListed($node) ? false : $this->isTainted($node->if ?? $node->cond)) || $this->isTainted($node->else),
            $node instanceof Expr\Match_ => $this->anyTainted(array_map(fn (Node\MatchArm $arm) => $arm->body, $node->arms)),
            $node instanceof Scalar\InterpolatedString => $this->anyTainted($node->parts),
            $node instanceof Expr\Array_ => $this->anyTainted(array_map(fn (?Node\ArrayItem $item) => $item?->value, $node->items)),
            $node instanceof Expr\Assign => $this->isTainted($node->expr),
            $node instanceof Expr\ErrorSuppress => $this->isTainted($node->expr),
            default => false,
        };
    }

    /**
     * Whether the value went through Laravel validation ($request->validated(),
     * $request->validate([...]), ->safe()). Validated input is still input, but
     * rules like "in:a,b" make it safe for identifier sinks such as orderBy().
     */
    public function isValidated(?Node $node): bool
    {
        return match (true) {
            $node instanceof Expr\Variable => is_string($node->name) && $this->scopeHas('validated', $node->name),
            $node instanceof Expr\ArrayDimFetch => $this->isValidated($node->var),
            $node instanceof Expr\BinaryOp\Coalesce => $this->isValidated($node->left) && ! $this->isTainted($node->right),
            $node instanceof Expr\Cast => $this->isValidated($node->expr),
            $node instanceof Expr\MethodCall, $node instanceof Expr\NullsafeMethodCall, $node instanceof Expr\StaticCall => Ast::chainHasMethod($node, ['validated', 'validate', 'safe', 'validatewithbag']),
            default => false,
        };
    }

    /**
     * Whether the value is only known at runtime, i.e. not a literal, a
     * constant or a variable that only ever held literals. Casting to a
     * number makes a value static enough for injection purposes.
     */
    public function isDynamic(?Node $node): bool
    {
        return match (true) {
            $node === null => false,
            $node instanceof Scalar\String_, $node instanceof Scalar\Int_, $node instanceof Scalar\Float_,
            $node instanceof Scalar\MagicConst, $node instanceof Node\InterpolatedStringPart => false,
            $node instanceof Expr\ConstFetch, $node instanceof Expr\ClassConstFetch => false,
            $node instanceof Expr\Cast\Int_, $node instanceof Expr\Cast\Double, $node instanceof Expr\Cast\Bool_ => false,
            $node instanceof Expr\Variable => ! (is_string($node->name) && $this->scopeHas('literal', $node->name)),
            $node instanceof Expr\BinaryOp\Concat => $this->isDynamic($node->left) || $this->isDynamic($node->right),
            $node instanceof Expr\BinaryOp\Coalesce => $this->isDynamic($node->left) || $this->isDynamic($node->right),
            $node instanceof Expr\Ternary => $this->isDynamic($node->if ?? $node->cond) || $this->isDynamic($node->else),
            $node instanceof Scalar\InterpolatedString => array_any($node->parts, fn (Node $part) => $this->isDynamic($part)),
            $node instanceof Expr\FuncCall => ! in_array(Ast::functionName($node), self::SANITIZERS, true),
            default => true,
        };
    }

    /**
     * Whether the expression is a Laravel request object.
     */
    public function isRequest(?Node $node): bool
    {
        return match (true) {
            $node instanceof Expr\Variable => is_string($node->name) && $this->scopeHas('requests', $node->name),
            $node instanceof Expr\FuncCall => Ast::functionName($node) === 'request' && $node->getArgs() === [],
            $node instanceof Expr\PropertyFetch => $node->name instanceof Node\Identifier && $node->name->toString() === 'request',
            $node instanceof Expr\StaticCall => Ast::className($node) === 'Request' && Ast::methodName($node) === 'instance',
            // Yii::$app->getRequest(), Symfony $requestStack->getCurrentRequest() / getMainRequest()
            $node instanceof Expr\MethodCall => in_array(Ast::methodName($node), ['getrequest', 'getcurrentrequest', 'getmainrequest'], true),
            default => false,
        };
    }

    /**
     * in_array($x, ['a', 'b']) ? $x : 'a' and array_key_exists($x, $map) ? $x : ...
     * only let allow-listed values through.
     */
    private function isAllowListed(Expr\Ternary $node): bool
    {
        $tested = $this->allowListedExpression($node->cond);

        return $tested !== null && $node->if !== null
            && $this->printer()->prettyPrintExpr($tested) === $this->printer()->prettyPrintExpr($this->withoutCasts($node->if));
    }

    /**
     * The value checked by in_array($value, [...]) / array_key_exists($value, $map).
     */
    private function allowListedExpression(Expr $condition): ?Expr
    {
        if (! in_array(Ast::functionName($condition), ['in_array', 'array_key_exists'], true)) {
            return null;
        }

        $tested = Ast::arg($condition, 0);
        $list = Ast::arg($condition, 1);

        return $tested !== null && ($list instanceof Expr\Array_ || ! $this->isTainted($list)) ? $this->withoutCasts($tested) : null;
    }

    private function guardedVariable(Expr $condition): ?string
    {
        $tested = $this->allowListedExpression($condition);

        return $tested instanceof Expr\Variable && is_string($tested->name) ? $tested->name : null;
    }

    private function withoutCasts(Expr $node): Expr
    {
        while ($node instanceof Expr\Cast\String_) {
            $node = $node->expr;
        }

        return $node;
    }

    private function printer(): Standard
    {
        return $this->printer ??= new Standard;
    }

    private function taintedDimFetch(Expr\ArrayDimFetch $node): bool
    {
        // Only the request-derived parts of $_SERVER come from the client.
        if ($node->var instanceof Expr\Variable && $node->var->name === '_SERVER') {
            return ! $node->dim instanceof Scalar\String_
                || preg_match('/^(HTTP_|REQUEST_URI|QUERY_STRING|PATH_INFO|PHP_SELF|ORIG_PATH_INFO|CONTENT_TYPE|argv)/', $node->dim->value) === 1;
        }

        return $this->isTainted($node->var) || $this->isRequest($node->var);
    }

    private function taintedFuncCall(Expr\FuncCall $node): bool
    {
        $name = Ast::functionName($node);

        if ($name === null) {
            return false;
        }

        if ($name === 'request') {
            return $node->getArgs() !== [];
        }

        if ($name === 'old' || $name === 'file_get_contents' && $this->isPhpInput(Ast::arg($node, 0))) {
            return true;
        }

        if (in_array($name, self::SANITIZERS, true) || $node->isFirstClassCallable()) {
            return false;
        }

        return $this->anyTainted(array_map(fn (Node\Arg $arg) => $arg->value, $node->getArgs()));
    }

    private function taintedMethodCall(Expr\MethodCall|Expr\NullsafeMethodCall $node): bool
    {
        $method = Ast::methodName($node);

        if (in_array($method, self::UNIVERSAL_SOURCE_METHODS, true)) {
            return true;
        }

        if (in_array($method, self::SANITIZING_METHODS, true)) {
            return false;
        }

        if ($this->isRequest($node->var)) {
            return in_array($method, self::SOURCE_METHODS, true);
        }

        // Fluent chains on tainted values (Stringable, Collection...) stay tainted.
        return $this->isTainted($node->var);
    }

    private function taintedStaticCall(Expr\StaticCall $node): bool
    {
        $class = Ast::className($node);
        $method = Ast::methodName($node);

        if ($class === 'Request' || $class === 'Input') {
            return in_array($method, self::SOURCE_METHODS, true);
        }

        if (in_array($class, ['Str', 'Arr', 'Collection', 'Stringable'], true) && ! in_array($method, self::SANITIZING_METHODS, true)) {
            return $this->anyTainted(array_map(fn (Node\Arg $arg) => $arg->value, $node->getArgs()));
        }

        return false;
    }

    private function assign(Expr $target, Expr $value, bool $append): void
    {
        $tainted = $this->isTainted($value);
        $request = $this->isRequest($value);
        $validated = $this->isValidated($value);
        $literal = ! $this->isDynamic($value);

        if ($target instanceof Expr\List_ || $target instanceof Expr\Array_) {
            $this->markTargets($target, $tainted);

            return;
        }

        $name = $this->rootVariable($target);

        if ($name === null) {
            return;
        }

        $scope = &$this->scopes[$this->current()];
        $whole = $target instanceof Expr\Variable && ! $append;

        if ($tainted) {
            $scope['tainted'][$name] = true;
        } elseif ($whole) {
            unset($scope['tainted'][$name]);
        }

        if ($validated && $whole) {
            $scope['validated'][$name] = true;
        } elseif ($whole) {
            unset($scope['validated'][$name]);
        }

        if ($request && $whole) {
            $scope['requests'][$name] = true;
        } elseif ($whole) {
            unset($scope['requests'][$name]);
        }

        if ($literal && ($whole || isset($scope['literal'][$name]))) {
            $scope['literal'][$name] = true;
        } else {
            unset($scope['literal'][$name]);
        }
    }

    private function markTargets(Node $target, bool $tainted): void
    {
        if ($target instanceof Expr\List_ || $target instanceof Expr\Array_) {
            foreach ($target->items as $item) {
                if ($item !== null) {
                    $this->markTargets($item->value, $tainted);
                }
            }

            return;
        }

        $name = $this->rootVariable($target);

        if ($name === null) {
            return;
        }

        $scope = &$this->scopes[$this->current()];
        unset($scope['literal'][$name]);

        if ($tainted) {
            $scope['tainted'][$name] = true;
        }
    }

    private function rootVariable(Node $node): ?string
    {
        while ($node instanceof Expr\ArrayDimFetch) {
            $node = $node->var;
        }

        return $node instanceof Expr\Variable && is_string($node->name) ? $node->name : null;
    }

    private function isRequestType(?Node $type): bool
    {
        if ($type instanceof Node\NullableType) {
            $type = $type->type;
        }

        if ($type instanceof Node\UnionType || $type instanceof Node\IntersectionType) {
            return array_any($type->types, fn (Node $inner) => $this->isRequestType($inner));
        }

        return $type instanceof Name && str_ends_with($type->getLast(), 'Request')
            && ! str_contains(strtolower($type->toString()), 'psr');
    }

    private function isPhpInput(?Node $node): bool
    {
        return $node instanceof Scalar\String_ && $node->value === 'php://input';
    }

    /**
     * @param  array<int, Node|null>  $nodes
     */
    private function anyTainted(array $nodes): bool
    {
        return array_any($nodes, fn (?Node $node) => $this->isTainted($node));
    }

    /**
     * @param  'tainted'|'requests'|'literal'|'validated'  $set
     */
    private function scopeHas(string $set, string $name): bool
    {
        return isset($this->scopes[$this->current()][$set][$name]);
    }

    private function current(): int
    {
        return count($this->scopes) - 1;
    }

    /**
     * @param  array<string, true>  $requests
     * @return array{tainted: array<string, true>, requests: array<string, true>, literal: array<string, true>, validated: array<string, true>}
     */
    private function emptyScope(array $requests = []): array
    {
        return ['tainted' => [], 'requests' => $requests, 'literal' => [], 'validated' => []];
    }
}

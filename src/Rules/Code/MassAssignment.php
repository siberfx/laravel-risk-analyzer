<?php

namespace Siberfx\RiskAnalyzer\Rules\Code;

use PhpParser\Node;
use PhpParser\Node\Expr;
use PhpParser\Node\Stmt;
use Siberfx\RiskAnalyzer\Code\Ast;
use Siberfx\RiskAnalyzer\Code\FileScope;
use Siberfx\RiskAnalyzer\Finding;
use Siberfx\RiskAnalyzer\Severity;

final class MassAssignment extends AbstractCodeRule
{
    /** Request methods that return every submitted field. */
    private const array UNFILTERED = ['all', 'input', 'post', 'json', 'except', 'collect', 'getpayload'];

    private const array WRITE_METHODS = [
        'create', 'fill', 'update', 'forcefill', 'forcecreate', 'firstorcreate', 'updateorcreate', 'insert',
        'createquietly', 'forcecreatequietly', 'updatequietly',
    ];

    private const array MODEL_PARENTS = ['Model', 'Authenticatable', 'User', 'Pivot', 'MorphPivot'];

    public function id(): string
    {
        return 'mass-assignment';
    }

    public function title(): string
    {
        return 'Mass assignment';
    }

    public function description(): string
    {
        return 'Every submitted field ($request->all(), ->except(), ->input()) written to a model with create/fill/update, forceFill/forceCreate of request input, models with an empty $guarded and Model::unguard().';
    }

    public function severity(): Severity
    {
        return Severity::High;
    }

    public function inspect(Node $node, FileScope $file): iterable
    {
        if ($node instanceof Stmt\Class_ && $this->isModel($node)) {
            yield from $this->inspectModel($node, $file);

            return;
        }

        if ($node instanceof Expr\StaticCall && Ast::methodName($node) === 'unguard' && $node->getArgs() === []) {
            yield $this->report($file, $node, 'Model::unguard() disables mass-assignment protection for every model.', Severity::Medium,
                'Remove the call and list writable attributes in $fillable, or wrap trusted code in Model::unguarded(fn () => ...).');

            return;
        }

        $method = Ast::methodName($node);

        if (! in_array($method, self::WRITE_METHODS, true) || ! $node instanceof Expr\CallLike) {
            return;
        }

        $attributes = $method === 'updateorcreate' || $method === 'firstorcreate'
            ? Ast::arg($node, 1, 'values')
            : Ast::arg($node, 0, 'attributes');

        if ($attributes === null || ! $this->isUnfilteredInput($attributes, $file)) {
            return;
        }

        $forced = str_starts_with((string) $method, 'force');

        yield $this->report($file, $node, $forced
            ? "Request input is written with {$method}(), bypassing \$fillable/\$guarded."
            : "Every submitted field is passed to {$method}().",
            $forced ? Severity::High : Severity::Medium,
            'Pass $request->validated() (or ->safe()->only([...])) from a FormRequest so only the fields you validated reach the model.',
        );
    }

    /**
     * @return iterable<Finding>
     */
    private function inspectModel(Stmt\Class_ $class, FileScope $file): iterable
    {
        foreach ($class->stmts as $statement) {
            if (! $statement instanceof Stmt\Property) {
                continue;
            }

            foreach ($statement->props as $property) {
                if ($property->name->toString() === 'guarded' && $property->default instanceof Expr\Array_ && $property->default->items === []) {
                    yield $this->report($file, $property, 'Model has an empty $guarded, so every column is mass assignable.', Severity::Medium,
                        'List writable columns in $fillable instead, or at least guard id, role/is_admin-style and foreign key columns.');
                }
            }
        }

        foreach ($class->attrGroups as $group) {
            foreach ($group->attrs as $attribute) {
                if ($attribute->name->getLast() === 'Unguarded') {
                    yield $this->report($file, $attribute, 'Model is marked #[Unguarded], so every column is mass assignable.', Severity::Medium,
                        'Use #[Fillable([...])] to list writable columns.');
                }
            }
        }
    }

    private function isUnfilteredInput(Expr $value, FileScope $file): bool
    {
        // request()->all(), $request->except('x'), $request->input() without a key
        if (($value instanceof Expr\MethodCall || $value instanceof Expr\NullsafeMethodCall) && $file->taint->isRequest($value->var)) {
            $method = Ast::methodName($value);

            return in_array($method, self::UNFILTERED, true) && ($method !== 'input' && $method !== 'post' && $method !== 'json' || $value->getArgs() === []);
        }

        if ($value instanceof Expr\StaticCall && Ast::className($value) === 'Request') {
            return in_array(Ast::methodName($value), ['all', 'except'], true);
        }

        return $value instanceof Expr\Variable && in_array($value->name, ['_POST', '_REQUEST', '_GET'], true);
    }

    private function isModel(Stmt\Class_ $class): bool
    {
        return $class->extends !== null && in_array($class->extends->getLast(), self::MODEL_PARENTS, true);
    }
}

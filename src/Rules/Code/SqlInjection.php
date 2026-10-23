<?php

namespace Siberfx\RiskAnalyzer\Rules\Code;

use PhpParser\Node;
use PhpParser\Node\Expr;
use Siberfx\RiskAnalyzer\Code\Ast;
use Siberfx\RiskAnalyzer\Code\FileScope;
use Siberfx\RiskAnalyzer\Severity;

final class SqlInjection extends AbstractCodeRule
{
    /** DB facade / connection methods whose first argument is raw SQL. */
    private const array CONNECTION_METHODS = [
        'raw', 'select', 'selectone', 'selectresultsets', 'scalar', 'cursor', 'statement', 'unprepared',
        'insert', 'update', 'delete', 'affectingstatement',
    ];

    /** Query builder methods whose first argument is raw SQL. */
    private const array RAW_METHODS = [
        'whereraw', 'orwhereraw', 'havingraw', 'orhavingraw', 'orderbyraw', 'selectraw', 'groupbyraw', 'fromraw',
        'wherenotraw', 'orwherenotraw',
    ];

    /** Builder methods whose first argument is a column or table name. */
    private const array COLUMN_METHODS = ['orderby', 'orderbydesc', 'groupby', 'latest', 'oldest', 'pluck', 'select', 'addselect', 'table', 'from'];

    public function id(): string
    {
        return 'sql-injection';
    }

    public function title(): string
    {
        return 'SQL injection';
    }

    public function description(): string
    {
        return 'Raw SQL (DB::select, DB::raw, whereRaw, orderByRaw...) built from request input or other runtime values instead of query bindings, and user-chosen column names passed to orderBy/groupBy.';
    }

    public function severity(): Severity
    {
        return Severity::Critical;
    }

    public function inspect(Node $node, FileScope $file): iterable
    {
        $method = Ast::methodName($node);

        if ($method === null) {
            return;
        }

        $isConnectionCall = in_array($method, self::CONNECTION_METHODS, true) && $this->isConnection($node);

        if ($isConnectionCall || in_array($method, self::RAW_METHODS, true)) {
            /** @var Expr\CallLike $node */
            $sql = Ast::arg($node, 0, $method === 'raw' ? 'value' : 'query') ?? Ast::arg($node, 0, 'sql');

            // Migrations and seeders build DDL from table names: only input matters there.
            // A runtime SQL string that comes with bindings is a deliberate query builder.
            $dynamic = str_starts_with($file->path, 'database/') || ($method !== 'unprepared' && Ast::arg($node, 1, 'bindings') !== null)
                ? null
                : ($method === 'unprepared' ? Severity::High : Severity::Medium);
            $severity = $this->sinkSeverity($file, $sql, $dynamic);

            if ($severity === null) {
                return;
            }

            yield $this->report($file, $node, $severity === $this->severity()
                ? "Request input flows into raw SQL passed to {$this->label($node)}()."
                : "Raw SQL passed to {$this->label($node)}() is built from a runtime value.",
                $severity,
                'Keep the SQL a literal and pass values as bindings: whereRaw(\'price > ?\', [$price]). For identifiers, check them against an allow-list.',
            );

            return;
        }

        // from()/table() mean many things (Enum::from(), $mail->from()); only trust DB:: chains.
        $isDbChain = ($node instanceof Expr\StaticCall && Ast::className($node) === 'DB') || Ast::chainRootClass($node) === 'DB';

        if (in_array($method, self::COLUMN_METHODS, true) && ($isDbChain || ! in_array($method, ['from', 'table'], true))) {
            $column = Ast::arg($node, 0, 'column') ?? Ast::arg($node, 0, 'table');

            if ($column !== null && $file->taint->isTainted($column) && ! $file->taint->isValidated($column)) {
                yield $this->report($file, $node, "Request input is used as an identifier in {$this->label($node)}().",
                    Severity::Medium,
                    'Map the requested sort/group field through an allow-list: in_array($field, [\'name\', \'created_at\'], true).',
                );
            }
        }
    }

    private function isConnection(Node $node): bool
    {
        if ($node instanceof Expr\StaticCall) {
            return Ast::className($node) === 'DB';
        }

        // DB::connection('x')->select(...), but not DB::table('x')->select(...).
        $root = Ast::chainRoot($node);

        return $root instanceof Expr\StaticCall && Ast::className($root) === 'DB' && Ast::methodName($root) === 'connection'
            && $node instanceof Expr\MethodCall && $node->var === $root;
    }

    private function label(Node $node): string
    {
        $method = $node instanceof Expr\CallLike && property_exists($node, 'name') && $node->name instanceof Node\Identifier
            ? $node->name->toString()
            : 'query';

        return $node instanceof Expr\StaticCall ? (Ast::className($node) ?? 'DB').'::'.$method : $method;
    }
}

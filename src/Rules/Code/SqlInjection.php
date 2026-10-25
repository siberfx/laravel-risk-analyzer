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

    /** PDO, mysqli, Doctrine DBAL/ORM and Yii2 methods that take raw SQL and are unambiguous by name. */
    private const array SQL_METHODS = [
        'executequery', 'executestatement', 'executeupdate', 'fetchallassociative', 'fetchassociative', 'fetchone', 'fetchallnumeric',
        'fetchnumeric', 'fetchfirstcolumn', 'fetchallkeyvalue', 'fetchallassociativeindexed', 'iterateassociative', 'iteratenumeric',
        'createnativequery', 'createcommand', 'findbysql', 'multi_query', 'real_query',
    ];

    /** Common method names (PDO::query(), mysqli::query(), EntityManager::createQuery()): SQL only when it looks like SQL or runs on a connection. */
    private const array AMBIGUOUS_SQL_METHODS = ['query', 'exec', 'prepare', 'createquery'];

    /** Native database functions => position of the SQL argument (-1: the last one). */
    private const array SQL_FUNCTIONS = [
        'mysqli_query' => 1, 'mysqli_real_query' => 1, 'mysqli_multi_query' => 1, 'mysqli_prepare' => 1, 'pg_query' => -1,
        'pg_send_query' => 1, 'pg_query_params' => 1, 'pg_prepare' => 2, 'sqlsrv_query' => 1, 'sqlsrv_prepare' => 1, 'oci_parse' => 1,
    ];

    /** Doctrine QueryBuilder and Yii2 Query methods that accept a raw SQL condition. */
    private const array CONDITION_METHODS = ['where', 'andwhere', 'orwhere', 'having', 'andhaving', 'orhaving'];

    private const string CONNECTION_NAME = '/^(pdo|db|dbh|conn|connection|mysqli|link|database|em|entitymanager|entity_manager)$/i';

    private const string SQL_TEXT = '/\b(select\s.+?\sfrom|insert\s+into|update\s+\S+\s+set|delete\s+from|replace\s+into|drop\s+table|truncate|alter\s+table)\b/is';

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
        return 'Raw SQL built from request input or other runtime values instead of bindings: Laravel (DB::select, DB::raw, whereRaw, orderByRaw...), PDO and mysqli (query, exec, prepare, mysqli_query, pg_query), Doctrine (executeQuery, fetchAllAssociative, createQuery, QueryBuilder where("... " . $x)) and Yii2 (createCommand, findBySql, where("... " . $x)); and user-chosen column names passed to orderBy/groupBy.';
    }

    public function severity(): Severity
    {
        return Severity::Critical;
    }

    public function inspect(Node $node, FileScope $file): iterable
    {
        $method = Ast::methodName($node);

        if ($method === null && ! $node instanceof Expr\FuncCall) {
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

        $sql = $this->nativeSql($node, $method);

        if ($sql !== null) {
            [$query, $label, $bound] = $sql;
            $severity = $this->sinkSeverity($file, $query, $bound ? null : Severity::Medium);

            if ($severity !== null) {
                yield $this->report($file, $node, $severity === $this->severity()
                    ? "Request input flows into raw SQL passed to {$label}()."
                    : "Raw SQL passed to {$label}() is built from a runtime value.",
                    $severity,
                    'Use a prepared statement with placeholders (? or :name) and pass the values separately; for identifiers, check them against an allow-list.',
                );
            }

            return;
        }

        // Doctrine QueryBuilder / Yii2 Query string conditions: ->where("u.id = " . $id)
        // Laravel quotes a lone where() string as a column name; DB:: and Model::where() chains are Laravel's.
        $root = Ast::chainRoot($node);
        $laravelChain = Ast::chainRootClass($node) === 'DB' || $node instanceof Expr\StaticCall
            || ($root instanceof Expr\StaticCall && in_array(Ast::methodName($root), ['query', 'where', 'orwhere', 'wherein', 'select'], true));

        if (! $laravelChain && in_array($method, self::CONDITION_METHODS, true) && ($condition = Ast::arg($node, 0)) !== null && $this->isSqlFragment($condition)) {
            // Conditions built from aliases ("$alias.id = :id") are everywhere; only input counts here.
            $severity = $this->sinkSeverity($file, $condition, null);

            if ($severity !== null) {
                yield $this->report($file, $node, $severity === $this->severity()
                    ? "Request input is concatenated into the SQL condition passed to {$this->label($node)}()."
                    : "The SQL condition passed to {$this->label($node)}() is built from a runtime value.",
                    $severity,
                    'Use a placeholder and bind the value: ->where(\'u.id = :id\')->setParameter(\'id\', $id), or [\'id\' => $id] in Yii2.',
                );
            }

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

    /**
     * Raw SQL handed to PDO, mysqli, pg_*, Doctrine or Yii2.
     *
     * @return array{Expr, string, bool}|null the SQL argument, a label, and whether values are bound separately
     */
    private function nativeSql(Node $node, ?string $method): ?array
    {
        if ($node instanceof Expr\FuncCall && isset(self::SQL_FUNCTIONS[$function = (string) Ast::functionName($node)])) {
            $args = $node->getArgs();
            $position = self::SQL_FUNCTIONS[$function] === -1 ? count($args) - 1 : self::SQL_FUNCTIONS[$function];
            $sql = $args[$position]->value ?? null;

            return $sql === null ? null : [$sql, $function, $function === 'pg_query_params'];
        }

        if (! $node instanceof Expr\MethodCall && ! $node instanceof Expr\NullsafeMethodCall && ! $node instanceof Expr\StaticCall) {
            return null;
        }

        $sql = Ast::arg($node, 0, 'sql') ?? Ast::arg($node, 0, 'query') ?? Ast::arg($node, 0, 'statement');

        if ($sql === null || $method === null) {
            return null;
        }

        $known = in_array($method, self::SQL_METHODS, true);
        $ambiguous = in_array($method, self::AMBIGUOUS_SQL_METHODS, true)
            && ($this->looksLikeSql($sql) || ($node instanceof Expr\MethodCall && preg_match(self::CONNECTION_NAME, (string) Ast::targetName($node->var)) === 1));

        // A second argument means parameters bound separately (DBAL, Yii2 createCommand, findBySql).
        return $known || $ambiguous ? [$sql, $this->label($node), Ast::arg($node, 1) !== null] : null;
    }

    private function looksLikeSql(Expr $node): bool
    {
        return preg_match(self::SQL_TEXT, $this->literalText($node)) === 1;
    }

    /**
     * A string built at runtime whose literal parts read like a SQL condition ("u.id = " . $id).
     */
    private function isSqlFragment(Expr $node): bool
    {
        return ($node instanceof Expr\BinaryOp\Concat || $node instanceof Node\Scalar\InterpolatedString)
            && preg_match('/(=|<|>|\blike\b|\bin\s*\(|\bbetween\b|\bis\s+(not\s+)?null\b)/i', $this->literalText($node)) === 1;
    }

    /**
     * The literal pieces of a string expression, joined.
     */
    private function literalText(Node $node): string
    {
        return match (true) {
            $node instanceof Node\Scalar\String_, $node instanceof Node\InterpolatedStringPart => $node->value,
            $node instanceof Node\Scalar\InterpolatedString => implode(' ', array_map(fn (Node $part) => $this->literalText($part), $node->parts)),
            $node instanceof Expr\BinaryOp\Concat => $this->literalText($node->left).' '.$this->literalText($node->right),
            default => ' ',
        };
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

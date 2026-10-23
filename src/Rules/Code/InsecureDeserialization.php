<?php

namespace Siberfx\RiskAnalyzer\Rules\Code;

use PhpParser\Node;
use PhpParser\Node\Expr;
use Siberfx\RiskAnalyzer\Code\Ast;
use Siberfx\RiskAnalyzer\Code\FileScope;
use Siberfx\RiskAnalyzer\Severity;

final class InsecureDeserialization extends AbstractCodeRule
{
    public function id(): string
    {
        return 'insecure-deserialization';
    }

    public function title(): string
    {
        return 'Insecure deserialization';
    }

    public function description(): string
    {
        return 'unserialize() of request input, or of any runtime value without restricting allowed_classes, which allows PHP object injection (gadget chains).';
    }

    public function severity(): Severity
    {
        return Severity::Critical;
    }

    public function inspect(Node $node, FileScope $file): iterable
    {
        if (Ast::functionName($node) !== 'unserialize' || ! $node instanceof Expr\FuncCall) {
            return;
        }

        $value = Ast::arg($node, 0, 'data');

        if ($this->restrictsClasses(Ast::arg($node, 1, 'options'))) {
            return;
        }

        $severity = $this->sinkSeverity($file, $value, Severity::Medium);

        if ($severity !== null) {
            yield $this->report($file, $node, $severity === $this->severity()
                ? 'Request input is passed to unserialize().'
                : 'unserialize() is called without restricting allowed_classes.',
                $severity,
                'Use json_decode() for data that crosses a trust boundary, or pass [\'allowed_classes\' => false].',
            );
        }
    }

    private function restrictsClasses(?Expr $options): bool
    {
        if (! $options instanceof Expr\Array_) {
            return false;
        }

        foreach ($options->items as $item) {
            if (Ast::targetName($item) === 'allowed_classes' && ! ($item->value instanceof Expr\ConstFetch && strtolower($item->value->name->toString()) === 'true')) {
                return true;
            }
        }

        return false;
    }
}

<?php

namespace Siberfx\RiskAnalyzer\Rules\Code;

use PhpParser\Node;
use PhpParser\Node\Expr;
use PhpParser\Node\Stmt;
use PhpParser\PrettyPrinter\Standard;
use Siberfx\RiskAnalyzer\Code\FileScope;
use Siberfx\RiskAnalyzer\Severity;

final class UnescapedEcho extends AbstractCodeRule
{
    private ?Standard $printer = null;

    public function id(): string
    {
        return 'xss-echo';
    }

    public function title(): string
    {
        return 'Unescaped PHP output';
    }

    public function description(): string
    {
        return 'echo, print and <?= ?> of request input without htmlspecialchars()/e()/Html::encode(), in plain PHP pages, Yii2 views and controllers that write HTML themselves. Command-line arguments are ignored.';
    }

    public function severity(): Severity
    {
        return Severity::High;
    }

    public function inspect(Node $node, FileScope $file): iterable
    {
        $values = match (true) {
            $node instanceof Stmt\Echo_ => $node->exprs,
            $node instanceof Expr\Print_ => [$node->expr],
            default => [],
        };

        foreach ($values as $value) {
            // $_SERVER['argv'] is input for CLI scripts, not for a browser.
            if ($file->taint->isTainted($value) && ! str_contains($this->print($value), 'argv')) {
                yield $this->report($file, $node, 'Request input is printed without escaping.', null,
                    'Escape it for HTML: htmlspecialchars($value, ENT_QUOTES), Html::encode() in Yii2, or a template engine that escapes by default.');

                return;
            }
        }
    }

    private function print(Expr $node): string
    {
        return ($this->printer ??= new Standard)->prettyPrintExpr($node);
    }
}

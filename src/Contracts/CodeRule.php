<?php

namespace Siberfx\RiskAnalyzer\Contracts;

use PhpParser\Node;
use Siberfx\RiskAnalyzer\Code\FileScope;
use Siberfx\RiskAnalyzer\Finding;

/**
 * A rule that looks at PHP AST nodes. Every PHP file is parsed once and each
 * node is offered to every code rule, with taint information for the
 * enclosing function available through $file->taint.
 */
interface CodeRule extends Rule
{
    /**
     * @return iterable<Finding>
     */
    public function inspect(Node $node, FileScope $file): iterable;
}

<?php

namespace Siberfx\RiskAnalyzer\Code;

use PhpParser\Error;
use PhpParser\Node;
use PhpParser\NodeTraverser;
use PhpParser\NodeVisitor\NameResolver;
use PhpParser\NodeVisitor\ParentConnectingVisitor;
use PhpParser\NodeVisitorAbstract;
use PhpParser\Parser;
use PhpParser\ParserFactory;
use Siberfx\RiskAnalyzer\Contracts\CodeRule;
use Siberfx\RiskAnalyzer\Finding;
use Siberfx\RiskAnalyzer\ScanContext;
use Siberfx\RiskAnalyzer\Severity;

/**
 * Parses each PHP file once and walks its AST, offering every node to every
 * code rule while keeping the taint tracker in step with the walk.
 */
final class Analyzer
{
    private readonly Parser $parser;

    public function __construct()
    {
        $this->parser = (new ParserFactory)->createForHostVersion();
    }

    /**
     * @param  list<CodeRule>  $rules
     * @return list<Finding>
     */
    public function analyse(ScanContext $context, array $rules): array
    {
        if ($rules === []) {
            return [];
        }

        $findings = [];

        foreach ($context->files(['.php']) as $path) {
            if (str_ends_with($path, '.blade.php')) {
                continue;
            }

            $source = $context->read($path);

            if ($source !== null) {
                array_push($findings, ...$this->analyseSource($path, $source, $rules));
            }
        }

        return $findings;
    }

    /**
     * @param  list<CodeRule>  $rules
     * @return list<Finding>
     */
    public function analyseSource(string $path, string $source, array $rules, int $lineOffset = 0, ?Taint $taint = null): array
    {
        try {
            $ast = $this->parser->parse($source) ?? [];
        } catch (Error $error) {
            return [new Finding(
                rule: 'parse-error',
                severity: Severity::Info,
                message: 'File could not be parsed and was not analysed: '.$error->getRawMessage(),
                file: $path,
                line: $error->getStartLine() > 0 ? $error->getStartLine() + $lineOffset : null,
            )];
        }

        $file = new FileScope($path, $source, $taint ?? new Taint, $lineOffset);
        $visitor = new class($rules, $file) extends NodeVisitorAbstract
        {
            /** @var list<Finding> */
            public array $findings = [];

            /**
             * @param  list<CodeRule>  $rules
             */
            public function __construct(private readonly array $rules, private readonly FileScope $file) {}

            public function enterNode(Node $node): null
            {
                if ($node instanceof Node\FunctionLike) {
                    $this->file->taint->enterFunction($node);
                }

                foreach ($this->rules as $rule) {
                    foreach ($rule->inspect($node, $this->file) as $finding) {
                        if ($finding->line === null || ! $this->file->isIgnored($finding->rule, $finding->line)) {
                            $this->findings[] = $finding;
                        }
                    }
                }

                $this->file->taint->enter($node);

                return null;
            }

            public function leaveNode(Node $node): null
            {
                $this->file->taint->leave($node);

                if ($node instanceof Node\FunctionLike) {
                    $this->file->taint->leaveFunction();
                }

                return null;
            }
        };

        $traverser = new NodeTraverser(new NameResolver, new ParentConnectingVisitor, $visitor);
        $traverser->traverse($ast);

        return $visitor->findings;
    }
}

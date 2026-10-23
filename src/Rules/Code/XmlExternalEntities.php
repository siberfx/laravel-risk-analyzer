<?php

namespace Siberfx\RiskAnalyzer\Rules\Code;

use PhpParser\Node;
use PhpParser\Node\Expr;
use Siberfx\RiskAnalyzer\Code\Ast;
use Siberfx\RiskAnalyzer\Code\FileScope;
use Siberfx\RiskAnalyzer\Finding;
use Siberfx\RiskAnalyzer\Severity;

final class XmlExternalEntities extends AbstractCodeRule
{
    private const array LOADERS = ['simplexml_load_string', 'simplexml_load_file', 'loadxml', 'load', 'xml_parse', 'xml_parse_into_struct'];

    public function id(): string
    {
        return 'xxe';
    }

    public function title(): string
    {
        return 'XML external entities';
    }

    public function description(): string
    {
        return 'XML parsed with entity substitution or DTD loading turned on (LIBXML_NOENT, LIBXML_DTDLOAD, substituteEntities, libxml_disable_entity_loader(false)), which lets a document read local files or reach internal hosts.';
    }

    public function severity(): Severity
    {
        return Severity::High;
    }

    public function inspect(Node $node, FileScope $file): iterable
    {
        if (Ast::functionName($node) === 'libxml_disable_entity_loader' && Ast::isFalse(Ast::arg($node, 0))) {
            yield $this->finding($file, $node, 'The external entity loader is switched back on.');

            return;
        }

        // $doc->substituteEntities = true; $doc->resolveExternals = true;
        if ($node instanceof Expr\Assign && in_array(Ast::targetName($node->var), ['substituteEntities', 'resolveExternals'], true)
            && $node->expr instanceof Expr\ConstFetch && strtolower($node->expr->name->toString()) === 'true') {
            yield $this->finding($file, $node, 'DOMDocument::'.Ast::targetName($node->var).' enables external entities.');

            return;
        }

        $name = Ast::functionName($node) ?? Ast::methodName($node);

        if (! in_array($name, self::LOADERS, true) || ! $node instanceof Expr\CallLike || $node->isFirstClassCallable()) {
            return;
        }

        foreach ($node->getArgs() as $arg) {
            foreach (['LIBXML_NOENT', 'LIBXML_DTDLOAD', 'LIBXML_DTDATTR'] as $flag) {
                if (Ast::usesConst($arg->value, $flag)) {
                    yield $this->finding($file, $node, "XML is parsed with {$flag}, which resolves external entities.",
                        $file->taint->isTainted(Ast::arg($node, 0)) ? null : Severity::Medium);

                    return;
                }
            }
        }
    }

    private function finding(FileScope $file, Node $node, string $message, ?Severity $severity = null): Finding
    {
        return $this->report($file, $node, $message, $severity,
            'Drop LIBXML_NOENT/LIBXML_DTDLOAD. Since PHP 8 entities are not loaded unless you ask for them; LIBXML_NONET also blocks network access.');
    }
}

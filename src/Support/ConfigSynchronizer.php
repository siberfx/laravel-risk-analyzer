<?php

namespace Siberfx\RiskAnalyzer\Support;

use PhpParser\Node\ArrayItem;
use PhpParser\Node\Expr\Array_;
use PhpParser\Node\Scalar\Int_;
use PhpParser\Node\Scalar\String_;
use PhpParser\Node\Stmt;
use PhpParser\Node\Stmt\Return_;
use PhpParser\Parser;
use PhpParser\ParserFactory;
use RuntimeException;

/**
 * Adds the package config keys missing from a published config file. The
 * package's own source text (comments included) is spliced in after the last
 * key of each section, so the user's comments, env() calls and formatting
 * stay exactly as written. Lists are never merged.
 */
final class ConfigSynchronizer
{
    private readonly Parser $parser;

    private string $defaultsCode = '';

    private string $publishedCode = '';

    /** @var list<array{int, string}> offset => text */
    private array $edits = [];

    /** @var list<string> */
    private array $added = [];

    public function __construct()
    {
        $this->parser = (new ParserFactory)->createForHostVersion();
    }

    /**
     * @return array{code: string, added: list<string>}
     */
    public function sync(string $defaultsCode, string $publishedCode): array
    {
        $this->defaultsCode = $defaultsCode;
        $this->publishedCode = $publishedCode;
        $this->edits = [];
        $this->added = [];

        $this->addMissing(
            $this->returnedArray($this->parser->parse($defaultsCode) ?? [], 'package'),
            $this->returnedArray($this->parser->parse($publishedCode) ?? [], 'published'),
            '',
        );

        usort($this->edits, fn (array $a, array $b) => $b[0] <=> $a[0]);

        $code = $publishedCode;

        foreach ($this->edits as [$offset, $text]) {
            $code = substr($code, 0, $offset).$text.substr($code, $offset);
        }

        return ['code' => $code, 'added' => $this->added];
    }

    private function addMissing(Array_ $defaults, Array_ $published, string $prefix): void
    {
        $missing = [];

        foreach ($defaults->items as $item) {
            $key = $this->key($item);

            if ($key === null) {
                continue;
            }

            $existing = array_find($published->items, fn (ArrayItem $candidate) => $this->key($candidate) === $key);

            if ($existing === null) {
                $missing[] = $item;
                $this->added[] = $prefix.$key;
            } elseif ($item->value instanceof Array_ && $existing->value instanceof Array_
                && $this->isMap($item->value) && $this->isMap($existing->value)) {
                $this->addMissing($item->value, $existing->value, $prefix.$key.'.');
            }
        }

        if ($missing !== []) {
            $this->append($published, $missing);
        }
    }

    /**
     * @param  list<ArrayItem>  $items
     */
    private function append(Array_ $array, array $items): void
    {
        $code = $this->publishedCode;
        $last = $array->items === [] ? null : $array->items[count($array->items) - 1];
        $close = $array->getEndFilePos();

        if ($last === null) {
            $indent = $this->indentAt($code, $array->getStartFilePos()).'    ';
            $this->edits[] = [$close, "\n".$this->render($items, $indent).$this->indentAt($code, $close)];

            return;
        }

        $end = $last->getEndFilePos() + 1;
        $lineEnd = strpos($code, "\n", $end);
        $hasComma = preg_match('/^\s*,/', substr($code, $end, $close - $end)) === 1;

        if ($lineEnd === false || $lineEnd > $close) {
            // Single-line array: ['a' => 1] becomes ['a' => 1, 'b' => 2].
            $inline = implode(', ', array_map(fn (ArrayItem $item) => $this->source($item, withComments: false), $items));
            $this->edits[] = $hasComma ? [$close, ' '.$inline] : [$end, ', '.$inline];

            return;
        }

        if (! $hasComma) {
            $this->edits[] = [$end, ','];
        }

        $this->edits[] = [$lineEnd + 1, $this->render($items, $this->indentAt($code, $last->getStartFilePos()))];
    }

    /**
     * @param  list<ArrayItem>  $items
     */
    private function render(array $items, string $indent): string
    {
        $text = '';

        foreach ($items as $item) {
            $source = $this->source($item, withComments: true);
            $from = $this->indentAt($this->defaultsCode, $this->startOf($item));
            $lines = explode("\n", $source);

            foreach ($lines as $i => $line) {
                $lines[$i] = match (true) {
                    $i === 0 => $indent.$line,
                    trim($line) === '' => '',
                    default => $indent.(str_starts_with($line, $from) ? substr($line, strlen($from)) : ltrim($line)),
                };
            }

            $text .= ($item->getComments() !== [] ? "\n" : '').implode("\n", $lines).",\n";
        }

        return $text;
    }

    private function source(ArrayItem $item, bool $withComments): string
    {
        $start = $withComments ? $this->startOf($item) : $item->getStartFilePos();

        return str_replace("\r\n", "\n", substr($this->defaultsCode, $start, $item->getEndFilePos() - $start + 1));
    }

    private function startOf(ArrayItem $item): int
    {
        $comments = $item->getComments();

        return $comments === [] ? $item->getStartFilePos() : $comments[0]->getStartFilePos();
    }

    /**
     * The leading whitespace of the line that $offset is on.
     */
    private function indentAt(string $code, int $offset): string
    {
        $lineStart = strrpos(substr($code, 0, $offset), "\n");
        $line = substr($code, $lineStart === false ? 0 : $lineStart + 1);

        return (string) preg_replace('/^([ \t]*).*/s', '$1', $line);
    }

    private function isMap(Array_ $array): bool
    {
        return $array->items !== [] && array_all($array->items, fn (ArrayItem $item) => $this->key($item) !== null);
    }

    private function key(ArrayItem $item): ?string
    {
        return match (true) {
            $item->key instanceof String_ => $item->key->value,
            $item->key instanceof Int_ => (string) $item->key->value,
            default => null,
        };
    }

    /**
     * @param  array<Stmt>  $statements
     */
    private function returnedArray(array $statements, string $which): Array_
    {
        foreach ($statements as $statement) {
            if ($statement instanceof Return_ && $statement->expr instanceof Array_) {
                return $statement->expr;
            }
        }

        throw new RuntimeException("The {$which} config file does not return an array literal.");
    }
}

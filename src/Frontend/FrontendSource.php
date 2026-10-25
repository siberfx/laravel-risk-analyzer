<?php

namespace Siberfx\RiskAnalyzer\Frontend;

use Siberfx\RiskAnalyzer\Code\FileScope;
use Siberfx\RiskAnalyzer\Code\Taint;

/**
 * A JavaScript, TypeScript, Vue or Angular template file. Rules match
 * patterns against $code, the source with comments blanked out so that
 * offsets and line numbers stay the same.
 */
final class FrontendSource
{
    /**
     * Values a visitor controls: the URL, route and query parameters in
     * plain JS, React Router, Next.js, Vue Router and Angular, and
     * cross-window messages.
     */
    public const string INPUT_SOURCE = '(?<![\w$])(?:location\s*\.\s*(?:search|hash|href)|document\s*\.\s*(?:URL|documentURI|referrer|cookie)|window\s*\.\s*name|URLSearchParams|searchParams|useSearchParams|useParams|router\s*\.\s*query|\$?route\s*\.\s*(?:query|params|hash|snapshot|queryParams|queryParamMap|paramMap|fragment)|useRoute\s*\(\s*\)\s*\.\s*(?:query|params)|snapshot\s*\.|queryParams|queryParamMap|paramMap|event\s*\.\s*data|evt\s*\.\s*data)\b';

    /** Wrappers that hand input on unchanged, allowed in front of it when it must come first. */
    private const string PASS_THROUGH = '(?:\s|\(|await\s+|new\s+|this\s*\.\s*|window\s*\.\s*|decodeURI(?:Component)?\s*\(|atob\s*\(|JSON\s*\.\s*parse\s*\(|String\s*\()*';

    public readonly string $code;

    private readonly FileScope $scope;

    /** @var list<string>|null variables assigned from input in this file */
    private ?array $inputVariables = null;

    public function __construct(
        public readonly string $path,
        public readonly string $source,
    ) {
        $this->scope = new FileScope($path, $source, new Taint);
        $this->code = (string) preg_replace_callback(
            '#/\*.*?\*/|<!--.*?-->|(?<![:\'"`\w\\\\/])//[^\r\n]*#s',
            fn (array $match) => (string) preg_replace('/[^\r\n]/', ' ', $match[0]),
            $source,
        );
    }

    /**
     * Matches of $pattern in the code, with the line each starts on.
     *
     * @return iterable<array{line: int, groups: array<int|string, string>}>
     */
    public function matches(string $pattern): iterable
    {
        preg_match_all($pattern, $this->code, $matches, PREG_SET_ORDER | PREG_OFFSET_CAPTURE | PREG_UNMATCHED_AS_NULL);

        foreach ($matches as $match) {
            yield [
                'line' => $this->lineAt((int) $match[0][1]),
                'groups' => array_map(fn (array $group) => (string) $group[0], $match),
            ];
        }
    }

    public function lineAt(int $offset): int
    {
        return substr_count($this->code, "\n", 0, $offset) + 1;
    }

    public function line(int $line): ?string
    {
        return $this->scope->line($line);
    }

    /**
     * A "risk-analyzer-ignore" comment on the line or the line above.
     */
    public function isIgnored(string $rule, int $line): bool
    {
        return $this->scope->isIgnored($rule, $line);
    }

    /**
     * Whether visitor-controlled input is visible in $expression, directly or
     * through a variable this file assigns from it. With $leading, the input
     * must be the value itself rather than, say, an argument of a URL builder.
     */
    public function hasInput(string $expression, bool $leading = false): bool
    {
        $this->inputVariables ??= $this->findInputVariables();
        $source = self::sourcePattern($this->inputVariables);

        return preg_match($leading ? '/^'.self::PASS_THROUGH.'(?:'.$source.')/' : '/'.$source.'/', $expression) === 1;
    }

    /**
     * @param  list<string>  $variables
     */
    private static function sourcePattern(array $variables): string
    {
        return $variables === []
            ? self::INPUT_SOURCE
            : self::INPUT_SOURCE.'|(?<![\w$.])(?:'.implode('|', array_map(fn (string $name) => preg_quote($name, '/'), $variables)).')(?![\w$])';
    }

    /**
     * const params = new URLSearchParams(location.search), const { id } = useParams(),
     * const [searchParams] = useSearchParams(), followed through one more assignment
     * (const next = params.get('next')). Values that only pass input to a
     * function (const { data } = useNorm(id)) are not followed: what an API
     * returns for a route id is not the visitor's input.
     *
     * @return list<string>
     */
    private function findInputVariables(): array
    {
        preg_match_all('/\b(?:const|let|var)\s+(\{[^}]*\}|\[[^\]]*\]|[\w$]+)\s*(?::\s*[\w<>\[\]]+\s*)?=\s*([^;\n]+)/', $this->code, $matches, PREG_SET_ORDER);
        $names = [];

        for ($pass = 0; $pass < 2; $pass++) {
            foreach ($matches as [, $target, $value]) {
                if (preg_match('/^'.self::PASS_THROUGH.'(?:'.self::sourcePattern($names).')/', $value) !== 1) {
                    continue;
                }

                // Destructured names, without defaults or renames' source keys.
                preg_match_all('/(?:^|[{\[,]|:)\s*\.{0,3}([A-Za-z_$][\w$]*)\s*(?==|,|[}\]]|$)/', $target, $parts);
                array_push($names, ...$parts[1]);
            }

            $names = array_values(array_unique($names));
        }

        return $names;
    }

    /**
     * A plain string: quoted, or a template literal without ${} parts.
     */
    public static function isLiteral(string $expression): bool
    {
        return preg_match('/^\s*(\'[^\'\\\\]*\'|"[^"\\\\]*"|`[^`$\\\\]*`)\s*$/', $expression) === 1;
    }

    public static function isSanitised(string $expression): bool
    {
        return preg_match('/\b(DOMPurify\s*\.\s*sanitize|sanitizeHtml|sanitize|purify|xss|escapeHtml|escape)\s*\(/i', $expression) === 1;
    }
}

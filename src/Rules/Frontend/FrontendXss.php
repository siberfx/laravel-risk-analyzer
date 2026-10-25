<?php

namespace Siberfx\RiskAnalyzer\Rules\Frontend;

use Siberfx\RiskAnalyzer\Frontend\FrontendSource;
use Siberfx\RiskAnalyzer\Severity;

final class FrontendXss extends AbstractFrontendRule
{
    /** Pattern => [sink, expression group]. */
    private const array SINKS = [
        '/dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:\s*(?<expr>[^\n]+?)\s*\}\s*\}/' => 'dangerouslySetInnerHTML',
        '/dangerouslySetInnerHTML\s*=\s*\{\s*(?<expr>[^{\s][^}\n]*)\}/' => 'dangerouslySetInnerHTML',
        '/(?<![\w-])v-html\s*=\s*(?:"(?<expr>[^"]*)"|\'(?<expr2>[^\']*)\')/' => 'v-html',
        '/\[(?<prop>innerHTML|outerHTML|srcdoc)\]\s*=\s*(?:"(?<expr>[^"]*)"|\'(?<expr2>[^\']*)\')/' => '[innerHTML]',
        '/\.\s*(?<prop>innerHTML|outerHTML)\s*\+?=(?!=)\s*(?<expr>[^;\n]+)/' => 'innerHTML',
        '/\.\s*insertAdjacentHTML\s*\(\s*[^,\n]+,\s*(?<expr>[^;\n]+?)\)\s*;?\s*$/m' => 'insertAdjacentHTML',
        '/(?<![\w$])document\s*\.\s*write(?:ln)?\s*\(\s*(?<expr>[^;\n]+?)\)\s*;?\s*$/m' => 'document.write',
        '/\bbypassSecurityTrust(?<type>Html|Script|Style|Url|ResourceUrl)\s*\(\s*(?<expr>[^;\n]+?)\)\s*;?\s*$/m' => 'bypassSecurityTrust',
    ];

    public function id(): string
    {
        return 'xss-frontend';
    }

    public function title(): string
    {
        return 'HTML injection in frontend code';
    }

    public function description(): string
    {
        return 'React dangerouslySetInnerHTML, Vue v-html, Angular [innerHTML] and DomSanitizer.bypassSecurityTrust*, and innerHTML/outerHTML/insertAdjacentHTML/document.write. URL, route or message input reaching them is high, other dynamic values are medium, sanitised values (DOMPurify) are low and string literals are skipped.';
    }

    public function severity(): Severity
    {
        return Severity::High;
    }

    protected function inspect(FrontendSource $file): iterable
    {
        $seen = [];

        foreach (self::SINKS as $pattern => $sink) {
            foreach ($file->matches($pattern) as $match) {
                $groups = $match['groups'];
                $expression = trim(($groups['expr'] ?? '') !== '' ? $groups['expr'] : ($groups['expr2'] ?? ''));

                // The two dangerouslySetInnerHTML forms can match the same line.
                // Literals and SCREAMING_CASE constants are written by the developer.
                if ($expression === '' || isset($seen[$match['line'].$sink]) || FrontendSource::isLiteral($expression)
                    || preg_match('/^[A-Z][A-Z0-9_]*$/', $expression)) {
                    continue;
                }

                $seen[$match['line'].$sink] = true;
                $name = match ($sink) {
                    '[innerHTML]' => '['.$groups['prop'].']',
                    'innerHTML' => $groups['prop'],
                    'bypassSecurityTrust' => 'bypassSecurityTrust'.$groups['type'].'()',
                    default => $sink,
                };

                // Bypassing Angular's sanitiser is worth a look even with a sanitised value.
                $severity = match (true) {
                    FrontendSource::isSanitised($expression) => $sink === 'bypassSecurityTrust' ? Severity::Medium : Severity::Low,
                    $file->hasInput($expression) => Severity::High,
                    default => Severity::Medium,
                };

                yield $this->report($file, $match['line'], match ($severity) {
                    Severity::High => "URL or route input reaches {$name}: {$this->excerpt($expression)}",
                    Severity::Low => "{$name} renders sanitised HTML ({$this->excerpt($expression)}); check the sanitiser configuration.",
                    default => "{$name} renders {$this->excerpt($expression)} as HTML; make sure it is trusted or sanitised.",
                }, $severity, $sink === 'bypassSecurityTrust'
                    ? 'Let Angular sanitise the value instead of bypassing it, or sanitise it (DOMPurify) before calling bypassSecurityTrust*.'
                    : 'Render text instead ({value}, {{ value }}, textContent). For user-authored HTML, sanitise it with DOMPurify before rendering.');
            }
        }
    }
}

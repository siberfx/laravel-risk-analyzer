<?php

namespace Siberfx\RiskAnalyzer\Rules\Frontend;

use Siberfx\RiskAnalyzer\Frontend\FrontendSource;
use Siberfx\RiskAnalyzer\Severity;

final class FrontendOpenRedirect extends AbstractFrontendRule
{
    private const array NAVIGATIONS = [
        '/(?<![\w$])(?<!const )(?<!let )(?<!var )(?:window\s*\.\s*|document\s*\.\s*|self\s*\.\s*|top\s*\.\s*)?location(?:\s*\.\s*href)?\s*=(?!=)\s*(?<expr>[^;\n]+)/' => 'location',
        '/(?<![\w$])(?:window\s*\.\s*|document\s*\.\s*)?location\s*\.\s*(?:assign|replace)\s*\(\s*(?<expr>[^;\n]+?)\)\s*;?\s*$/m' => 'location',
        '/(?<![\w$])window\s*\.\s*open\s*\(\s*(?<expr>[^,;\n)]+)/' => 'window.open()',
        // React href={...}, Vue :href="...", Angular [href]="..."
        '/(?:\s|^)(?:href|src|action|formAction)\s*=\s*\{(?<expr>(?:[^{}\n]|\{[^{}\n]*\})+)\}/' => 'href',
        '/(?:\s|^)(?::|v-bind:)(?:href|src|action)\s*=\s*"(?<expr>[^"\n]+)"/' => 'href',
        '/\[(?:href|src|action)\]\s*=\s*"(?<expr>[^"\n]+)"/' => 'href',
    ];

    public function id(): string
    {
        return 'frontend-open-redirect';
    }

    public function title(): string
    {
        return 'Unvalidated redirect or javascript: URL';
    }

    public function description(): string
    {
        return 'Navigation to a URL taken from the query string or route (location.href, location.assign/replace, window.open, href/src bindings), which lets a link send visitors to any site or run a javascript: URL, and javascript: URLs written in templates.';
    }

    public function severity(): Severity
    {
        return Severity::Medium;
    }

    protected function inspect(FrontendSource $file): iterable
    {
        foreach (self::NAVIGATIONS as $pattern => $sink) {
            foreach ($file->matches($pattern) as $match) {
                $expression = $match['groups']['expr'];

                // The URL must be the input itself: `/runs/${id}`, 'mailto:' + email
                // and loginUrl(location.search) cannot become another site or javascript:.
                if (! $file->hasInput($expression, leading: true)) {
                    continue;
                }

                yield $this->report($file, $match['line'], $sink === 'href'
                    ? "A link or source URL comes from URL or route input ({$this->excerpt($expression)}); javascript: URLs run as code."
                    : "{$sink} navigates to URL or route input: {$this->excerpt($expression)}",
                    null,
                    'Only follow relative paths (starting with a single /) or URLs whose origin is on an allow-list; reject javascript:, data: and protocol-relative URLs.');
            }
        }

        foreach ($file->matches('/(?:\s|^|\[|:)(?:href|src|action|formAction)\]?\s*=\s*\{?\s*["\'`]{1,2}\s*javascript:(?<code>[^"\'`]*)["\'`](?<rest>[^\n>]*)/i') as $match) {
            $code = trim($match['groups']['code']);
            // href="javascript:void(0)" placeholders do nothing, but block a strict CSP.
            // 'javascript:' + action is built at runtime.
            $noop = preg_match('/^(void\s*\(?\s*0\s*\)?|;)?\s*;?$/', $code) === 1
                && preg_match('/^["\'`]?\s*\}?\s*(\s[^+]*)?$/', $match['groups']['rest']) === 1;

            yield $this->report($file, $match['line'], $noop
                ? 'javascript: placeholder URL in a link.'
                : 'javascript: URL in a template: javascript:'.$this->excerpt($code),
                $noop ? Severity::Low : Severity::Medium,
                'Use a <button> or an @click/onClick/(click) handler instead; javascript: URLs are blocked by a strict Content-Security-Policy.');
        }
    }
}

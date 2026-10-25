<?php

namespace Siberfx\RiskAnalyzer\Rules\Frontend;

use Siberfx\RiskAnalyzer\Frontend\FrontendSource;
use Siberfx\RiskAnalyzer\Severity;

final class FrontendTokenStorage extends AbstractFrontendRule
{
    private const string TOKEN_KEY = '/(token|jwt|auth|bearer|session|api_?key|apikey)/i';

    private const string SECRET_KEY = '/(password|passwd|secret|credential|private)/i';

    public function id(): string
    {
        return 'frontend-token-storage';
    }

    public function title(): string
    {
        return 'Credentials in browser storage';
    }

    public function description(): string
    {
        return 'Auth tokens written to localStorage or sessionStorage (low), where any script on the page, including one injected through XSS, can read them, and passwords or secrets stored there (medium).';
    }

    public function severity(): Severity
    {
        return Severity::Medium;
    }

    protected function inspect(FrontendSource $file): iterable
    {
        $patterns = [
            '/(?<storage>localStorage|sessionStorage)\s*\.\s*setItem\s*\(\s*([\'"`])(?<key>[^\'"`]+)\2/',
            '/(?<storage>localStorage|sessionStorage)\s*\[\s*([\'"`])(?<key>[^\'"`]+)\2\s*\]\s*=(?!=)/',
            '/(?<storage>localStorage|sessionStorage)\s*\.\s*(?<key>[A-Za-z_$][\w$]*)\s*=(?!=)/',
        ];

        foreach ($patterns as $pattern) {
            foreach ($file->matches($pattern) as $match) {
                $key = $match['groups']['key'];
                $storage = $match['groups']['storage'];

                if (preg_match(self::SECRET_KEY, $key)) {
                    yield $this->report($file, $match['line'], "'{$key}' is stored in {$storage}, readable by any script on the page.", Severity::Medium,
                        'Never keep passwords or secrets in the browser.');
                } elseif (preg_match(self::TOKEN_KEY, $key)) {
                    yield $this->report($file, $match['line'], "Auth token '{$key}' is stored in {$storage}, readable by any script on the page (XSS).", Severity::Low,
                        'For a first-party SPA, use Sanctum\'s cookie-based session authentication (HttpOnly cookies) instead of storing tokens.');
                }
            }
        }
    }
}

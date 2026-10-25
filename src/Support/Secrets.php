<?php

namespace Siberfx\RiskAnalyzer\Support;

/**
 * Recognises credentials: provider token formats, secret-looking names and
 * values that look random enough to be real rather than placeholders.
 */
final class Secrets
{
    /** Provider token formats: label => pattern. */
    public const array TOKEN_FORMATS = [
        'AWS access key' => '/^(AKIA|ASIA)[0-9A-Z]{16}$/',
        'Stripe live key' => '/^(sk|rk)_live_[0-9a-zA-Z]{20,}$/',
        'GitHub token' => '/^(gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})$/',
        'Slack token' => '/^xox[abposr]-[0-9A-Za-z-]{10,}$/',
        'Google API key' => '/^AIza[0-9A-Za-z_\-]{35}$/',
        'SendGrid key' => '/^SG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{16,}$/',
        'Anthropic key' => '/^sk-ant-[A-Za-z0-9_\-]{20,}$/',
        'OpenAI key' => '/^sk-(proj-)?[A-Za-z0-9_\-]{32,}$/',
        'Twilio key' => '/^SK[0-9a-f]{32}$/',
        'Mailgun key' => '/^key-[0-9a-f]{32}$/',
        'Private key' => '/-----BEGIN ((RSA|EC|DSA|OPENSSH|ENCRYPTED) )?PRIVATE KEY-----/',
        'Laravel APP_KEY' => '/^base64:[A-Za-z0-9+\/]{43}=$/',
    ];

    public const string SECRET_NAME = '/(^|_|-|\b)(password|passwd|pwd|secret|api_?key|apikey|access_?key|private_?key|client_?secret|auth_?token|access_?token|bearer|credentials?)($|_|-|\b)/i';

    private const string PLACEHOLDER = '/^(|null|none|secret|password|changeme|change-me|xxx+|\*+|your[-_ ].*|<.*>|\{.*\}|\$\{.*\}|example.*|test.*|dummy.*|placeholder.*|todo|\.\.\.)$/i';

    /**
     * The provider whose token format $value has, if any.
     */
    public static function tokenFormat(string $value): ?string
    {
        foreach (self::TOKEN_FORMATS as $label => $pattern) {
            if (preg_match($pattern, $value)) {
                return $label;
            }
        }

        return null;
    }

    /**
     * @param  list<string>  $allow  literal values that are fine to commit
     */
    public static function looksReal(string $value, array $allow = []): bool
    {
        if (strlen($value) < 8 || preg_match(self::PLACEHOLDER, $value) || in_array($value, $allow, true)) {
            return false;
        }

        // Sentences, config keys, URLs, identifiers (table names), validation
        // rules ("required|string") and casts ("encrypted:array") are not secrets.
        if (preg_match('/\s/', $value)
            || preg_match('#^(/|https?://|[a-z]+://)#i', $value)
            || preg_match('/^[a-z0-9_.\-]+$/', $value) && ! preg_match('/\d/', $value)
            || preg_match('/^[a-z_]+([:|][a-z0-9_,.:]*)+$/i', $value)
            || str_contains($value, '|')) {
            return false;
        }

        // Real secrets mix character classes or are long random strings.
        $classes = (int) preg_match('/[a-z]/', $value) + (int) preg_match('/[A-Z]/', $value)
            + (int) preg_match('/\d/', $value) + (int) preg_match('/[^a-zA-Z\d]/', $value);

        return ($classes >= 3 || strlen($value) >= 24) && self::entropy($value) >= 3.0;
    }

    /**
     * Shannon entropy in bits per character.
     */
    private static function entropy(string $value): float
    {
        $length = strlen($value);
        $entropy = 0.0;

        foreach (count_chars($value, 1) as $count) {
            $probability = $count / $length;
            $entropy -= $probability * log($probability, 2);
        }

        return $entropy;
    }
}

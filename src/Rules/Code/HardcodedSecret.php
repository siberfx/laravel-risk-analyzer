<?php

namespace Siberfx\RiskAnalyzer\Rules\Code;

use PhpParser\Node;
use PhpParser\Node\Expr;
use PhpParser\Node\Scalar\String_;
use Siberfx\RiskAnalyzer\Code\Ast;
use Siberfx\RiskAnalyzer\Code\FileScope;
use Siberfx\RiskAnalyzer\Severity;

final class HardcodedSecret extends AbstractCodeRule
{
    /** Provider token formats: label => pattern. */
    private const array TOKEN_FORMATS = [
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

    private const string SECRET_NAME = '/(^|_|-|\b)(password|passwd|pwd|secret|api_?key|apikey|access_?key|private_?key|client_?secret|auth_?token|access_?token|bearer|credentials?)($|_|-|\b)/i';

    private const string PLACEHOLDER = '/^(|null|none|secret|password|changeme|change-me|xxx+|\*+|your[-_ ].*|<.*>|\{.*\}|\$\{.*\}|example.*|test.*|dummy.*|placeholder.*|todo|\.\.\.)$/i';

    /** @var list<string> */
    private array $allow;

    /**
     * @param  list<string>  $allow  literal values that are fine to commit
     */
    public function __construct(array $allow = [])
    {
        $this->allow = $allow;
    }

    public function id(): string
    {
        return 'hardcoded-secret';
    }

    public function title(): string
    {
        return 'Hard-coded secret';
    }

    public function description(): string
    {
        return 'Credentials in source: known provider token formats (AWS, Stripe, GitHub, Slack, Google, OpenAI, Anthropic...), private keys, literal values assigned to password/secret/api_key names, and secrets used as env() fallbacks in config files.';
    }

    public function severity(): Severity
    {
        return Severity::Critical;
    }

    public function inspect(Node $node, FileScope $file): iterable
    {
        if ($node instanceof String_) {
            foreach (self::TOKEN_FORMATS as $label => $pattern) {
                if (preg_match($pattern, $node->value) && ! $this->isAllowed($node->value)) {
                    yield $this->report($file, $node, "{$label} committed in source.", null,
                        'Revoke and rotate the credential, then load it from the environment: env() in a config file, config() in code.',
                        ['type' => $label]);

                    return;
                }
            }

            return;
        }

        // 'password' => env('DB_PASSWORD', 's3cr3t-fallback')
        if (Ast::functionName($node) === 'env' && $node instanceof Expr\FuncCall) {
            $key = Ast::arg($node, 0, 'key');
            $default = Ast::arg($node, 1, 'default');

            if ($key instanceof String_ && $default instanceof String_ && preg_match(self::SECRET_NAME, $key->value)
                && ! preg_match('/_(TABLE|NAME|DRIVER|PATH|URL|HOST|PORT|USER|USERNAME|CONNECTION|STORE|EXPIRE|TIMEOUT|ALGO|ALGORITHM)$/i', $key->value)
                && $this->looksReal($default->value)) {
                yield $this->report($file, $node, "env('{$key->value}') falls back to a hard-coded secret.", Severity::High,
                    'Drop the default (or use null) so a missing variable fails loudly instead of using a committed secret.');
            }

            return;
        }

        // $password = '...'; ['api_key' => '...']; new Client(secret: '...')
        $pair = match (true) {
            $node instanceof Expr\Assign => [$node->var, $node->expr],
            $node instanceof Node\ArrayItem && $node->key !== null => [$node, $node->value],
            $node instanceof Node\Arg && $node->name !== null => [$node, $node->value],
            $node instanceof Node\PropertyItem => [$node, $node->default],
            $node instanceof Node\Const_ => [$node, $node->value],
            default => null,
        };

        if ($pair === null || ! $pair[1] instanceof String_) {
            return;
        }

        $name = match (true) {
            $pair[0] instanceof Node\PropertyItem, $pair[0] instanceof Node\Const_ => $pair[0]->name->toString(),
            default => Ast::targetName($pair[0]),
        };

        if ($name !== null && preg_match(self::SECRET_NAME, $name) && ! preg_match('/(_name|_field|_key_name|_path|_url|_type|_rule|_confirmation|_reset|_label|_route|_header)$/i', $name)
            && $this->looksReal($pair[1]->value)) {
            yield $this->report($file, $node, "A literal value is assigned to '{$name}'.", Severity::High,
                'Move the value to .env and read it through config().');
        }
    }

    private function looksReal(string $value): bool
    {
        if (strlen($value) < 8 || preg_match(self::PLACEHOLDER, $value) || $this->isAllowed($value)) {
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

        return ($classes >= 3 || strlen($value) >= 24) && $this->entropy($value) >= 3.0;
    }

    private function isAllowed(string $value): bool
    {
        return in_array($value, $this->allow, true);
    }

    /**
     * Shannon entropy in bits per character.
     */
    private function entropy(string $value): float
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

<?php

namespace Siberfx\RiskAnalyzer\Rules\Code;

use PhpParser\Node;
use PhpParser\Node\Expr;
use PhpParser\Node\Scalar\String_;
use Siberfx\RiskAnalyzer\Code\Ast;
use Siberfx\RiskAnalyzer\Code\FileScope;
use Siberfx\RiskAnalyzer\Severity;
use Siberfx\RiskAnalyzer\Support\Secrets;

final class HardcodedSecret extends AbstractCodeRule
{
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
            $label = Secrets::tokenFormat($node->value);

            if ($label !== null && ! in_array($node->value, $this->allow, true)) {
                yield $this->report($file, $node, "{$label} committed in source.", null,
                    'Revoke and rotate the credential, then load it from the environment: env() in a config file, config() in code.',
                    ['type' => $label]);
            }

            return;
        }

        // 'password' => env('DB_PASSWORD', 's3cr3t-fallback')
        if (Ast::functionName($node) === 'env' && $node instanceof Expr\FuncCall) {
            $key = Ast::arg($node, 0, 'key');
            $default = Ast::arg($node, 1, 'default');

            if ($key instanceof String_ && $default instanceof String_ && preg_match(Secrets::SECRET_NAME, $key->value)
                && ! preg_match('/_(TABLE|NAME|DRIVER|PATH|URL|HOST|PORT|USER|USERNAME|CONNECTION|STORE|EXPIRE|TIMEOUT|ALGO|ALGORITHM)$/i', $key->value)
                && Secrets::looksReal($default->value, $this->allow)) {
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

        if ($name !== null && preg_match(Secrets::SECRET_NAME, $name) && ! preg_match('/(_name|_field|_key_name|_path|_url|_type|_rule|_confirmation|_reset|_label|_route|_header)$/i', $name)
            && Secrets::looksReal($pair[1]->value, $this->allow)) {
            yield $this->report($file, $node, "A literal value is assigned to '{$name}'.", Severity::High,
                'Move the value to .env and read it through config().');
        }
    }
}

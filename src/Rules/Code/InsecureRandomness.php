<?php

namespace Siberfx\RiskAnalyzer\Rules\Code;

use PhpParser\Node;
use PhpParser\Node\Expr;
use PhpParser\Node\Stmt;
use Siberfx\RiskAnalyzer\Code\Ast;
use Siberfx\RiskAnalyzer\Code\FileScope;
use Siberfx\RiskAnalyzer\Finding;
use Siberfx\RiskAnalyzer\Severity;

final class InsecureRandomness extends AbstractCodeRule
{
    private const array WEAK = ['rand', 'mt_rand', 'uniqid', 'lcg_value', 'str_shuffle', 'array_rand', 'shuffle', 'microtime'];

    private const string SECURITY_NAME = '/token|secret|passw|otp|nonce|salt|api_?key|reset|verif|invite|code|pin\b|signature/i';

    public function id(): string
    {
        return 'insecure-randomness';
    }

    public function title(): string
    {
        return 'Predictable randomness for secrets';
    }

    public function description(): string
    {
        return 'Tokens, OTP codes, passwords and keys generated with rand(), mt_rand(), uniqid(), str_shuffle() and friends, whose output can be predicted.';
    }

    public function severity(): Severity
    {
        return Severity::High;
    }

    public function inspect(Node $node, FileScope $file): iterable
    {
        // $token = uniqid(); $user->otp = mt_rand(100000, 999999); ['reset_code' => rand()]
        $target = match (true) {
            $node instanceof Expr\Assign => [$node->var, $node->expr],
            $node instanceof Node\ArrayItem && $node->key !== null => [$node, $node->value],
            $node instanceof Node\Arg && $node->name !== null => [$node, $node->value],
            default => null,
        };

        if ($target !== null) {
            [$holder, $value] = $target;
            $name = Ast::targetName($holder);

            if ($name !== null && preg_match(self::SECURITY_NAME, $name) && ! $this->isMetadataName($name) && Ast::containsCall($value, self::WEAK)) {
                yield $this->finding($file, $node, "'{$name}' is generated with a predictable random source.");
            }

            return;
        }

        // function generateOtp() { return mt_rand(...); }
        if ($node instanceof Stmt\Return_ && $node->expr !== null && Ast::containsCall($node->expr, self::WEAK)) {
            $function = $this->enclosingFunctionName($node);

            if ($function !== null && preg_match(self::SECURITY_NAME, $function)) {
                yield $this->finding($file, $node, "{$function}() returns a value from a predictable random source.");
            }
        }
    }

    private function finding(FileScope $file, Node $node, string $message): Finding
    {
        return $this->report($file, $node, $message, null,
            'Use random_int(), random_bytes() or Str::random() / Str::password(), which use a CSPRNG.');
    }

    private function isMetadataName(string $name): bool
    {
        return preg_match('/(_at|_count|_length|_type|_id|expires|expiry|status|color|postal|zip|country|currency|qr)/i', $name) === 1;
    }

    private function enclosingFunctionName(Node $node): ?string
    {
        while (($node = $node->getAttribute('parent')) instanceof Node) {
            if ($node instanceof Stmt\ClassMethod || $node instanceof Stmt\Function_) {
                return $node->name->toString();
            }
        }

        return null;
    }
}

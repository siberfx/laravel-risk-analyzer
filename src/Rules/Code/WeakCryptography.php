<?php

namespace Siberfx\RiskAnalyzer\Rules\Code;

use PhpParser\Node;
use PhpParser\Node\Expr;
use PhpParser\Node\Scalar\String_;
use Siberfx\RiskAnalyzer\Code\Ast;
use Siberfx\RiskAnalyzer\Code\FileScope;
use Siberfx\RiskAnalyzer\Severity;

final class WeakCryptography extends AbstractCodeRule
{
    private const string SECRET_NAME = '/pass(word|wd|phrase)?|pwd|secret|pin\b/i';

    public function id(): string
    {
        return 'weak-cryptography';
    }

    public function title(): string
    {
        return 'Weak cryptography';
    }

    public function description(): string
    {
        return 'Passwords hashed with fast digests (md5, sha1, hash("sha256") ...) instead of Hash::make(), ECB mode or broken ciphers (DES, RC4) in openssl_encrypt(), and string comparison of secrets with == instead of hash_equals().';
    }

    public function severity(): Severity
    {
        return Severity::High;
    }

    public function inspect(Node $node, FileScope $file): iterable
    {
        $function = Ast::functionName($node);

        if (in_array($function, ['md5', 'sha1', 'crc32', 'hash', 'md5_file'], true) && $node instanceof Expr\FuncCall) {
            $value = $function === 'hash' ? Ast::arg($node, 1, 'data') : Ast::arg($node, 0, 'string');

            if ($value !== null && $this->namesSecret($value)) {
                yield $this->report($file, $node, "A password-like value is hashed with {$function}(), which is fast to brute-force.", null,
                    'Use Hash::make() / password_hash() for passwords and Hash::check() to verify them.');
            }

            return;
        }

        if (in_array($function, ['openssl_encrypt', 'openssl_decrypt'], true) && $node instanceof Expr\FuncCall) {
            $cipher = Ast::arg($node, 1, 'cipher_algo');

            if ($cipher instanceof String_ && preg_match('/ecb|^des|rc4|rc2|bf-|blowfish/i', $cipher->value)) {
                yield $this->report($file, $node, "openssl cipher '{$cipher->value}' is broken or leaks patterns.", null,
                    'Use Crypt::encryptString() (AES-256-GCM/CBC with a MAC) or aes-256-gcm with a random IV.');
            }

            return;
        }

        if (str_starts_with((string) $function, 'mcrypt_')) {
            yield $this->report($file, $node, 'mcrypt was removed from PHP and is not maintained.', null, 'Use Crypt or the openssl/sodium extensions.');

            return;
        }

        // $token == $request->input('token'): timing-unsafe comparison of a secret.
        if (($node instanceof Expr\BinaryOp\Equal || $node instanceof Expr\BinaryOp\Identical
            || $node instanceof Expr\BinaryOp\NotEqual || $node instanceof Expr\BinaryOp\NotIdentical)
            && $this->comparesSecretToInput($node, $file)) {
            yield $this->report($file, $node, 'A secret is compared to request input with ==/===, which leaks timing information.', Severity::Medium,
                'Compare secrets with hash_equals($known, $input).');
        }
    }

    private function namesSecret(Expr $value): bool
    {
        $name = match (true) {
            $value instanceof Expr\MethodCall, $value instanceof Expr\StaticCall => $this->firstStringArg($value),
            $value instanceof Expr\FuncCall && Ast::functionName($value) === 'request' => $this->firstStringArg($value),
            default => Ast::targetName($value),
        };

        return $name !== null && preg_match(self::SECRET_NAME, $name) === 1 && ! preg_match('/reset|confirm.*token|_at$/i', $name);
    }

    private function comparesSecretToInput(Expr\BinaryOp $node, FileScope $file): bool
    {
        foreach ([[$node->left, $node->right], [$node->right, $node->left]] as [$known, $input]) {
            $name = Ast::targetName($known);

            if ($name !== null && preg_match('/(secret|signature|api_?key|webhook_?token|hmac)/i', $name) && $file->taint->isTainted($input)) {
                return true;
            }
        }

        return false;
    }

    private function firstStringArg(Expr\CallLike $call): ?string
    {
        $arg = Ast::arg($call, 0);

        return $arg instanceof String_ ? $arg->value : null;
    }
}

<?php

namespace Siberfx\RiskAnalyzer\Rules\Code;

use PhpParser\Node;
use PhpParser\Node\Expr;
use Siberfx\RiskAnalyzer\Code\Ast;
use Siberfx\RiskAnalyzer\Code\FileScope;
use Siberfx\RiskAnalyzer\Severity;

final class DisabledTlsVerification extends AbstractCodeRule
{
    public function id(): string
    {
        return 'tls-verification-disabled';
    }

    public function title(): string
    {
        return 'TLS verification disabled';
    }

    public function description(): string
    {
        return 'HTTP clients that skip certificate checks: Http::withoutVerifying(), Guzzle "verify" => false, CURLOPT_SSL_VERIFYPEER/VERIFYHOST off, stream contexts with verify_peer false.';
    }

    public function severity(): Severity
    {
        return Severity::High;
    }

    public function inspect(Node $node, FileScope $file): iterable
    {
        $message = match (true) {
            Ast::methodName($node) === 'withoutverifying' => 'Http::withoutVerifying() turns off certificate verification.',
            $node instanceof Node\ArrayItem && in_array(Ast::targetName($node), ['verify', 'verify_peer', 'verify_peer_name'], true)
                && Ast::isFalse($node->value) && ! $file->isConfigFile() => "The '".Ast::targetName($node)."' option turns off certificate verification.",
            Ast::functionName($node) === 'curl_setopt' && $this->disablesCurlCheck($node) => 'curl is told not to verify the peer certificate.',
            default => null,
        };

        if ($message !== null) {
            yield $this->report($file, $node, $message, null,
                'Keep verification on. For private CAs point "verify" (or CURLOPT_CAINFO) at the CA bundle instead.');
        }
    }

    private function disablesCurlCheck(Node $node): bool
    {
        if (! $node instanceof Expr\FuncCall) {
            return false;
        }

        $option = Ast::arg($node, 1);

        return (Ast::isConst($option, 'CURLOPT_SSL_VERIFYPEER') || Ast::isConst($option, 'CURLOPT_SSL_VERIFYHOST'))
            && Ast::isFalse(Ast::arg($node, 2));
    }
}

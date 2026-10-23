<?php

namespace Siberfx\RiskAnalyzer\Rules\Code;

use PhpParser\Node;
use PhpParser\Node\Expr;
use Siberfx\RiskAnalyzer\Code\Ast;
use Siberfx\RiskAnalyzer\Code\FileScope;
use Siberfx\RiskAnalyzer\Severity;

final class ServerSideRequestForgery extends AbstractCodeRule
{
    private const array HTTP_METHODS = ['get', 'post', 'put', 'patch', 'delete', 'head', 'send', 'request', 'requestasync', 'baseurl'];

    public function id(): string
    {
        return 'ssrf';
    }

    public function title(): string
    {
        return 'Server-side request forgery';
    }

    public function description(): string
    {
        return 'Outgoing HTTP requests (Http facade, Guzzle, curl, file_get_contents/fopen of URLs) whose URL comes from request input, letting callers reach internal services or cloud metadata endpoints.';
    }

    public function severity(): Severity
    {
        return Severity::High;
    }

    public function inspect(Node $node, FileScope $file): iterable
    {
        $url = match (true) {
            $this->isHttpClientCall($node) => $this->urlArgument($node),
            in_array(Ast::functionName($node), ['curl_init'], true) => Ast::arg($node, 0, 'url'),
            Ast::functionName($node) === 'curl_setopt' && Ast::isConst(Ast::arg($node, 1), 'CURLOPT_URL') => Ast::arg($node, 2),
            in_array(Ast::functionName($node), ['get_headers', 'getimagesize'], true) => Ast::arg($node, 0),
            default => null,
        };

        if ($url !== null && $file->taint->isTainted($url)) {
            yield $this->report($file, $node, 'An outgoing HTTP request is sent to a URL taken from request input.', null,
                'Allow-list the hosts you call, resolve the host and reject private, loopback and link-local addresses (169.254.169.254), and disable redirects.');
        }
    }

    private function isHttpClientCall(Node $node): bool
    {
        $method = Ast::methodName($node);

        if (! in_array($method, self::HTTP_METHODS, true)) {
            return false;
        }

        if ($node instanceof Expr\StaticCall) {
            return Ast::className($node) === 'Http';
        }

        if (! $node instanceof Expr\MethodCall) {
            return false;
        }

        $root = Ast::chainRoot($node);

        // Http::withToken(...)->get($url), (new Client)->get($url), $this->http->get($url), $guzzle->request('GET', $url)
        return Ast::chainRootClass($node) === 'Http'
            || ($root instanceof Expr\New_ && in_array(Ast::className($root), ['Client', 'PendingRequest'], true))
            || ($root instanceof Expr\Variable && is_string($root->name) && preg_match('/^(http|client|guzzle)/i', $root->name) === 1)
            || ($node->var instanceof Expr\PropertyFetch && preg_match('/^(http|client|guzzle)/i', (string) Ast::targetName($node->var)) === 1);
    }

    private function urlArgument(Node $node): ?Expr
    {
        /** @var Expr\CallLike $node */
        return in_array(Ast::methodName($node), ['send', 'request', 'requestasync'], true)
            ? Ast::arg($node, 1, 'uri') ?? Ast::arg($node, 1, 'url')
            : Ast::arg($node, 0, 'url');
    }
}

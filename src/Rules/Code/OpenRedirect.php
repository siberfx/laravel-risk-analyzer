<?php

namespace Siberfx\RiskAnalyzer\Rules\Code;

use PhpParser\Node;
use PhpParser\Node\Expr;
use Siberfx\RiskAnalyzer\Code\Ast;
use Siberfx\RiskAnalyzer\Code\FileScope;
use Siberfx\RiskAnalyzer\Severity;

final class OpenRedirect extends AbstractCodeRule
{
    public function id(): string
    {
        return 'open-redirect';
    }

    public function title(): string
    {
        return 'Open redirect';
    }

    public function description(): string
    {
        return 'Redirects whose target comes from request input: Laravel redirect(), redirect()->to()/away(), Redirect::to(); Symfony new RedirectResponse() and $this->redirect(); Yii2 $this->redirect() and Yii::$app->response->redirect(); header("Location: ...").';
    }

    public function severity(): Severity
    {
        return Severity::High;
    }

    public function inspect(Node $node, FileScope $file): iterable
    {
        $target = match (true) {
            Ast::functionName($node) === 'redirect' => Ast::arg($node, 0, 'to'),
            Ast::functionName($node) === 'header' => $this->locationHeader($node),
            $node instanceof Expr\StaticCall && Ast::className($node) === 'Redirect'
                && in_array(Ast::methodName($node), ['to', 'away'], true) => Ast::arg($node, 0, 'path'),
            $node instanceof Expr\MethodCall && in_array(Ast::methodName($node), ['to', 'away', 'redirectto'], true)
                && $this->isRedirector($node->var) => Ast::arg($node, 0, 'path'),
            // Symfony: new RedirectResponse($url); Symfony/Yii2 controllers: $this->redirect($url); Yii2: Yii::$app->response->redirect($url)
            $node instanceof Expr\New_ && in_array(Ast::className($node), ['RedirectResponse', 'TrustedRedirectResponse'], true) => Ast::arg($node, 0, 'url'),
            $node instanceof Expr\MethodCall && Ast::methodName($node) === 'redirect' && $this->isControllerOrResponse($node->var) => Ast::arg($node, 0, 'url'),
            default => null,
        };

        if ($target !== null && $file->taint->isTainted($target) && ! $this->isCurrentUrl($target, $file)) {
            yield $this->report($file, $node, 'The redirect target comes from request input.', null,
                'Redirect to named routes, or validate the URL host against an allow-list (or keep it relative with str_starts_with($url, \'/\') && ! str_starts_with($url, \'//\')).');
        }
    }

    /**
     * redirect($request->fullUrl()) sends the user back to this app.
     */
    private function isCurrentUrl(Expr $target, FileScope $file): bool
    {
        return ($target instanceof Expr\MethodCall || $target instanceof Expr\NullsafeMethodCall)
            && in_array(Ast::methodName($target), ['fullurl', 'url', 'path', 'fullurlwithquery', 'fullurlwithoutquery', 'geturi', 'geturl', 'getpathinfo'], true)
            && $file->taint->isRequest($target->var);
    }

    private function isControllerOrResponse(Expr $node): bool
    {
        return ($node instanceof Expr\Variable && $node->name === 'this')
            || Ast::targetName($node) === 'response'
            || Ast::methodName($node) === 'getresponse';
    }

    private function isRedirector(Expr $node): bool
    {
        return (Ast::functionName($node) === 'redirect' && $node instanceof Expr\FuncCall && $node->getArgs() === [])
            || (Ast::functionName($node) === 'response' && $node instanceof Expr\FuncCall)
            || ($node instanceof Expr\StaticCall && Ast::className($node) === 'Response');
    }

    private function locationHeader(Node $node): ?Expr
    {
        if (! $node instanceof Expr\FuncCall) {
            return null;
        }

        $header = Ast::arg($node, 0, 'header');
        $first = match (true) {
            $header instanceof Expr\BinaryOp\Concat => $header->left,
            $header instanceof Node\Scalar\InterpolatedString => $header->parts[0] ?? null,
            default => null,
        };

        $text = $first instanceof Node\Scalar\String_ || $first instanceof Node\InterpolatedStringPart ? $first->value : '';

        return stripos(ltrim($text), 'location:') === 0 ? $header : null;
    }
}

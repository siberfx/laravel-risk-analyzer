<?php

namespace Siberfx\RiskAnalyzer\Rules\Code;

use PhpParser\Node;
use PhpParser\Node\Expr;
use Siberfx\RiskAnalyzer\Code\Ast;
use Siberfx\RiskAnalyzer\Code\FileScope;
use Siberfx\RiskAnalyzer\Severity;

final class PathTraversal extends AbstractCodeRule
{
    /** Function name => position of the path argument. */
    private const array FUNCTIONS = [
        'file_get_contents' => 0, 'file_put_contents' => 0, 'fopen' => 0, 'file' => 0, 'readfile' => 0,
        'unlink' => 0, 'rmdir' => 0, 'mkdir' => 0, 'copy' => 1, 'rename' => 1, 'move_uploaded_file' => 1,
        'parse_ini_file' => 0, 'simplexml_load_file' => 0, 'scandir' => 0, 'glob' => 0, 'touch' => 0,
        'chmod' => 0, 'symlink' => 1, 'opendir' => 0,
    ];

    /** Storage / File facade and response() methods taking a path first. */
    private const array PATH_METHODS = [
        'get', 'put', 'putfile', 'putfileas', 'download', 'delete', 'exists', 'path', 'readstream', 'writestream',
        'move', 'copy', 'url', 'temporaryurl', 'append', 'prepend', 'json', 'lines', 'deletedirectory', 'file',
        'storeas', 'storepubliclyas', 'response',
    ];

    public function id(): string
    {
        return 'path-traversal';
    }

    public function title(): string
    {
        return 'Path traversal';
    }

    public function description(): string
    {
        return 'Filesystem access (file functions, Storage/File facades, response()->download(), UploadedFile::storeAs()) with a path or file name taken from request input, including client-supplied upload names.';
    }

    public function severity(): Severity
    {
        return Severity::High;
    }

    public function inspect(Node $node, FileScope $file): iterable
    {
        $function = Ast::functionName($node);

        $path = match (true) {
            $function !== null && array_key_exists($function, self::FUNCTIONS) => Ast::arg($node, self::FUNCTIONS[$function]),
            $this->isPathMethod($node) => $this->pathArgument($node),
            default => null,
        };

        if ($path !== null && $file->taint->isTainted($path)) {
            yield $this->report($file, $node, 'A filesystem path is built from request input.', null,
                'Never use client file names: store uploads with ->store() (random name) and look files up by id. When a name is required, take basename() and check realpath() stays inside the intended directory.');
        }
    }

    private function isPathMethod(Node $node): bool
    {
        $method = Ast::methodName($node);

        if (! in_array($method, self::PATH_METHODS, true)) {
            return false;
        }

        if ($node instanceof Expr\StaticCall) {
            return in_array(Ast::className($node), ['Storage', 'File'], true);
        }

        if (! $node instanceof Expr\MethodCall) {
            return false;
        }

        // Storage::disk('s3')->get($path), response()->download($path), $file->storeAs($dir, $name)
        return in_array(Ast::chainRootClass($node), ['Storage', 'File'], true)
            || (in_array($method, ['download', 'file'], true) && Ast::functionName($node->var) === 'response')
            || in_array($method, ['storeas', 'storepubliclyas', 'move'], true);
    }

    private function pathArgument(Node $node): ?Expr
    {
        /** @var Expr\CallLike $node */
        return match (Ast::methodName($node)) {
            // storeAs($path, $name) / move($directory, $name): the name is the dangerous part.
            'storeas', 'storepubliclyas' => $node instanceof Expr\MethodCall && Ast::chainRootClass($node) !== 'Storage'
                ? (Ast::arg($node, 1, 'name') ?? Ast::arg($node, 0, 'path'))
                : Ast::arg($node, 0, 'path'),
            'move' => $node instanceof Expr\MethodCall && Ast::chainRootClass($node) === null
                ? Ast::arg($node, 1, 'name')
                : Ast::arg($node, 0),
            default => Ast::arg($node, 0, 'path') ?? Ast::arg($node, 0, 'file'),
        };
    }
}

<?php

namespace Siberfx\RiskAnalyzer\Rules\Code;

use PhpParser\Node;
use PhpParser\Node\Expr;
use Siberfx\RiskAnalyzer\Code\Ast;
use Siberfx\RiskAnalyzer\Code\FileScope;
use Siberfx\RiskAnalyzer\Severity;

final class CommandInjection extends AbstractCodeRule
{
    private const array SHELL_FUNCTIONS = ['exec', 'shell_exec', 'system', 'passthru', 'proc_open', 'popen', 'pcntl_exec'];

    public function id(): string
    {
        return 'command-injection';
    }

    public function title(): string
    {
        return 'Command injection';
    }

    public function description(): string
    {
        return 'Shell commands (exec, shell_exec, system, backticks, Process::run, Process::fromShellCommandline) built from request input or runtime strings. Array-form Process commands are not reported.';
    }

    public function severity(): Severity
    {
        return Severity::Critical;
    }

    public function inspect(Node $node, FileScope $file): iterable
    {
        $command = match (true) {
            in_array(Ast::functionName($node), self::SHELL_FUNCTIONS, true) => Ast::arg($node, 0, 'command'),
            $node instanceof Expr\ShellExec => new Node\Scalar\InterpolatedString($node->parts),
            $this->isProcessShellCall($node) => Ast::arg($node, 0, 'command'),
            default => null,
        };

        // Array commands are passed to the OS without a shell.
        if ($command === null || $command instanceof Expr\Array_) {
            return;
        }

        $severity = $this->sinkSeverity($file, $command);

        if ($severity !== null) {
            yield $this->report($file, $node, $severity === $this->severity()
                ? 'Request input flows into a shell command.'
                : 'A shell command is built from a runtime string.',
                $severity,
                'Pass the command as an array (Process::run([\'convert\', $path])) so no shell is involved, or wrap every runtime value in escapeshellarg().',
            );
        }
    }

    private function isProcessShellCall(Node $node): bool
    {
        $method = Ast::methodName($node);

        if ($node instanceof Expr\StaticCall) {
            return in_array(Ast::className($node), ['Process', 'Symfony\Component\Process\Process'], true)
                && in_array($method, ['run', 'start', 'fromshellcommandline', 'command', 'pipe'], true);
        }

        // Process::timeout(10)->run($command)
        return in_array($method, ['run', 'start', 'command'], true) && Ast::chainRootClass($node) === 'Process';
    }
}

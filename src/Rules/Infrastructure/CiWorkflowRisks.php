<?php

namespace Siberfx\RiskAnalyzer\Rules\Infrastructure;

use Siberfx\RiskAnalyzer\Infrastructure\InfrastructureFile;
use Siberfx\RiskAnalyzer\Infrastructure\ShellChecks;
use Siberfx\RiskAnalyzer\ScanContext;
use Siberfx\RiskAnalyzer\Severity;

final class CiWorkflowRisks extends AbstractInfrastructureRule
{
    /** Event fields anyone opening an issue or pull request controls. */
    private const string UNTRUSTED = '/\$\{\{\s*(github\.head_ref|github\.event\.[\w.\[\]*\-]*\.?(?:title|body|message|name|ref|label|email|head_ref|default_branch|page_name|text|description))\s*\}\}/';

    public function id(): string
    {
        return 'ci-workflow-risks';
    }

    public function title(): string
    {
        return 'GitHub Actions workflow risks';
    }

    public function description(): string
    {
        return 'GitHub Actions workflows: issue and pull request fields (titles, bodies, branch names, commit messages) expanded inside run: or github-script, which lets anyone run commands in CI (high); pull_request_target workflows that check out the pull request\'s code (high); permissions: write-all; third-party actions not pinned to a commit SHA (low); and the shell checks on run: steps.';
    }

    public function severity(): Severity
    {
        return Severity::High;
    }

    protected function kinds(): array
    {
        return [InfrastructureFile::WORKFLOW];
    }

    protected function inspect(InfrastructureFile $file, ScanContext $context): iterable
    {
        foreach ($this->scriptLines($file) as $line => $text) {
            if (preg_match(self::UNTRUSTED, $text, $match)) {
                yield $this->report($file, $line, "\${{ {$match[1]} }} is expanded inside a script; whoever opens the issue or pull request controls it and can run commands in CI.", Severity::High,
                    'Pass it through an environment variable and quote it: env: TITLE: ${{ '.$match[1].' }} then run: echo "$TITLE".');
            }
        }

        if (preg_match('/^\s*(?:on:\s*\[?[^\n]*\bpull_request_target\b|pull_request_target\s*:|-\s*pull_request_target\b)/m', $file->code)) {
            foreach ($file->matches('/^\s*ref:\s*["\']?\$\{\{\s*(github\.event\.pull_request\.head\.(?:sha|ref)|github\.head_ref)\s*\}\}/m') as $match) {
                yield $this->report($file, $match['line'], 'A pull_request_target workflow checks out the pull request\'s code, running untrusted code with access to secrets and a write token.', Severity::High,
                    'Use the pull_request trigger for building and testing contributions; keep pull_request_target for labelling and commenting without checking out the head.');
            }
        }

        foreach ($file->matches('/^\s*permissions:\s*["\']?write-all\b/m') as $match) {
            yield $this->report($file, $match['line'], 'permissions: write-all gives every step a token that can push code and create releases.', Severity::Medium,
                'Grant only what the job needs, e.g. permissions: contents: read.');
        }

        $unpinned = [];

        foreach ($file->matches('/^\s*-?\s*uses:\s*["\']?([\w.\-]+)\/([\w.\-\/]+)@([^\s"\'#]+)/m') as $match) {
            [, $owner, $repository, $ref] = $match['groups'];

            if (! in_array(strtolower($owner), ['actions', 'github'], true) && ! preg_match('/^[0-9a-f]{40}$/', $ref)) {
                $unpinned[$owner.'/'.$repository.'@'.$ref] ??= $match['line'];
            }
        }

        if ($unpinned !== []) {
            // One finding per workflow, anchored on the file so baselines survive version bumps.
            $actions = array_keys($unpinned);

            yield $this->finding(
                (count($actions) === 1 ? "{$actions[0]} is" : count($actions).' third-party actions are ('.implode(', ', array_slice($actions, 0, 5)).(count($actions) > 5 ? ', …' : '').')')
                    .' not pinned to a commit; whoever controls the tag can change the code your workflow runs.',
                Severity::Low,
                'Pin each to its full commit SHA and keep the version in a comment (uses: owner/action@<sha> # v2); Dependabot keeps pinned actions updated.',
                $file->path,
                reset($unpinned),
                'unpinned-actions',
            );
        }

        foreach (ShellChecks::inspect($file, $this->allow) as $issue) {
            yield $this->report($file, $issue['line'], $issue['message'], $issue['severity'], $issue['remediation']);
        }
    }

    /**
     * Lines of run: steps and actions/github-script script: inputs.
     *
     * @return array<int, string> line number => text
     */
    private function scriptLines(InfrastructureFile $file): array
    {
        $lines = $file->lines();
        $scripts = [];

        foreach ($lines as $index => $text) {
            if (! preg_match('/^(\s*)(?:-\s+)?(run|script):\s*(.*)$/', $text, $match)) {
                continue;
            }

            if (! preg_match('/^[|>][+\-]?\d*\s*$/', $match[3])) {
                $scripts[$index + 1] = $match[3];

                continue;
            }

            $indent = strlen($match[1]);

            for ($next = $index + 1; $next < count($lines); $next++) {
                if (trim($lines[$next]) !== '' && strlen($lines[$next]) - strlen(ltrim($lines[$next])) <= $indent) {
                    break;
                }

                $scripts[$next + 1] = $lines[$next];
            }
        }

        return $scripts;
    }
}

<?php

namespace Siberfx\RiskAnalyzer\Support;

use RuntimeException;
use Symfony\Component\Process\Process;

/**
 * Files changed compared to a git ref, plus uncommitted and untracked files.
 */
final class ChangedFiles
{
    /**
     * @return list<string> relative paths
     */
    public static function since(string $basePath, ?string $ref = null): array
    {
        $commands = [
            ['git', 'diff', '--name-only', '--diff-filter=ACMR', 'HEAD'],
            ['git', 'ls-files', '--others', '--exclude-standard'],
        ];

        if ($ref !== null && $ref !== '') {
            $commands[] = ['git', 'diff', '--name-only', '--diff-filter=ACMR', $ref.'...HEAD'];
        }

        $files = [];

        foreach ($commands as $command) {
            $process = new Process($command, $basePath, timeout: 60);
            $process->run();

            if (! $process->isSuccessful()) {
                throw new RuntimeException('git failed: '.trim($process->getErrorOutput() ?: $process->getOutput()));
            }

            foreach (preg_split('/\R/', trim($process->getOutput())) ?: [] as $file) {
                if ($file !== '') {
                    $files[str_replace('\\', '/', $file)] = true;
                }
            }
        }

        return array_keys($files);
    }
}

<?php

namespace Siberfx\RiskAnalyzer\Rules\Runtime;

use Siberfx\RiskAnalyzer\Category;
use Siberfx\RiskAnalyzer\Rules\AbstractProjectRule;
use Siberfx\RiskAnalyzer\ScanContext;
use Siberfx\RiskAnalyzer\Severity;
use Siberfx\RiskAnalyzer\Support\PhpIni;

final class PhpConfiguration extends AbstractProjectRule
{
    public function id(): string
    {
        return 'php-configuration';
    }

    public function title(): string
    {
        return 'Unsafe php.ini settings';
    }

    public function description(): string
    {
        return 'php.ini settings in production: allow_url_include, display_errors, display_startup_errors, expose_php, log_errors and zend.assertions. Read from the php.ini files (the PHP-FPM ones next to the CLI ones on Debian/Ubuntu, or risk-analyzer.php.ini_files) plus public/.user.ini and .htaccess, because ini_get() only shows the CLI\'s values.';
    }

    public function category(): Category
    {
        return Category::Runtime;
    }

    public function severity(): Severity
    {
        return Severity::Medium;
    }

    public function run(ScanContext $context): iterable
    {
        if (! $context->production) {
            return;
        }

        $files = $context->config('php.ini_files');
        $ini = PhpIni::read($context, is_array($files) && $files !== [] ? array_values(array_map('strval', $files)) : null);
        $note = $ini->cliOnly
            ? ' These values come from the CLI\'s php.ini; if PHP-FPM loads another one, list it in risk-analyzer.php.ini_files.'
            : '';

        // [setting, PHP's built-in default, on is bad, severity, what it means, fix]
        $checks = [
            ['allow_url_include', false, true, Severity::High, 'include/require can load code from remote URLs, turning any file-inclusion bug into remote code execution.', 'Set allow_url_include = Off.'],
            ['display_errors', true, true, Severity::Medium, 'errors that happen before or outside Laravel\'s handler (parse errors, fatal errors) are shown to visitors with file paths.', 'Set display_errors = Off and log_errors = On.'],
            ['display_startup_errors', true, true, Severity::Low, 'PHP startup errors are shown to visitors.', 'Set display_startup_errors = Off.'],
            ['expose_php', true, true, Severity::Low, 'every response carries X-Powered-By with the exact PHP version.', 'Set expose_php = Off.'],
            ['log_errors', true, false, Severity::Low, 'PHP errors outside Laravel are not logged anywhere.', 'Set log_errors = On.'],
        ];

        foreach ($checks as [$name, $default, $badWhenOn, $severity, $meaning, $fix]) {
            if ($ini->enabled($name, $default) !== $badWhenOn) {
                continue;
            }

            $state = $badWhenOn ? 'on' : 'off';

            yield $this->finding("{$name} is {$state} ({$ini->source($name)}), so {$meaning}", $severity, $fix.$note,
                anchor: 'php.'.$name, meta: ['setting' => $name, 'source' => $ini->source($name), 'files' => $ini->files]);
        }

        if ($ini->value('zend.assertions', '1') === '1') {
            yield $this->finding("zend.assertions is 1 ({$ini->source('zend.assertions')}), so assert() calls are compiled and run in production.", Severity::Low,
                'Set zend.assertions = -1 in production.'.$note, anchor: 'php.zend.assertions',
                meta: ['setting' => 'zend.assertions', 'source' => $ini->source('zend.assertions'), 'files' => $ini->files]);
        }
    }
}

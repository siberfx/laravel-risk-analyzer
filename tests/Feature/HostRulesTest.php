<?php

use Siberfx\RiskAnalyzer\Finding;
use Siberfx\RiskAnalyzer\RiskAnalyzer;
use Siberfx\RiskAnalyzer\Rules\Filesystem\FilePermissions;
use Siberfx\RiskAnalyzer\ScanContext;

const PRODUCTION_INI = "[PHP]\ndisplay_errors = Off\ndisplay_startup_errors = Off\nexpose_php = Off\nallow_url_include = Off\nlog_errors = On\n\n[Assertion]\nzend.assertions = -1\n";

/**
 * @return list<array{string, string}> severity, message
 */
function hostFindings(string $rule, string $root, bool $production = true): array
{
    app()->forgetInstance(RiskAnalyzer::class);

    return collect(app(RiskAnalyzer::class)->scan(only: [$rule], production: $production, baseline: false, basePath: $root)->findings)
        ->map(fn (Finding $finding) => [$finding->severity->value, $finding->message])
        ->all();
}

it('accepts production php.ini settings', function () {
    $root = $this->project(['php.ini' => PRODUCTION_INI]);
    config()->set('risk-analyzer.php.ini_files', [$root.'/php.ini']);

    expect(hostFindings('php-configuration', $root))->toBe([]);
});

it('falls back to PHP\'s development-friendly defaults when php.ini sets nothing', function () {
    $root = $this->project(['php.ini' => "; empty\n"]);
    config()->set('risk-analyzer.php.ini_files', [$root.'/php.ini']);
    $default = 'PHP default, no php.ini sets it';

    expect(hostFindings('php-configuration', $root))->toBe([
        ['medium', "display_errors is on ({$default}), so errors that happen before or outside Laravel's handler (parse errors, fatal errors) are shown to visitors with file paths."],
        ['low', "display_startup_errors is on ({$default}), so PHP startup errors are shown to visitors."],
        ['low', "expose_php is on ({$default}), so every response carries X-Powered-By with the exact PHP version."],
        ['low', "zend.assertions is 1 ({$default}), so assert() calls are compiled and run in production."],
    ])->and(hostFindings('php-configuration', $root, production: false))->toBe([]);
});

it('applies FPM pool overrides, .user.ini and .htaccess on top of php.ini', function () {
    $root = $this->project([
        'php.ini' => PRODUCTION_INI,
        'www.conf' => "[www]\nuser = www-data\nphp_admin_flag[allow_url_include] = on\nphp_value[log_errors] = 0\n",
        'public/.user.ini' => "display_errors = stderr\n",
        // expose_php cannot be changed per directory, so this line has no effect.
        'public/.htaccess' => "<IfModule mod_php.c>\n    php_flag expose_php On\n    php_value zend.assertions 1\n</IfModule>\n",
    ]);
    config()->set('risk-analyzer.php.ini_files', [$root.'/php.ini', $root.'/www.conf']);

    expect(hostFindings('php-configuration', $root))->toBe([
        ['high', "allow_url_include is on ({$root}/www.conf), so include/require can load code from remote URLs, turning any file-inclusion bug into remote code execution."],
        ['medium', "display_errors is on (public/.user.ini), so errors that happen before or outside Laravel's handler (parse errors, fatal errors) are shown to visitors with file paths."],
        ['low', "log_errors is off ({$root}/www.conf), so PHP errors outside Laravel are not logged anywhere."],
        ['low', 'zend.assertions is 1 (public/.htaccess), so assert() calls are compiled and run in production.'],
    ]);
});

it('flags secrets and writable folders other users can reach', function () {
    $root = $this->project(['.env' => 'APP_KEY=x', 'auth.json' => '{}', 'storage/oauth-private.key' => 'key', 'bootstrap/cache/.gitignore' => '*']);
    $modes = ['.env' => 0o644, 'auth.json' => 0o666, 'storage/oauth-private.key' => 0o600, 'storage' => 0o777, 'bootstrap/cache' => 0o775];
    $rule = new FilePermissions(fn (string $path) => $modes[substr(str_replace('\\', '/', $path), strlen($root) + 1)] ?? false);

    $findings = collect($rule->run(new ScanContext(app(), $root, (array) config('risk-analyzer'))))
        ->map(fn (Finding $finding) => [$finding->severity->value, $finding->message])->all();

    expect($findings)->toBe([
        ['medium', '.env is readable by every user on the machine (mode 644).'],
        ['high', 'auth.json is writable by every user on the machine (mode 666).'],
        ['low', 'storage is writable by every user on the machine (mode 777).'],
    ]);
});

it('checks folders linked into public/ for executable and secret files', function () {
    $root = $this->project([
        'public/index.php' => '<?php',
        'public/storage/.keep' => '',
        'storage/app/public/.gitignore' => "*\n!.gitignore\n",
        'storage/app/public/avatars/photo.jpg' => 'jpg',
        'storage/app/public/avatars/shell.php5' => '<?php system($_GET["c"]);',
        'storage/app/public/exports/backup.sql.gz' => 'dump',
        'storage/app/public/exports/report.zip' => 'zip',
        'storage/app/public/logs/import.log' => 'log',
        'storage/app/public/unlinked-check.txt' => 'txt',
    ]);
    config()->set('filesystems.links', [$root.'/public/storage' => $root.'/storage/app/public']);

    $findings = collect(hostFindings('public-exposure', $root))->sortBy(1)->values()->all();

    expect($findings)->toBe([
        ['critical', 'storage/app/public/avatars/shell.php5 is a PHP file the web server may execute, served at /storage/avatars/shell.php5.'],
        ['critical', 'storage/app/public/exports/backup.sql.gz is a database dump, served at /storage/exports/backup.sql.gz.'],
        ['medium', 'storage/app/public/logs/import.log is a log file, served at /storage/logs/import.log.'],
    ]);

    config()->set('filesystems.links', [$root.'/public/missing-link' => $root.'/storage/app/public']);
    expect(hostFindings('public-exposure', $root))->toBe([]);
});

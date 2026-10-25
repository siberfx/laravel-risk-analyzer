# Risk Analyzer for plain PHP

Risk Analyzer scans PHP projects that don't use a framework (or use one it has no special support for): pages, includes, classes, CLI scripts, JavaScript, Dockerfiles, compose files, shell scripts, Makefiles, GitHub Actions workflows, `composer.lock`/`package-lock.json` advisories and committed secrets. It also works on a repository that has no PHP at all, such as a React app or a deploy repository.

## Install

The scanner needs PHP 8.4 or 8.5. Install it once, outside the project:

```bash
composer global require siberfx/laravel-risk-analyzer
risk-analyzer scan --project=/path/to/project
```

If the project uses Composer and its dependencies allow it, you can also add it to the project:

```bash
composer require --dev siberfx/laravel-risk-analyzer
vendor/bin/risk-analyzer scan
```

The scanned code can target any PHP version. Projects without a `composer.json` work too.

## Run it

```bash
risk-analyzer scan --project=.                         # whole project, fails on "high" and above
risk-analyzer scan --project=. --fail-on=medium
risk-analyzer scan --project=. --only=code             # PHP only
risk-analyzer scan --project=. --frontend              # only JavaScript/TypeScript/Vue
risk-analyzer scan --project=. --infrastructure        # only Docker, compose, scripts and workflows
risk-analyzer scan --project=. --changed=origin/main   # only files changed since origin/main
risk-analyzer scan --project=. --format=json --output=report.json
risk-analyzer baseline --project=.                     # accept today's findings, fail only on new ones
```

Exit codes: `0` when nothing reaches the threshold, `1` when something does, `2` for invalid options.

## What it checks

User input is tracked from `$_GET`, `$_POST`, `$_COOKIE`, `$_FILES`, `$_REQUEST`, the client parts of `$_SERVER` (`HTTP_*`, `REQUEST_URI`, `QUERY_STRING`, `PHP_SELF`), `php://input` and uploaded file names. It is followed through variables, string building, function arguments, closures and loops within a function or file.

| Rule | Plain PHP sinks |
| --- | --- |
| `sql-injection` | PDO `query`/`exec`/`prepare`, `mysqli_query`, `$mysqli->query`, `pg_query`, `sqlsrv_query`, `oci_parse` with SQL built from input (critical) or from other runtime values (medium) |
| `xss-echo` | `echo`, `print` and `<?= ?>` of input without `htmlspecialchars()` |
| `command-injection` | `exec`, `shell_exec`, `system`, `passthru`, `proc_open`, `popen`, backticks |
| `code-execution` | `eval`, `include`/`require` of input, `call_user_func` with input, `$fn()` |
| `path-traversal` | `file_get_contents`, `fopen`, `unlink`, `move_uploaded_file`... with input paths or client file names |
| `open-redirect` | `header('Location: ' . $_GET['next'])` |
| `ssrf` | curl, `file_get_contents`, `get_headers` with input URLs |
| `insecure-deserialization`, `xxe` | `unserialize` of input or without `allowed_classes`; `LIBXML_NOENT`/`LIBXML_DTDLOAD` |
| `hardcoded-secret`, `weak-cryptography`, `insecure-randomness`, `tls-verification-disabled`, `debug-leftover` | literal passwords and tokens, `md5`/`sha1` passwords, `rand()` tokens, `CURLOPT_SSL_VERIFYPEER` off, `var_dump`/`phpinfo()` |

Plus the frontend, Docker/compose, shell script and workflow rules, OSV advisories, abandoned packages, Composer hardening, PHP/Node versions past end of support, `public/` exposure, committed secrets and file permissions.

These are not reported:

- prepared statements: `$pdo->prepare('... WHERE id = ?')->execute([$id])`
- escaped output: `htmlspecialchars($x, ENT_QUOTES)`
- casts and checks: `(int) $_GET['id']`, `in_array($x, [...], true)`
- `$_SERVER['argv']` in CLI scripts

**Not checked:** the Laravel configuration & route rules need a booted Laravel app and are skipped. The taint analysis follows input within a function or file, not across method calls or class properties, so treat a clean scan as "no known patterns found".

## Configure

Without a config file, the whole project is scanned, minus `vendor`, `node_modules`, `var`, `runtime`, `storage`, `cache`, tests and build output. To change that, add `risk-analyzer.php` to the project root (or pass `--config=path`):

```php
<?php

return [
    'paths' => ['public', 'src', 'includes', 'templates'],
    'exclude' => ['vendor', 'cache', 'uploads', 'tests'],
    'fail_on' => 'high',
    'frontend' => ['paths' => ['public/js']],
    'rules' => [
        'disabled' => ['mass-assignment', 'xss-blade'],   // Laravel-only rules
    ],
    'secrets' => [
        'allow' => ['sample-key-from-the-docs'],
    ],
];
```

The keys are the same as in the [package config](../config/risk-analyzer.php); anything you leave out keeps its default. Use `getenv()` for values from the environment.

Suppress a single finding with a comment on the line or the line above:

```php
// risk-analyzer-ignore sql-injection -- $table comes from the hard-coded list above
$pdo->query("SELECT COUNT(*) FROM {$table}");
```

## In your test suite

```php
use PHPUnit\Framework\TestCase;
use Siberfx\RiskAnalyzer\Standalone;

final class SecurityTest extends TestCase
{
    public function test_no_security_findings(): void
    {
        Standalone::scan(dirname(__DIR__), offline: true)->assertClean('high');
    }
}
```

## CI

```yaml
name: security

on: [push, pull_request]

jobs:
  risk-analyzer:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@v4
      - uses: shivammathur/setup-php@v2
        with:
          php-version: '8.4'
      - run: composer global require siberfx/laravel-risk-analyzer
      - run: ~/.composer/vendor/bin/risk-analyzer scan --format=sarif --output=risk-analyzer.sarif
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: risk-analyzer.sarif
```

Back to the [main README](../README.md).

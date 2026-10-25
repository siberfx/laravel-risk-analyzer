# Risk Analyzer for Symfony

Risk Analyzer scans a Symfony project without Laravel: your PHP code, Twig templates, JavaScript in `assets/`, Dockerfiles, compose files, scripts, GitHub Actions workflows, `composer.lock`/`package-lock.json` advisories and committed secrets.

## Install

The scanner needs PHP 8.4 or 8.5. It depends on Illuminate (Laravel) components, which require Symfony Console 7.2+ or 8.

**Symfony 7.4 and 8 apps** can usually add it as a dev dependency:

```bash
composer require --dev siberfx/laravel-risk-analyzer
vendor/bin/risk-analyzer scan
```

**Symfony 6.4 apps**, or any project where Composer reports a conflict, install it once outside the project:

```bash
composer global require siberfx/laravel-risk-analyzer
risk-analyzer scan --project=/path/to/your/app
```

Your app can run on an older PHP version; only the scanner needs 8.4+.

## Run it

```bash
vendor/bin/risk-analyzer scan                        # whole project, fails on "high" and above
vendor/bin/risk-analyzer scan --fail-on=medium
vendor/bin/risk-analyzer scan --only=code            # PHP and Twig only
vendor/bin/risk-analyzer scan --frontend=assets      # only the JavaScript in assets/
vendor/bin/risk-analyzer scan --infrastructure       # only Docker, compose, scripts and workflows
vendor/bin/risk-analyzer scan --format=sarif --output=risk-analyzer.sarif
vendor/bin/risk-analyzer baseline                    # accept today's findings, fail only on new ones
vendor/bin/risk-analyzer rules --details             # what every rule looks for
```

Exit codes: `0` when nothing reaches the threshold, `1` when something does, `2` for invalid options.

## What it checks in a Symfony app

User input is tracked from:

- a `Request` argument: `$request->query->get()`, `$request->request->get()`, `$request->get()`, `$request->getContent()`, `$request->headers`, `$request->cookies`, uploaded file names
- `$_GET`, `$_POST`, `$_COOKIE`, `$_FILES`, `$_REQUEST` and the client parts of `$_SERVER`

It is reported when it reaches:

| Rule | Symfony sinks |
| --- | --- |
| `sql-injection` | Doctrine DBAL `executeQuery`, `executeStatement`, `fetchAllAssociative`, `fetchOne`...; DQL `createQuery`, `createNativeQuery`; QueryBuilder `where`/`andWhere`/`having` with a concatenated condition; PDO `query`/`exec`/`prepare` |
| `open-redirect` | `new RedirectResponse($url)`, `$this->redirect($url)` in controllers |
| `xss-twig` | `{{ app.request.query.get('q')\|raw }}` (high), other `\|raw` output (low), `{% autoescape false %}` (medium) |
| `xss-echo` | `echo`/`print` of input in plain PHP files |
| `command-injection`, `code-execution`, `path-traversal`, `ssrf`, `insecure-deserialization`, `xxe` | `Process` with a command string, `exec`, `eval`, file functions, HttpClient/curl, `unserialize`, XML parsing |

Plus the general rules: hard-coded secrets, weak cryptography, insecure randomness, disabled TLS verification, debug leftovers, React/Vue/Stimulus code in `assets/`, Dockerfile and compose hardening, script and workflow risks, OSV advisories, abandoned packages, Composer hardening, Symfony/PHP/Node versions past end of support, public-directory exposure and file permissions.

Bound parameters are not reported: `->where('u.id = :id')->setParameter('id', $id)` and `executeQuery('... WHERE id = ?', [$id])` are fine.

**Committed `.env` files:** Symfony commits `.env` and `.env.<env>` with defaults on purpose, so they are only reported when they contain a real-looking secret (an `APP_SECRET` value, or a password in a DSN other than `!ChangeMe!`). `.env.dev`/`.env.test` count as low, `.env`/`.env.prod` as medium. A committed `.env.local` is critical.

**Not checked:** the Laravel configuration & route rules (debug mode, cookies, CSRF, routes, security headers, php.ini) need a booted Laravel app and are skipped. Symfony's `security.yaml` firewalls and access control are not analysed.

## Configure

Without a config file, the whole project is scanned, minus `vendor`, `var`, `node_modules`, `public/bundles`, `public/build`, `assets/vendor`, tests and caches. To change that, add `risk-analyzer.php` to the project root (or `config/risk-analyzer.php`, or pass `--config=path`):

```php
<?php

return [
    'paths' => ['src', 'templates', 'config', 'public/index.php'],
    'exclude' => ['vendor', 'var', 'tests'],
    'fail_on' => 'high',

    'frontend' => [
        'paths' => ['assets'],
    ],

    'rules' => [
        'disabled' => ['mass-assignment', 'xss-blade'],   // Laravel-only rules
        'severity' => ['xss-twig' => 'medium'],
    ],

    'baseline' => 'risk-analyzer-baseline.json',
];
```

The keys are the same as in the [package config](../config/risk-analyzer.php); anything you leave out keeps its default. Use `getenv()` rather than `env()` for values from the environment.

Suppress a single finding with a comment on the line or the line above:

```php
// risk-analyzer-ignore sql-injection -- $column is checked against an allow-list above
$qb->orderBy("p.{$column}");
```

```twig
{# risk-analyzer-ignore xss-twig -- body is sanitised with html_sanitizer on save #}
{{ post.body|raw }}
```

## In your test suite

```php
use PHPUnit\Framework\TestCase;
use Siberfx\RiskAnalyzer\Standalone;

final class SecurityTest extends TestCase
{
    public function test_no_security_findings(): void
    {
        Standalone::scan(__DIR__.'/..', offline: true, only: ['code'])->assertClean('high');
    }
}
```

`Standalone::scan()` takes the project folder, an optional config file, config overrides, and the same named options as the command (`only`, `skip`, `offline`, `frontend`, `infrastructure`, `files`, `baseline`...).

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
      - run: ~/.composer/vendor/bin/risk-analyzer scan --format=markdown >> "$GITHUB_STEP_SUMMARY"
        if: always()
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: risk-analyzer.sarif
```

The global install keeps the scanner's dependencies out of your app, so this works whatever Symfony version the app uses. Run `composer install` first if you want `composer.lock` advisories checked against what is actually installed. For pull requests, `--changed=origin/${{ github.base_ref }}` scans only the touched files.

Back to the [main README](../README.md).

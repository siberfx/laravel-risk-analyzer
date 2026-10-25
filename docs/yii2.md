# Risk Analyzer for Yii2

Risk Analyzer scans a Yii2 project (basic or advanced template) without Laravel: controllers, models, views, components, console commands, JavaScript under `web/`, Dockerfiles, compose files, scripts, GitHub Actions workflows, `composer.lock`/`package-lock.json` advisories and committed secrets.

## Install

The scanner needs PHP 8.4 or 8.5 and Symfony Console 7.2+, so it usually can't be installed next to a Yii2 app's own dependencies. Install it once, outside the project:

```bash
composer global require siberfx/laravel-risk-analyzer
risk-analyzer scan --project=/path/to/your/app
```

Your app can keep running on an older PHP version; only the scanner needs 8.4+. If your app's dependencies do allow it, `composer require --dev siberfx/laravel-risk-analyzer` and `vendor/bin/risk-analyzer scan` work too.

## Run it

```bash
risk-analyzer scan --project=.                         # whole project, fails on "high" and above
risk-analyzer scan --project=. --fail-on=medium
risk-analyzer scan --project=. --only=code             # PHP only
risk-analyzer scan --project=. --frontend=web/js       # only your JavaScript
risk-analyzer scan --project=. --infrastructure        # only Docker, compose, scripts and workflows
risk-analyzer scan --project=. --format=sarif --output=risk-analyzer.sarif
risk-analyzer baseline --project=.                     # accept today's findings, fail only on new ones
risk-analyzer rules --details
```

Exit codes: `0` when nothing reaches the threshold, `1` when something does, `2` for invalid options.

## What it checks in a Yii2 app

User input is tracked from:

- `Yii::$app->request` and `$this->request`: `get()`, `post()`, `getBodyParam()`, `getQueryParam()`, `getRawBody()`, headers, cookies, `getUrl()`
- `$_GET`, `$_POST`, `$_COOKIE`, `$_FILES`, `$_REQUEST` and the client parts of `$_SERVER`
- uploaded file names

It is reported when it reaches:

| Rule | Yii2 sinks |
| --- | --- |
| `sql-injection` | `Yii::$app->db->createCommand("... " . $x)`, `Model::findBySql("... " . $x)`, `->where("status = $x")` / `andWhere` / `orWhere` / `having` with a concatenated string, PDO and mysqli calls |
| `xss-echo` | `<?= $x ?>`, `echo` and `print` of input in views and controllers |
| `open-redirect` | `$this->redirect($url)`, `Yii::$app->response->redirect($url)` |
| `command-injection`, `code-execution`, `path-traversal`, `ssrf`, `insecure-deserialization`, `xxe` | `exec`/`shell_exec`/`proc_open`, `eval`, file functions with input paths, curl/Guzzle, `unserialize`, XML parsing |

Plus the general rules: hard-coded secrets (also in `config/db.php`, `params.php`), weak cryptography, insecure randomness, disabled TLS verification, debug leftovers (`var_dump`, `print_r`), JavaScript checks, Dockerfile and compose hardening, script and workflow risks, OSV advisories, abandoned packages, Composer hardening, PHP/Node versions past end of support, public-directory exposure and file permissions.

These are not reported:

- `Html::encode()` and `htmlspecialchars()` output
- hash conditions such as `->where(['status' => $status])`
- bound parameters: `createCommand('... WHERE id=:id', [':id' => $id])`
- route arrays in `$this->redirect(['site/index'])`

**Not checked:** the Laravel configuration & route rules (debug mode, cookies, CSRF, routes, security headers, php.ini) need a booted Laravel app and are skipped. `YII_DEBUG`/`YII_ENV` in `web/index.php` and `cookieValidationKey` are not analysed yet.

## Configure

Without a config file, the whole project is scanned, minus `vendor`, `runtime`, `web/assets`, `node_modules`, tests and caches. To change that, add `risk-analyzer.php` to the project root (or pass `--config=path`).

Basic template:

```php
<?php

return [
    'paths' => ['controllers', 'models', 'views', 'components', 'commands', 'config', 'web/index.php'],
    'exclude' => ['vendor', 'runtime', 'web/assets', 'tests'],
    'frontend' => ['paths' => ['web/js']],
    'rules' => ['disabled' => ['mass-assignment', 'xss-blade']],   // Laravel-only rules
];
```

Advanced template:

```php
<?php

return [
    'paths' => ['frontend', 'backend', 'common', 'console'],
    'exclude' => ['vendor', 'runtime', 'web/assets', 'tests', 'frontend/web/assets', 'backend/web/assets'],
    'frontend' => ['paths' => ['frontend/web/js', 'backend/web/js']],
];
```

The keys are the same as in the [package config](../config/risk-analyzer.php); anything you leave out keeps its default. Use `getenv()` rather than `env()` for values from the environment.

Suppress a single finding with a comment on the line or the line above:

```php
<?php // risk-analyzer-ignore xss-echo -- $html is rendered by HtmlPurifier::process() ?>
<?= $html ?>
```

## In your test suite

With Codeception or PHPUnit, once the package is installed for the tests:

```php
use Siberfx\RiskAnalyzer\Standalone;

class SecurityTest extends \PHPUnit\Framework\TestCase
{
    public function testNoSecurityFindings(): void
    {
        Standalone::scan(dirname(__DIR__), offline: true, only: ['code'])->assertClean('high');
    }
}
```

When the app's dependencies can't take the package, run the global `risk-analyzer scan` in CI instead.

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

The scanner runs on PHP 8.4 in its own step; the app's own test job can keep its PHP version.

Back to the [main README](../README.md).

# Risk Analyzer: security scanner for Laravel

[![Latest Version on Packagist](https://img.shields.io/packagist/v/siberfx/laravel-risk-analyzer.svg?style=flat-square)](https://packagist.org/packages/siberfx/laravel-risk-analyzer)
[![Tests](https://img.shields.io/github/actions/workflow/status/siberfx/laravel-risk-analyzer/tests.yml?branch=main&label=tests&style=flat-square)](https://github.com/siberfx/laravel-risk-analyzer/actions/workflows/tests.yml)
[![Total Downloads](https://img.shields.io/packagist/dt/siberfx/laravel-risk-analyzer.svg?style=flat-square)](https://packagist.org/packages/siberfx/laravel-risk-analyzer)
[![PHP Version](https://img.shields.io/packagist/php-v/siberfx/laravel-risk-analyzer.svg?style=flat-square)](https://packagist.org/packages/siberfx/laravel-risk-analyzer)
[![Laravel](https://img.shields.io/badge/Laravel-12.x%20%7C%2013.x-FF2D20?style=flat-square&logo=laravel&logoColor=white)](https://laravel.com)
[![License](https://img.shields.io/github/license/siberfx/laravel-risk-analyzer.svg?style=flat-square)](LICENSE)

Risk Analyzer finds security problems in a Laravel application: in its code, its running configuration and routes, its dependencies and its files.

It does not grep source text. It **parses your PHP** and **follows request input through your code** (taint analysis), so it can tell these apart:

```php
DB::select("select * from users where id = $id");      // $id = $request->input('id')  → critical
DB::select("select * from {$this->table()}");          // runtime value, not input       → medium
DB::select('select * from users where id = ?', [$id]); // bindings                       → not reported
```

Runtime rules check the **booted application** instead of reading `.env` files. They look at the merged config and the **real route table** with middleware groups expanded. Dependency advisories come from the **OSV.dev** database, read straight from your lock files.

- 29 rules across code, configuration and routes, dependencies and filesystem
- Taint tracking through variables, string building, helpers, closures and loops, with sanitizers (`(int)`, `escapeshellarg`, `basename`, `in_array` allow-lists, `validated()`...)
- Severity reflects reachability: user input reaching a sink ranks higher than a runtime value
- Inline suppressions with reasons: `// risk-analyzer-ignore sql-injection -- table name comes from an enum`
- Baselines to adopt it on an existing project and only gate **new** findings
- `--changed` to scan only the files a branch touches
- Console, JSON, **SARIF** (GitHub code scanning) and Markdown (PR comments / job summaries) output
- A `Report::assertClean()` helper to run the scan inside your own test suite
- Custom rules: an AST rule takes about 15 lines

## Requirements

| Package | Version    |
| ------- | ---------- |
| PHP     | 8.4, 8.5   |
| Laravel | 12.x, 13.x |

## Installation

```bash
composer require --dev siberfx/laravel-risk-analyzer
php artisan risk-analyzer:scan
```

Publish the config if you want to change paths, thresholds or rules:

```bash
php artisan vendor:publish --tag=risk-analyzer-config
```

## Usage

```bash
php artisan risk-analyzer:scan                         # everything, fails on "high" and above
php artisan risk-analyzer:scan --production            # apply production checks (debug mode, cookies, dev tools...)
php artisan risk-analyzer:scan --fail-on=medium
php artisan risk-analyzer:scan --only=code             # categories: code, runtime, dependencies, filesystem
php artisan risk-analyzer:scan --only=sql-injection,ssrf --skip=xss-blade
php artisan risk-analyzer:scan --changed=origin/main   # code rules only, on files changed since origin/main
php artisan risk-analyzer:scan --offline               # no network: skips the OSV lookup
php artisan risk-analyzer:scan --format=sarif --output=risk-analyzer.sarif
php artisan risk-analyzer:scan --format=markdown >> "$GITHUB_STEP_SUMMARY"

php artisan risk-analyzer:rules --details              # what every rule looks for
php artisan risk-analyzer:baseline                     # accept the current findings
```

Sample output:

```
  RISK ANALYZER  29 rules · production profile · 1.84s

  CRITICAL sql-injection  app/Http/Controllers/ReportController.php:22
           Request input flows into raw SQL passed to DB::select().
           │ $rows = DB::select("select * from reports where id = $id");
           ↳ Keep the SQL a literal and pass values as bindings: whereRaw('price > ?', [$price]).

  HIGH     unprotected-route
           GET|HEAD admin/users looks like an admin route but has no authentication middleware.
           ↳ Put the route in a group with the auth middleware (and an authorization check such as can:).

  1 critical · 1 high · 0 medium · 3 low · 0 info (4 baselined)

  FAIL  2 finding(s) at or above "high".
```

Exit codes: `0` when nothing reaches the threshold, `1` when something does, `2` for invalid options.

## Rules

### Code (AST + taint analysis)

| Rule | Looks for |
| --- | --- |
| `sql-injection` | Raw SQL (`DB::select`, `DB::raw`, `whereRaw`, `orderByRaw`...) built from input or runtime strings; user-chosen `orderBy`/`groupBy`/`DB::table` identifiers |
| `command-injection` | `exec`, `shell_exec`, `system`, backticks, string-form `Process::run()` built from input |
| `code-execution` | `eval`, `include` of input, `call_user_func($request->...)`, `$fn()` |
| `insecure-deserialization` | `unserialize()` of input, or without `allowed_classes` |
| `path-traversal` | File functions, `Storage`/`File`, `response()->download()`, `storeAs()` with input paths or client file names |
| `ssrf` | `Http::get()`, Guzzle, curl, `get_headers` with input URLs |
| `open-redirect` | `redirect()`, `->away()`, `Redirect::to()`, `Location:` headers with input targets |
| `xxe` | `LIBXML_NOENT`/`LIBXML_DTDLOAD`, `substituteEntities`, re-enabled entity loader |
| `mass-assignment` | `create($request->all())`, `forceFill(...)` of input, empty `$guarded`, `#[Unguarded]`, `Model::unguard()` |
| `xss-blade` | `{!! !!}` echoes: input printed raw (high), other raw output to review (low) |
| `hardcoded-secret` | Provider token formats (AWS, Stripe, GitHub, Slack, OpenAI, Anthropic...), private keys, literal passwords, secret `env()` fallbacks |
| `weak-cryptography` | `md5`/`sha1` of passwords, ECB/DES/RC4, mcrypt, `==` on signatures |
| `insecure-randomness` | Tokens, OTPs and passwords made with `rand`, `mt_rand`, `uniqid`, `str_shuffle` |
| `tls-verification-disabled` | `withoutVerifying()`, `'verify' => false`, `CURLOPT_SSL_VERIFYPEER` off |
| `debug-leftover` | `dd`, `dump`, `ray`, `var_dump`, `->dd()`, `phpinfo()` |

### Configuration & routes (booted application)

| Rule | Looks for |
| --- | --- |
| `debug-mode` | `APP_DEBUG` and debug log level in production |
| `encryption-key` | Missing/invalid `APP_KEY`, weak cipher, production key equal to `.env.example` |
| `session-cookies` | `http_only` off, `secure` off in production, `SameSite=None` without `Secure`, very long lifetimes |
| `csrf-exclusions` | Catch-all exclusions, and **which real POST/PUT/DELETE web routes** each exclusion unprotects |
| `unprotected-route` | Admin-looking routes without auth, login/password/OTP routes without `throttle` |
| `cors-policy` | Any origin with credentials, unescaped origin patterns |
| `password-hashing` | bcrypt rounds < 10, Argon2 below OWASP minimums |
| `dev-tools-exposed` | Debugbar/Clockwork/Ray in `require`, debug routes and Debugbar/Telescope enabled in production |

### Dependencies

| Rule | Looks for |
| --- | --- |
| `vulnerable-dependency` | `composer.lock` and `package-lock.json` packages with OSV advisories, with the lowest fixing version |
| `abandoned-package` | Packages marked abandoned (from the lock file, offline) |
| `composer-hardening` | `secure-http: false`, HTTP repositories, `allow-plugins: true`, unlisted plugins, missing lock |
| `unsupported-runtime` | PHP and Laravel versions past (or within 90 days of) end of security support |

### Filesystem

| Rule | Looks for |
| --- | --- |
| `public-exposure` | `.env`, `.git`, dumps, keys, backups, `phpinfo.php`, logs inside `public/` |
| `secrets-in-git` | `.env`, OAuth keys, `auth.json`, private keys **committed to git** (asks `git ls-files`) |

## Production profile

Some issues only matter in production (debug mode, insecure cookies, enabled dev tools). These rules use their full severity when the app runs in an environment listed in `risk-analyzer.production_environments`, or when you pass `--production`. Run the scan on the server, or in CI with the production config cached, to check the configuration that actually ships.

## Suppressing findings

**Inline**, on the line or the line above:

```php
// risk-analyzer-ignore sql-injection -- $column is mapped from an enum above
$query->orderByRaw("{$column} desc");

$token = md5(uniqid()); // risk-analyzer-ignore insecure-randomness -- cache-busting only, not a secret
```

```blade
{{-- risk-analyzer-ignore xss-blade -- sanitised with HTMLPurifier in the model --}}
{!! $post->body_html !!}
```

`risk-analyzer-ignore` with no rule id ignores every rule on that line. Put the reason after `--`.

**Baseline**: record the findings you accept and only fail on new ones:

```bash
php artisan risk-analyzer:baseline     # writes risk-analyzer-baseline.json, commit it
php artisan risk-analyzer:scan         # baselined findings are listed as such but never fail
php artisan risk-analyzer:scan --no-baseline
```

Fingerprints ignore line numbers, so a baselined finding stays baselined when code moves around the file.

**Config**: disable rules, change severities or allow known sample values:

```php
'rules' => [
    'disabled' => ['debug-leftover'],
    'severity' => ['xss-blade' => 'medium'],
],
'dependencies' => ['ignore' => ['GHSA-xxxx-xxxx-xxxx']],
'secrets' => ['allow' => ['sk_test_documented_example']],
```

## CI

GitHub Actions with code scanning annotations:

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
        with:
          fetch-depth: 0
      - uses: shivammathur/setup-php@v2
        with:
          php-version: '8.4'
      - run: composer install --no-interaction --prefer-dist
      - run: cp .env.example .env && php artisan key:generate
      - run: php artisan risk-analyzer:scan --format=sarif --output=risk-analyzer.sarif
      - run: php artisan risk-analyzer:scan --format=markdown >> "$GITHUB_STEP_SUMMARY"
        if: always()
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: risk-analyzer.sarif
```

For pull requests you can scan only the touched files: `php artisan risk-analyzer:scan --changed=origin/${{ github.base_ref }}`.

## Inside your test suite

```php
use Siberfx\RiskAnalyzer\Facades\Risk Analyzer;

it('has no security findings', function () {
    RiskAnalyzer::scan(only: ['code', 'runtime'], offline: true)->assertClean('high');
});
```

## Writing your own rules

Code rules receive every AST node ([nikic/php-parser](https://github.com/nikic/PHP-Parser)), with taint information for the enclosing function in `$file->taint`:

```php
use PhpParser\Node;
use Siberfx\RiskAnalyzer\Code\Ast;
use Siberfx\RiskAnalyzer\Code\FileScope;
use Siberfx\RiskAnalyzer\Rules\Code\AbstractCodeRule;
use Siberfx\RiskAnalyzer\Severity;

final class NoRawHtmlMail extends AbstractCodeRule
{
    public function id(): string { return 'raw-html-mail'; }
    public function title(): string { return 'Raw HTML mail'; }
    public function description(): string { return 'Mail::html() with request input.'; }
    public function severity(): Severity { return Severity::High; }

    public function inspect(Node $node, FileScope $file): iterable
    {
        if ($node instanceof Node\Expr\StaticCall && Ast::className($node) === 'Mail'
            && Ast::methodName($node) === 'html' && $file->taint->isTainted(Ast::arg($node, 0))) {
            yield $this->report($file, $node, 'Request input is sent as raw HTML mail.');
        }
    }
}
```

Project rules (config, files, external services) implement `Siberfx\RiskAnalyzer\Contracts\ProjectRule` and receive a `ScanContext`. Register either kind in `config/risk-analyzer.php` (`rules.extra`) or from a service provider:

```php
RiskAnalyzer::extend(NoRawHtmlMail::class);
```

## Limits

Risk Analyzer is a static scanner with intra-procedural taint tracking. It follows input within a function, not across method calls or class properties, so treat a clean scan as "no known patterns found", not as proof of safety. It complements code review, dependency updates and a web application firewall; it doesn't replace them.

## Testing

```bash
composer test
composer analyse
composer format
```

## License

MIT. See [LICENSE](LICENSE).

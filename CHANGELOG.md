# Changelog

All notable changes to this package are documented here.

## [2.5.1] - 2026-10-25

### Added
- `--dev` for `risk-analyzer:scan` and `risk-analyzer:baseline`: forces the development profile even when `APP_ENV` is a production environment, so production-only checks (and their page requests and service connections) are skipped. The console header shows `development profile (--dev)`. Passing `--dev` with `--production` is an error.

## [2.5.0] - 2026-10-25

### Added
- `unsupported-runtime` checks, in production, the version of the default database server (MySQL, MariaDB, PostgreSQL) and of the Redis or Valkey server used by the cache, session or queue against endoflife.date (built-in dates offline): high past end of support, low within 90 days. MariaDB is recognised behind the `mysql` driver. Each check uses its own connection with a 5 second timeout, only reads the version, and skips servers it cannot reach.
- `runtime.services` config (default `true`) to turn the server checks off.

## [2.4.0] - 2026-10-25

### Added
- `php-configuration` (production): `allow_url_include` on (high), `display_errors` on (medium), `display_startup_errors` and `expose_php` on, `log_errors` off and `zend.assertions` 1 (low). Values are read from the php.ini files rather than `ini_get()`, which shows the CLI's: the PHP-FPM php.ini, `conf.d` and pool overrides next to the CLI ones on Debian/Ubuntu, or the files in the new `php.ini_files` config, plus `public/.user.ini` and `php_flag`/`php_value` in `public/.htaccess`. Each finding names the file the value came from.
- `file-permissions`: `.env`, `auth.json` and `storage/oauth-private.key` readable (medium) or writable (high) by every user on the machine, and `storage/` or `bootstrap/cache` writable by everyone (low). Skipped on Windows.
- `public-exposure` checks folders linked into `public/` (`filesystems.links`, e.g. `php artisan storage:link`) for PHP files the web server may execute, environment files, database dumps, keys, credentials, logs and `.htaccess`. Archives and other uploads are not reported there.

## [2.3.0] - 2026-10-25

### Added
- `security-headers` (production): checks one page for clickjacking protection (`X-Frame-Options` or CSP `frame-ancestors`), `Strict-Transport-Security` (missing, or `max-age` under six months), `X-Content-Type-Options: nosniff`, a `Content-Security-Policy` (missing, report-only, or allowing `'unsafe-inline'`/`'unsafe-eval'` scripts without nonces), `Referrer-Policy`, and version-revealing `X-Powered-By`/`Server` headers. The page is requested through the app's HTTP kernel (`http.probe_path`, default `/`) or from the live site (`http.probe_url`, which also sees web-server headers). A failing page is reported as info.
- `trusted-proxies`: `TrustProxies` trusting every proxy (`trustProxies(at: '*')`, `$proxies = '*'` in an app middleware, or the old `trustedproxy.proxies` config), which lets any client spoof its IP with `X-Forwarded-For`.
- `insecure-app-url` (production): `APP_URL` on `http://` (unless https is forced), or `URL::forceScheme('http')`.
- `database-tls` (production): MySQL/MariaDB connections to public hosts without an SSL CA, and PostgreSQL connections with `sslmode` disable, allow or prefer (Laravel's default). Local, socket, private-range, single-label (Docker service) and `.internal`/`.local`/`.svc` hosts are skipped.
- `http` config section: `probe_path`, `probe_url` (`RISK_ANALYZER_PROBE_URL`) and `timeout`.

## [2.2.1] - 2026-10-25

### Fixed
- Skipping a single route no longer depends on the package being installed. The `->riskAnalyzerIgnore()` route macro added in 2.1.0 only exists while the package is loaded, so with the package installed as a dev dependency, `composer install --no-dev` made every route file that used it throw `BadMethodCallException`.

### Removed
- The `->riskAnalyzerIgnore()` route macro. Replace it with the `#[RiskAnalyzerIgnore]` attribute on the route's closure, controller method or controller class, or with the `routes.ignore` config:

  ```php
  // before
  Route::get('admin/status', StatusController::class)->riskAnalyzerIgnore('unprotected-route', 'public status page');

  // after
  #[RiskAnalyzerIgnore('unprotected-route', reason: 'public status page')]
  final class StatusController { /* ... */ }
  ```

### Added
- `Siberfx\RiskAnalyzer\Attributes\RiskAnalyzerIgnore`. PHP only loads an attribute's class when it is instantiated, which only the scanner does, so routes using it keep working without the package.

## [2.2.0] - 2026-10-25

### Added
- `unsupported-runtime` checks Node.js: versions pinned in `.nvmrc`, `.node-version`, `package.json` (`engines.node`, `volta.node`), Dockerfiles, compose files and GitHub Actions `node-version`, plus the installed `node`. Each finding names the file and line it came from.
- `unsupported-runtime` checks the PHP patch level against php.net: high when a newer patch of the running branch fixed security issues, low when only bug-fix releases are newer.
- `unsupported-runtime` flags a `composer.json` `require.php` or `config.platform.php` constraint whose lowest allowed version is unsupported (medium).
- `vulnerable-dependency` reads `yarn.lock` (v1 and Berry), `pnpm-lock.yaml` (v5 to v9) and the text `bun.lock`, next to `package-lock.json`. A binary `bun.lockb` is reported as info. Upgrade commands match the package manager.
- `runtime` config section: endpoints, timeout, cache TTL, `node` and `node_binary`.

### Changed
- Support dates for PHP, Laravel and Node.js come from endoflife.date (cached for a day), with the built-in tables used offline or when it is unreachable. Existing PHP and Laravel findings keep their fingerprints.

## [2.1.0] - 2026-10-25

### Added
- `unprotected-route` recognises OAuth/SSO callbacks and webhooks (`routes.auth_flow_patterns`: callback, oauth, sso, saml, webhook). They are no longer reported as unauthenticated admin routes; callbacks without `throttle` and state-changing webhooks without signature-verification middleware are reported as low instead.
- `unprotected-route` recognises SPA catch-all routes (`admin/{any?}`, or a parameter constrained to `.*`) and judges them by the API routes under `api/{prefix}` or `{prefix}/api`: info when those all require auth, low when none can be found, high (listing them) when some are unprotected.
- `->riskAnalyzerIgnore($rules, $reason)` route macro to skip a route in `unprotected-route`, `csrf-exclusions` and `dev-tools-exposed`; with no rule ids it skips all of them.
- `routes.ignore` config: URI or route-name patterns skipped by `unprotected-route`, optionally keyed with a reason.
- `risk-analyzer:config-sync` adds options introduced by package updates to a published `config/risk-analyzer.php`, keeping your values, comments, `env()` calls and formatting. `--dry-run` lists them, `--check` fails when any are missing. Can be run from `post-update-cmd`.

### Changed
- The package config is merged recursively, so options added to nested sections (such as `routes.auth_flow_patterns`) take effect for apps that published an older config. Lists set in the published config still replace the defaults as a whole.
- Unprotected admin route findings end with the file and line of the closure or controller method that handles the route. Baseline fingerprints are unchanged.

## [2.0.1] - 2026-10-25

### Fixed
- Allow `guzzlehttp/guzzle` ^8.0 alongside ^7.9, so the package installs in Laravel 13 apps that already lock Guzzle 8. HTTP calls go through Laravel's `Http` client, which supports both; the test suite passes on Guzzle 7.15 and 8.3.

## [2.0.0] - 2026-10-23

### Changed
- `vulnerable-dependency` findings now show the advisory's CVE ids next to its OSV id, e.g. `(GHSA-wxmh-65f7-jcvw / CVE-2023-29197)`, so CVEs are visible in console and Markdown output. Baseline fingerprints are unchanged.

## [1.0.0] - 2026-10-23

### Added
- AST-based code analysis (nikic/php-parser) with intra-procedural taint tracking: request input, superglobals, uploaded file names, sanitizers, `in_array` allow-lists and validated input
- Code rules: `sql-injection`, `command-injection`, `code-execution`, `insecure-deserialization`, `path-traversal`, `ssrf`, `open-redirect`, `xxe`, `mass-assignment`, `xss-blade`, `hardcoded-secret`, `weak-cryptography`, `insecure-randomness`, `tls-verification-disabled`, `debug-leftover`
- Runtime rules on the booted app and its route table: `debug-mode`, `encryption-key`, `session-cookies`, `csrf-exclusions`, `unprotected-route`, `cors-policy`, `password-hashing`, `dev-tools-exposed`
- Dependency rules: `vulnerable-dependency` (OSV.dev, composer.lock and package-lock.json, cached), `abandoned-package`, `composer-hardening`, `unsupported-runtime`
- Filesystem rules: `public-exposure`, `secrets-in-git`
- `risk-analyzer:scan` with `--fail-on`, `--only`, `--skip`, `--production`, `--offline`, `--changed` and console/JSON/SARIF/Markdown output
- `risk-analyzer:baseline` and line-independent fingerprints
- `risk-analyzer:rules`
- Inline `risk-analyzer-ignore` comments with rule ids and reasons
- `Report::assertClean()` for use in test suites
- Custom `CodeRule` / `ProjectRule` support through config or `RiskAnalyzer::extend()`
- Support for PHP 8.4 / 8.5 and Laravel 12 / 13

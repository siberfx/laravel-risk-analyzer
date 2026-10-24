# Changelog

All notable changes to this package are documented here.

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

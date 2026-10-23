# Changelog

All notable changes to this package are documented here.

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

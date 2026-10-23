<?php

return [

    /*
    |--------------------------------------------------------------------------
    | Failure threshold
    |--------------------------------------------------------------------------
    |
    | The lowest severity that makes `risk-analyzer:scan` exit with a non-zero
    | code. One of: critical, high, medium, low, info. Can be overridden
    | per run with --fail-on.
    |
    */

    'fail_on' => env('RISK_ANALYZER_FAIL_ON', 'high'),

    /*
    |--------------------------------------------------------------------------
    | Code paths
    |--------------------------------------------------------------------------
    |
    | Directories (relative to the project root) whose PHP and Blade files
    | are parsed by the code rules, and path fragments to skip inside them.
    |
    */

    'paths' => [
        'app',
        'bootstrap',
        'config',
        'database',
        'resources/views',
        'routes',
    ],

    'exclude' => [
        'vendor',
        'node_modules',
        'storage',
        'bootstrap/cache',
        'tests',
    ],

    /*
    |--------------------------------------------------------------------------
    | Production environments
    |--------------------------------------------------------------------------
    |
    | Runtime rules (debug mode, cookies, dev tools...) report their full
    | severity only when the app runs in one of these environments, or when
    | the scan is started with --production.
    |
    */

    'production_environments' => ['production', 'prod', 'live'],

    /*
    |--------------------------------------------------------------------------
    | Rules
    |--------------------------------------------------------------------------
    |
    | 'disabled'  rule ids that never run.
    | 'severity'  per-rule severity overrides, e.g. ['debug-call' => 'medium'].
    | 'extra'     your own rule classes (Rule or CodeRule implementations).
    |
    */

    'rules' => [
        'disabled' => [],
        'severity' => [],
        'extra' => [],
    ],

    /*
    |--------------------------------------------------------------------------
    | Baseline
    |--------------------------------------------------------------------------
    |
    | Findings recorded in this file (created with `risk-analyzer:baseline`) are
    | reported as "baselined" and never fail a scan, so you can adopt the
    | scanner on an existing project and only gate new issues.
    |
    */

    'baseline' => 'risk-analyzer-baseline.json',

    /*
    |--------------------------------------------------------------------------
    | Dependency advisories
    |--------------------------------------------------------------------------
    |
    | Lock files are checked against the OSV.dev database (GitHub Security
    | Advisories, FriendsOfPHP, npm...). Results are cached per package
    | version. Use --offline to skip network lookups.
    |
    */

    'dependencies' => [
        'endpoint' => env('RISK_ANALYZER_OSV_ENDPOINT', 'https://api.osv.dev'),
        'timeout' => 15,
        'cache_ttl' => 60 * 60 * 6,
        'include_dev' => true,
        'npm' => true,
        'ignore' => [
            // 'GHSA-xxxx-xxxx-xxxx',
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Route rules
    |--------------------------------------------------------------------------
    */

    'routes' => [
        'auth_middleware' => ['auth', 'auth.basic', 'can', 'signed', 'password.confirm', 'verified'],
        'admin_patterns' => ['admin', 'dashboard', 'backoffice', 'panel', 'manage'],
        'sensitive_patterns' => ['login', 'register', 'password', 'otp', 'two-factor', '2fa', 'verify'],
    ],

    /*
    |--------------------------------------------------------------------------
    | Secrets
    |--------------------------------------------------------------------------
    |
    | Literal values that look like secrets but are fine to commit
    | (test fixtures, documented sample keys...).
    |
    */

    'secrets' => [
        'allow' => [],
    ],

];

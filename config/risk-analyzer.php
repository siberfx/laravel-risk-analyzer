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
    | Frontend code
    |--------------------------------------------------------------------------
    |
    | Folders (relative to the project root, or absolute) whose React, Vue
    | and Angular sources are checked by the frontend rules. --frontend
    | replaces this list for one run, e.g. for a separate SPA folder; a
    | lockfile inside such a folder is also checked for advisories.
    |
    */

    'frontend' => [
        'paths' => [
            'resources/js',
            'resources/ts',
        ],
        'extensions' => ['js', 'jsx', 'mjs', 'cjs', 'ts', 'tsx', 'vue', 'html'],
        'exclude' => [
            'node_modules',
            'dist',
            'build',
            '.angular',
            '.next',
            '.nuxt',
            'coverage',
            'vendor',
            'tests',
            '__tests__',
            'e2e',
        ],
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
    | Lock files (composer.lock, package-lock.json, yarn.lock, pnpm-lock.yaml,
    | bun.lock) are checked against the OSV.dev database (GitHub Security
    | Advisories, FriendsOfPHP, npm...). Results are cached per package
    | version. Use --offline to skip network lookups. 'npm' covers every
    | JavaScript lockfile.
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
    | Runtime support
    |--------------------------------------------------------------------------
    |
    | unsupported-runtime takes support dates from endoflife.date and PHP
    | security releases from php.net, cached for cache_ttl seconds. The
    | built-in tables are used with --offline or when they are unreachable.
    | 'node' checks Node versions pinned in the project; 'node_binary' is
    | also asked for its version (false to skip). 'services' asks the
    | database and Redis servers the app uses for their versions in
    | production (a separate connection with a 5 second timeout).
    |
    */

    'runtime' => [
        'endpoint' => env('RISK_ANALYZER_EOL_ENDPOINT', 'https://endoflife.date'),
        'php_endpoint' => env('RISK_ANALYZER_PHP_ENDPOINT', 'https://www.php.net'),
        'timeout' => 10,
        'cache_ttl' => 60 * 60 * 24,
        'node' => true,
        'node_binary' => 'node',
        'services' => true,
    ],

    /*
    |--------------------------------------------------------------------------
    | Route rules
    |--------------------------------------------------------------------------
    |
    | 'auth_flow_patterns'  OAuth/SSO callbacks and webhooks: public by design,
    |                       checked for rate limiting / signatures instead of auth.
    | 'ignore'              URI or route-name patterns skipped by unprotected-route,
    |                       optionally keyed with a reason: ['admin/oauth/*' => 'SSO'].
    |                       Single routes can use the #[RiskAnalyzerIgnore] attribute.
    |
    */

    'routes' => [
        'auth_middleware' => ['auth', 'auth.basic', 'can', 'signed', 'password.confirm', 'verified'],
        'admin_patterns' => ['admin', 'dashboard', 'backoffice', 'panel', 'manage'],
        'sensitive_patterns' => ['login', 'register', 'password', 'otp', 'two-factor', '2fa', 'verify'],
        'auth_flow_patterns' => ['callback', 'oauth', 'sso', 'saml', 'webhook', 'webhooks'],
        'ignore' => [],
    ],

    /*
    |--------------------------------------------------------------------------
    | Security headers
    |--------------------------------------------------------------------------
    |
    | security-headers requests one page in production. By default it goes
    | through the app's HTTP kernel (probe_path, false to skip), so headers
    | your web server or CDN adds are not seen. Set probe_url to the live
    | site (e.g. https://example.com) to check what browsers actually get.
    |
    */

    'http' => [
        'probe_path' => '/',
        'probe_url' => env('RISK_ANALYZER_PROBE_URL'),
        'timeout' => 10,
    ],

    /*
    |--------------------------------------------------------------------------
    | php.ini
    |--------------------------------------------------------------------------
    |
    | php-configuration reads settings from php.ini files, because ini_get()
    | shows the CLI's values. By default it uses the CLI's files, or the
    | PHP-FPM ones next to them (Debian/Ubuntu). List the files PHP-FPM
    | loads here when they live elsewhere (e.g. in a Docker image).
    |
    */

    'php' => [
        'ini_files' => null,
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

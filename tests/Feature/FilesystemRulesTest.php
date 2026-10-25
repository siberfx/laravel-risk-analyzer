<?php

use Siberfx\RiskAnalyzer\RiskAnalyzer;
use Symfony\Component\Process\Process;

it('finds sensitive files in the web root', function () {
    $root = $this->project([
        'public/index.php' => '<?php',
        'public/.env' => 'APP_KEY=x',
        'public/backup.sql.gz' => 'x',
        'public/phpinfo.php' => '<?php phpinfo();',
        'public/storage/report.sql' => 'symlinked storage is skipped',
        'public/build/app.js' => 'x',
    ]);

    $findings = collect(app(RiskAnalyzer::class)->scan(only: ['public-exposure'], baseline: false, basePath: $root)->findings)
        ->map(fn ($f) => [$f->severity->value, $f->file])->sort()->values()->all();

    expect($findings)->toBe([
        ['critical', 'public/.env'],
        ['critical', 'public/backup.sql.gz'],
        ['high', 'public/phpinfo.php'],
    ]);
});

it('asks git which secret files are committed', function () {
    $root = $this->project([
        '.env' => 'APP_KEY=x',
        '.env.example' => 'APP_KEY=',
        'storage/oauth-private.key' => 'key',
        'tests/fixtures/test.pem' => 'fixture',
        'app/Models/User.php' => '<?php',
    ]);

    foreach ([['git', 'init', '-q'], ['git', 'add', '-f', '.']] as $command) {
        (new Process($command, $root))->mustRun();
    }

    $files = collect(app(RiskAnalyzer::class)->scan(only: ['secrets-in-git'], baseline: false, basePath: $root)->findings)
        ->pluck('file')->sort()->values()->all();

    expect($files)->toBe(['.env', 'storage/oauth-private.key']);
});

it('falls back to .gitignore without a git repository', function () {
    $root = $this->project(['.gitignore' => "/vendor\n/node_modules\n"]);

    $findings = app(RiskAnalyzer::class)->scan(only: ['secrets-in-git'], baseline: false, basePath: $root)->findings;

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->message)->toBe('.env is not listed in .gitignore.');
});

it('only reports committed .npmrc files that hold a token', function () {
    $root = $this->project(['.npmrc' => "ignore-scripts=true\n", 'web/.npmrc' => '//registry.npmjs.org/:_authToken=npm_'.'abc123'."\n"]);

    foreach ([['git', 'init', '-q'], ['git', 'add', '-f', '.']] as $command) {
        (new Process($command, $root))->mustRun();
    }

    $files = collect(app(RiskAnalyzer::class)->scan(only: ['secrets-in-git'], baseline: false, basePath: $root)->findings)->pluck('file')->all();

    expect($files)->toBe(['web/.npmrc']);
});

it('skips templates, committed dependencies and public certificates', function () {
    $root = $this->project([
        '.env.production.example' => 'APP_KEY=',
        'docker/.env.dev.local.example' => 'DB_PASSWORD=',
        'vendor/acme/sdk/cacert.pem' => "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
        'certs/ca.pem' => "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
        'certs/server.key' => "-----BEGIN RSA PRIVATE KEY-----\nMIIE\n-----END RSA PRIVATE KEY-----\n",
    ]);

    foreach ([['git', 'init', '-q'], ['git', 'add', '-f', '.']] as $command) {
        (new Process($command, $root))->mustRun();
    }

    $files = collect(app(RiskAnalyzer::class)->scan(only: ['secrets-in-git'], baseline: false, basePath: $root)->findings)->pluck('file')->all();

    expect($files)->toBe(['certs/server.key']);
});

it('only reports Symfony env files that hold a real secret', function () {
    $root = $this->project([
        'composer.json' => json_encode(['require' => ['symfony/framework-bundle' => '^7.4']]),
        '.env' => "APP_ENV=dev\nAPP_SECRET=\nDATABASE_URL=\"postgresql://app:!ChangeMe!@127.0.0.1:5432/app\"\n",
        '.env.dev' => "APP_SECRET=4f9c1b7e2d8a6f3c5e0b9d7a1c3e5f7a\n",
        '.env.prod' => "MAILER_DSN=smtp://mailer:Xk9vQ2mLp7Rt4Wz8@smtp.example.com:587\n",
        '.env.local' => "APP_SECRET=x\n",
    ]);

    foreach ([['git', 'init', '-q'], ['git', 'add', '-f', '.']] as $command) {
        (new Process($command, $root))->mustRun();
    }

    $findings = collect(app(RiskAnalyzer::class)->scan(only: ['secrets-in-git'], baseline: false, basePath: $root)->findings)
        ->mapWithKeys(fn ($finding) => [$finding->file => $finding->severity->value])->all();

    expect($findings)->toBe(['.env.local' => 'critical', '.env.prod' => 'medium', '.env.dev' => 'low']);
});

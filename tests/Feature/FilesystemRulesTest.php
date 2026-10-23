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

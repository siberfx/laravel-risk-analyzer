<?php

use Illuminate\Support\Facades\Artisan;
use Symfony\Component\Process\Process;

beforeEach(function () {
    $this->root = $this->project([
        'app/Http/Controllers/A.php' => controllerAction('exec($request->input("cmd"));'),
        'app/Debug.php' => "<?php\ndump('x');\n",
    ]);

    // Point the scanner at the throwaway project.
    $this->app->setBasePath($this->root);
});

it('prints findings and fails on the threshold', function () {
    $exitCode = Artisan::call('risk-analyzer:scan', ['--only' => ['code']]);

    expect($exitCode)->toBe(1)
        ->and(Artisan::output())->toContain('CRITICAL command-injection  app/Http/Controllers/A.php:11')
        ->toContain('exec($request->input("cmd"));')
        ->toContain('FAIL');
});

it('passes when nothing reaches --fail-on', function () {
    $this->artisan('risk-analyzer:scan', ['--only' => ['debug-leftover'], '--fail-on' => 'medium'])
        ->expectsOutputToContain('PASS')
        ->assertSuccessful();
});

it('accepts comma separated --only and --skip', function () {
    $this->artisan('risk-analyzer:scan', ['--only' => ['code'], '--skip' => ['command-injection,xss-blade']])
        ->assertSuccessful();
});

it('writes SARIF that GitHub code scanning understands', function () {
    $output = $this->root.'/risk-analyzer.sarif';

    $this->artisan('risk-analyzer:scan', ['--only' => ['code'], '--format' => 'sarif', '--output' => $output])->assertFailed();

    $sarif = json_decode(file_get_contents($output), true);
    $result = $sarif['runs'][0]['results'][0];

    expect($sarif['version'])->toBe('2.1.0')
        ->and($result['ruleId'])->toBe('command-injection')
        ->and($result['level'])->toBe('error')
        ->and($result['locations'][0]['physicalLocation'])->toBe(['artifactLocation' => ['uri' => 'app/Http/Controllers/A.php'], 'region' => ['startLine' => 11]])
        ->and($result['partialFingerprints']['risk-analyzer/v1'])->toHaveLength(16)
        ->and(collect($sarif['runs'][0]['tool']['driver']['rules'])->pluck('id'))->toContain('command-injection');
});

it('prints JSON and markdown reports', function () {
    Artisan::call('risk-analyzer:scan', ['--only' => ['code'], '--format' => 'json']);
    $json = json_decode(Artisan::output(), true);

    expect($json['summary']['critical'])->toBe(1)
        ->and($json['findings'][0]['rule'])->toBe('command-injection');

    Artisan::call('risk-analyzer:scan', ['--only' => ['code'], '--format' => 'markdown']);

    expect(Artisan::output())->toContain('## 🛡️ Risk Analyzer security scan')->toContain('`command-injection`');
});

it('creates a baseline that makes the next scan pass', function () {
    $this->artisan('risk-analyzer:baseline', ['--offline' => true])->assertSuccessful();

    expect(file_exists($this->root.'/risk-analyzer-baseline.json'))->toBeTrue();

    $this->artisan('risk-analyzer:scan', ['--only' => ['code']])
        ->expectsOutputToContain('baselined')
        ->assertSuccessful();

    $this->artisan('risk-analyzer:scan', ['--only' => ['code'], '--no-baseline' => true])->assertFailed();
});

it('rejects invalid options', function () {
    $this->artisan('risk-analyzer:scan', ['--fail-on' => 'severe'])->assertExitCode(2);
    $this->artisan('risk-analyzer:scan', ['--format' => 'xml', '--only' => ['code']])->assertExitCode(2);
});

it('lists rules', function () {
    $this->artisan('risk-analyzer:rules')
        ->expectsOutputToContain('sql-injection')
        ->expectsOutputToContain('vulnerable-dependency')
        ->assertSuccessful();
});

it('scans only files changed in git with --changed', function () {
    foreach ([['git', 'init', '-q'], ['git', 'add', '.'], ['git', '-c', 'user.name=t', '-c', 'user.email=t@t', 'commit', '-qm', 'init']] as $command) {
        (new Process($command, $this->root))->mustRun();
    }

    file_put_contents($this->root.'/app/New.php', "<?php\neval(\$_GET['x']);\n");

    Artisan::call('risk-analyzer:scan', ['--changed' => '', '--format' => 'json']);
    $rules = collect(json_decode(Artisan::output(), true)['findings'])->pluck('rule')->all();

    expect($rules)->toBe(['code-execution']);
});

it('forces the development profile with --dev, even when APP_ENV is production', function () {
    $this->app['env'] = 'production';
    config()->set('app.debug', true);

    $this->artisan('risk-analyzer:scan', ['--only' => ['debug-mode']])
        ->expectsOutputToContain('production profile')
        ->assertFailed();

    $this->artisan('risk-analyzer:scan', ['--only' => ['debug-mode'], '--dev' => true])
        ->expectsOutputToContain('development profile (--dev)')
        ->expectsOutputToContain('PASS')
        ->assertSuccessful();
});

it('rejects --dev together with --production', function (string $command) {
    $this->artisan($command, ['--dev' => true, '--production' => true])
        ->expectsOutputToContain('Use either --dev or --production, not both.')
        ->assertExitCode(2);
})->with(['risk-analyzer:scan', 'risk-analyzer:baseline']);

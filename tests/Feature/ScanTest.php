<?php

use PhpParser\Node;
use PHPUnit\Framework\AssertionFailedError;
use Siberfx\RiskAnalyzer\Baseline;
use Siberfx\RiskAnalyzer\Category;
use Siberfx\RiskAnalyzer\Code\FileScope;
use Siberfx\RiskAnalyzer\Contracts\CodeRule;
use Siberfx\RiskAnalyzer\Facades\RiskAnalyzer as RiskAnalyzerFacade;
use Siberfx\RiskAnalyzer\Finding;
use Siberfx\RiskAnalyzer\Report;
use Siberfx\RiskAnalyzer\RiskAnalyzer;
use Siberfx\RiskAnalyzer\Severity;

function vulnerableProject(): array
{
    return [
        'app/Http/Controllers/ReportController.php' => controllerAction('return DB::select("select * from reports where id = {$request->input(\'id\')}");'),
        'app/Support/helpers.php' => "<?php\nfunction trace(\$x) { dd(\$x); }\n",
        'resources/views/profile.blade.php' => "<h1>{{ \$user->name }}</h1>\n<div>{!! request('bio') !!}</div>\n<div>{!! \$post->body !!}</div>\n{!! csrf_field() !!}\n",
        'tests/Feature/IgnoredTest.php' => "<?php\ndd('tests are excluded');\n",
        'vendor/acme/pkg/src/Bad.php' => "<?php\neval(\$_GET['x']);\n",
    ];
}

function scanProject(string $root, array $options = []): Report
{
    return app(RiskAnalyzer::class)->scan(...['only' => ['code'], 'baseline' => false, 'basePath' => $root, ...$options]);
}

it('scans code and blade files under the configured paths only', function () {
    $report = scanProject($this->project(vulnerableProject()));
    $rules = collect($report->findings)->map(fn (Finding $f) => $f->rule.'@'.$f->file.':'.$f->line)->all();

    expect($rules)->toContain('sql-injection@app/Http/Controllers/ReportController.php:11')
        ->toContain('debug-leftover@app/Support/helpers.php:2')
        ->toContain('xss-blade@resources/views/profile.blade.php:2')
        ->toContain('xss-blade@resources/views/profile.blade.php:3')
        ->and(collect($report->findings)->pluck('file')->unique()->all())->not->toContain('tests/Feature/IgnoredTest.php', 'vendor/acme/pkg/src/Bad.php');

    $blade = collect($report->findings)->where('rule', 'xss-blade')->pluck('severity', 'line')->map->value->all();

    expect($blade)->toBe([2 => 'high', 3 => 'low']);
});

it('sorts findings by severity and decides pass/fail by threshold', function () {
    $report = scanProject($this->project(vulnerableProject()));

    expect($report->findings[0]->severity)->toBe(Severity::Critical)
        ->and($report->passes('critical'))->toBeFalse()
        ->and($report->failing('high')->count())->toBe(2)
        ->and($report->counts())->toMatchArray(['critical' => 1, 'high' => 1, 'low' => 2]);
});

it('limits code rules to changed files', function () {
    $report = scanProject($this->project(vulnerableProject()), ['files' => ['app/Support/helpers.php']]);

    expect(collect($report->findings)->pluck('rule')->unique()->values()->all())->toBe(['debug-leftover']);
});

it('applies a baseline so known findings no longer fail the scan', function () {
    $root = $this->project(vulnerableProject());
    Baseline::fromFindings(scanProject($root)->findings)->save($root.'/risk-analyzer-baseline.json');

    file_put_contents($root.'/app/Http/Controllers/NewController.php', controllerAction('exec($request->input("cmd"));'));

    $report = scanProject($root, ['baseline' => $root.'/risk-analyzer-baseline.json']);

    expect($report->baselined()->count())->toBe(4)
        ->and($report->active()->pluck('rule')->all())->toBe(['command-injection']);
});

it('overrides severities and disables rules from config', function () {
    config()->set('risk-analyzer.rules.severity', ['debug-leftover' => 'high']);
    config()->set('risk-analyzer.rules.disabled', ['xss-blade']);
    app()->forgetInstance(RiskAnalyzer::class);

    $report = scanProject($this->project(vulnerableProject()));

    expect(collect($report->findings)->firstWhere('rule', 'debug-leftover')->severity)->toBe(Severity::High)
        ->and(collect($report->findings)->where('rule', 'xss-blade'))->toBeEmpty()
        ->and(RiskAnalyzerFacade::rules())->not->toHaveKey('xss-blade');
});

it('rejects unknown rule selectors', function () {
    app(RiskAnalyzer::class)->scan(only: ['nope']);
})->throws(InvalidArgumentException::class, 'Unknown rule or category [nope]');

it('runs custom code rules registered with extend()', function () {
    RiskAnalyzerFacade::extend(new class implements CodeRule
    {
        public function id(): string
        {
            return 'no-goto';
        }

        public function title(): string
        {
            return 'No goto';
        }

        public function description(): string
        {
            return 'Flags goto.';
        }

        public function category(): Category
        {
            return Category::Code;
        }

        public function severity(): Severity
        {
            return Severity::Medium;
        }

        public function inspect(Node $node, FileScope $file): iterable
        {
            if ($node instanceof Node\Stmt\Goto_) {
                yield $file->finding($this->id(), $node, $this->severity(), 'goto used.');
            }
        }
    });

    $report = scanProject($this->project(['app/Legacy.php' => "<?php\nstart:\ngoto start;\n"]));

    expect($report->findings)->toHaveCount(1)
        ->and($report->findings[0]->rule)->toBe('no-goto')
        ->and($report->findings[0]->line)->toBe(3);
});

it('offers an assertion for use in your own test suite', function () {
    scanProject($this->project(['app/Clean.php' => "<?php\necho 'hello';\n"]))->assertClean();

    expect(fn () => scanProject($this->project(vulnerableProject()))->assertClean('high'))
        ->toThrow(AssertionFailedError::class, 'sql-injection');
});

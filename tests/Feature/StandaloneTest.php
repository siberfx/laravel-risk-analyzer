<?php

use PHPUnit\Framework\AssertionFailedError;
use Siberfx\RiskAnalyzer\Category;
use Siberfx\RiskAnalyzer\Finding;
use Siberfx\RiskAnalyzer\Report;
use Siberfx\RiskAnalyzer\RiskAnalyzer;
use Siberfx\RiskAnalyzer\Standalone;
use Symfony\Component\Process\Process;

function symfonyProject(): array
{
    return [
        'composer.lock' => json_encode(['packages' => [['name' => 'symfony/framework-bundle', 'version' => 'v6.3.12']]]),
        'src/Controller/SearchController.php' => <<<'PHP'
            <?php
            namespace App\Controller;

            use Doctrine\DBAL\Connection;
            use Symfony\Component\HttpFoundation\RedirectResponse;
            use Symfony\Component\HttpFoundation\Request;

            final class SearchController
            {
                public function __invoke(Request $request, Connection $conn): RedirectResponse
                {
                    $conn->fetchAllAssociative("SELECT * FROM posts WHERE title LIKE '%" . $request->query->get('q') . "%'");

                    return new RedirectResponse($request->query->get('next'));
                }
            }
            PHP,
        'templates/search.html.twig' => "<h1>{{ title }}</h1>\n{{ app.request.query.get('q')|raw }}\n{{ post.body|raw }}\n{# risk-analyzer-ignore xss-twig -- sanitised #}\n{{ post.intro|raw }}\n{% autoescape false %}{{ x }}{% endautoescape %}\n",
        'var/cache/prod/Compiled.php' => "<?php\neval(\$_GET['x']);\n",
        'vendor/acme/lib/Bad.php' => "<?php\neval(\$_GET['x']);\n",
    ];
}

function yiiProject(): array
{
    return [
        'controllers/SiteController.php' => <<<'PHP'
            <?php
            namespace app\controllers;

            use Yii;
            use yii\web\Controller;

            class SiteController extends Controller
            {
                public function actionView()
                {
                    $rows = Yii::$app->db->createCommand('SELECT * FROM post WHERE id=' . Yii::$app->request->get('id'))->queryAll();

                    return $this->redirect(Yii::$app->request->get('return'));
                }
            }
            PHP,
        'views/site/search.php' => "<?php\nuse yii\\helpers\\Html;\n?>\n<h1><?= Html::encode(Yii::\$app->request->get('q')) ?></h1>\n<p><?= Yii::\$app->request->get('q') ?></p>\n",
        'runtime/cache/x.php' => "<?php\neval(\$_GET['x']);\n",
        'web/assets/abc/jquery.js' => "eval(location.hash);\n",
    ];
}

/**
 * @return array<string, string> "rule@file:line" => severity
 */
function standaloneFindings(Report $report): array
{
    return collect($report->findings)->mapWithKeys(fn (Finding $f) => [$f->rule.'@'.$f->location() => $f->severity->value])->all();
}

it('scans a Symfony project without Laravel', function () {
    $report = Standalone::scan($this->project(symfonyProject()), offline: true, baseline: false);

    expect(standaloneFindings($report))->toMatchArray([
        'sql-injection@src/Controller/SearchController.php:12' => 'critical',
        'open-redirect@src/Controller/SearchController.php:14' => 'high',
        'xss-twig@templates/search.html.twig:2' => 'high',
        'xss-twig@templates/search.html.twig:3' => 'low',
        'xss-twig@templates/search.html.twig:6' => 'medium',
        'unsupported-runtime@composer.lock' => 'high',
    ])
        ->not->toHaveKey('xss-twig@templates/search.html.twig:5')
        ->and(collect($report->findings)->firstWhere('rule', 'unsupported-runtime')->message)->toStartWith('Symfony 6.3 stopped receiving security fixes')
        ->and(collect($report->findings)->pluck('file')->filter(fn ($file) => str_starts_with((string) $file, 'var/') || str_starts_with((string) $file, 'vendor/'))->all())->toBe([]);
});

it('scans a Yii2 project without Laravel', function () {
    $findings = standaloneFindings(Standalone::scan($this->project(yiiProject()), offline: true, baseline: false));

    expect($findings)->toMatchArray([
        'sql-injection@controllers/SiteController.php:11' => 'critical',
        'open-redirect@controllers/SiteController.php:13' => 'high',
        'xss-echo@views/site/search.php:5' => 'high',
    ])
        ->not->toHaveKey('xss-echo@views/site/search.php:4')
        ->and(array_filter(array_keys($findings), fn ($key) => str_contains($key, 'runtime/') || str_contains($key, 'web/assets')))->toBe([]);
});

it('skips the rules that need a booted Laravel app', function () {
    $report = Standalone::scan($this->project(['index.php' => "<?php\necho 'hi';\n"]), offline: true, baseline: false);
    $categories = collect($report->rules)->map(fn ($rule) => $rule->category())->unique()->values()->all();

    expect($categories)->not->toContain(Category::Runtime)
        ->toContain(Category::Code, Category::Frontend, Category::Infrastructure, Category::Dependencies, Category::Filesystem)
        ->and($report->production)->toBeFalse();
});

it('reads risk-analyzer.php from the project, or --config', function () {
    $root = $this->project([
        'lib/a.php' => "<?php\neval(\$_GET['x']);\n",
        'other/b.php' => "<?php\neval(\$_GET['x']);\n",
        'risk-analyzer.php' => "<?php\nreturn ['paths' => ['lib'], 'rules' => ['disabled' => ['frontend-debug']]];\n",
    ]);
    $files = fn (Report $report) => collect($report->findings)->where('rule', 'code-execution')->pluck('file')->values()->all();

    expect($files(Standalone::scan($root, offline: true, baseline: false)))->toBe(['lib/a.php'])
        ->and(Standalone::make($root)->rules())->not->toHaveKey('frontend-debug');

    file_put_contents($root.'/custom.php', "<?php\nreturn ['paths' => ['other']];\n");

    expect($files(Standalone::scan($root, $root.'/custom.php', offline: true, baseline: false)))->toBe(['other/b.php'])
        ->and(fn () => Standalone::make($root.'/missing'))->toThrow(InvalidArgumentException::class, 'does not exist')
        ->and(fn () => Standalone::make($root, $root.'/nope.php'))->toThrow(InvalidArgumentException::class, 'Config file');
});

it('works as a PHPUnit assertion', function () {
    Standalone::scan($this->project(['src/ok.php' => "<?php\necho htmlspecialchars(\$_GET['q']);\n"]), offline: true, baseline: false)->assertClean('high');

    expect(fn () => Standalone::scan($this->project(['src/bad.php' => "<?php\necho \$_GET['q'];\n"]), offline: true, baseline: false)->assertClean('high'))
        ->toThrow(AssertionFailedError::class, 'xss-echo');
});

it('runs from vendor/bin/risk-analyzer', function () {
    $root = $this->project(yiiProject());
    $run = function (array $arguments) {
        $process = new Process([PHP_BINARY, __DIR__.'/../../bin/risk-analyzer', ...$arguments]);
        $process->run();

        return $process;
    };

    $scan = $run(['scan', '--project='.$root, '--offline', '--no-baseline', '--format=json']);
    $json = json_decode($scan->getOutput(), true);

    expect($scan->getExitCode())->toBe(1)
        ->and(collect($json['findings'])->pluck('rule')->unique()->sort()->values()->all())->toContain('sql-injection', 'xss-echo', 'open-redirect');

    $rules = $run(['rules', '--project', $root]);

    expect($rules->getExitCode())->toBe(0)
        ->and($rules->getOutput())->toContain('xss-twig')->not->toContain('debug-mode');

    $missing = $run(['scan', '--project='.$root.'/missing']);

    expect($missing->getExitCode())->toBe(2)
        ->and($missing->getErrorOutput())->toContain('does not exist');

    $clean = $run(['scan', '--project='.$this->project(['index.php' => "<?php\necho 'ok';\n"]), '--offline', '--no-baseline']);

    expect($clean->getExitCode())->toBe(0)->and($clean->getOutput())->toContain('PASS');
});

it('checks Twig templates in Laravel apps using TwigBridge', function () {
    $report = app(RiskAnalyzer::class)->scan(only: ['xss-twig'], baseline: false, basePath: $this->project([
        'resources/views/search.twig' => "{{ request('q')|raw }}\n{{ request().input('q')|raw }}\n{{ old('name')|raw }}\n{{ page.body|raw }}\n{{ request('q') }}\n",
    ]));

    expect(standaloneFindings($report))->toBe([
        'xss-twig@resources/views/search.twig:1' => 'high',
        'xss-twig@resources/views/search.twig:2' => 'high',
        'xss-twig@resources/views/search.twig:3' => 'high',
        'xss-twig@resources/views/search.twig:4' => 'low',
    ]);
});

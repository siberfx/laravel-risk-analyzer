<?php

use Siberfx\RiskAnalyzer\Code\Analyzer;
use Siberfx\RiskAnalyzer\Contracts\CodeRule;
use Siberfx\RiskAnalyzer\Finding;
use Siberfx\RiskAnalyzer\RiskAnalyzer;
use Siberfx\RiskAnalyzer\Tests\TestCase;

uses(TestCase::class)->in('Unit', 'Feature');

/**
 * Runs every code rule over a PHP snippet ("<?php" is added when missing).
 *
 * @return list<Finding>
 */
function analyse(string $code, string $path = 'app/Http/Controllers/DemoController.php'): array
{
    if (! str_starts_with(ltrim($code), '<?php')) {
        $code = "<?php\n".$code;
    }

    $rules = array_values(array_filter(app(RiskAnalyzer::class)->rules(), fn ($rule) => $rule instanceof CodeRule));

    return (new Analyzer)->analyseSource($path, $code, $rules);
}

/**
 * Wraps statements in a controller action that receives the request.
 */
function controllerAction(string $body): string
{
    return "<?php\nnamespace App\\Http\\Controllers;\n\nuse Illuminate\\Http\\Request;\nuse Illuminate\\Support\\Facades\\DB;\n\nclass DemoController\n{\n    public function __invoke(Request \$request)\n    {\n{$body}\n    }\n}\n";
}

/**
 * @return list<Finding>
 */
function findingsFor(string $rule, string $code, string $path = 'app/Http/Controllers/DemoController.php'): array
{
    return array_values(array_filter(analyse($code, $path), fn (Finding $finding) => $finding->rule === $rule));
}

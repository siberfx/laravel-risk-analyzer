<?php

namespace Siberfx\RiskAnalyzer\Facades;

use Illuminate\Support\Facades\Facade;

/**
 * @method static \Siberfx\RiskAnalyzer\Report scan(list<string> $only = [], list<string> $skip = [], ?bool $production = null, bool $offline = false, list<string>|null $files = null, string|false|null $baseline = null, ?string $basePath = null)
 * @method static array<string, \Siberfx\RiskAnalyzer\Contracts\Rule> rules()
 * @method static \Siberfx\RiskAnalyzer\RiskAnalyzer extend(\Siberfx\RiskAnalyzer\Contracts\Rule|string $rule)
 *
 * @see \Siberfx\RiskAnalyzer\RiskAnalyzer
 */
final class RiskAnalyzer extends Facade
{
    protected static function getFacadeAccessor(): string
    {
        return \Siberfx\RiskAnalyzer\RiskAnalyzer::class;
    }
}

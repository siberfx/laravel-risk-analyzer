<?php

namespace Siberfx\RiskAnalyzer\Attributes;

use Attribute;

/**
 * Skips a route in the route rules (unprotected-route, csrf-exclusions,
 * dev-tools-exposed). Put it on a route closure, a controller method, or a
 * controller class to cover all of its routes. No rule ids skips them all.
 *
 * Safe without the package installed (composer install --no-dev): PHP only
 * loads an attribute's class when it is instantiated, which only the scanner does.
 */
#[Attribute(Attribute::TARGET_CLASS | Attribute::TARGET_METHOD | Attribute::TARGET_FUNCTION)]
final class RiskAnalyzerIgnore
{
    /** @var list<string> */
    public readonly array $rules;

    /**
     * @param  string|list<string>  $rules
     */
    public function __construct(string|array $rules = [], public readonly ?string $reason = null)
    {
        $this->rules = (array) $rules;
    }
}

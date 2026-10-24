<?php

namespace Siberfx\RiskAnalyzer;

use Illuminate\Contracts\Foundation\Application;
use InvalidArgumentException;
use Siberfx\RiskAnalyzer\Code\Analyzer;
use Siberfx\RiskAnalyzer\Contracts\CodeRule;
use Siberfx\RiskAnalyzer\Contracts\ProjectRule;
use Siberfx\RiskAnalyzer\Contracts\Rule;
use Siberfx\RiskAnalyzer\Rules\Code;
use Siberfx\RiskAnalyzer\Rules\Dependencies;
use Siberfx\RiskAnalyzer\Rules\Filesystem;
use Siberfx\RiskAnalyzer\Rules\Runtime;
use Throwable;

final class RiskAnalyzer
{
    /** @var list<class-string<Rule>> */
    public const array BUILT_IN = [
        Code\SqlInjection::class,
        Code\CommandInjection::class,
        Code\CodeExecution::class,
        Code\InsecureDeserialization::class,
        Code\PathTraversal::class,
        Code\ServerSideRequestForgery::class,
        Code\OpenRedirect::class,
        Code\XmlExternalEntities::class,
        Code\MassAssignment::class,
        Code\UnescapedBladeOutput::class,
        Code\HardcodedSecret::class,
        Code\WeakCryptography::class,
        Code\InsecureRandomness::class,
        Code\DisabledTlsVerification::class,
        Code\DebugLeftovers::class,
        Runtime\DebugMode::class,
        Runtime\EncryptionKey::class,
        Runtime\SessionCookies::class,
        Runtime\CsrfExclusions::class,
        Runtime\RouteProtection::class,
        Runtime\CorsPolicy::class,
        Runtime\PasswordHashing::class,
        Runtime\DevToolsExposure::class,
        Runtime\SecurityHeaders::class,
        Runtime\TrustedProxies::class,
        Runtime\InsecureAppUrl::class,
        Runtime\DatabaseTls::class,
        Dependencies\VulnerableDependencies::class,
        Dependencies\AbandonedPackages::class,
        Dependencies\ComposerHardening::class,
        Dependencies\UnsupportedRuntime::class,
        Filesystem\PublicDirectoryExposure::class,
        Filesystem\SecretsInVersionControl::class,
    ];

    /** @var list<Rule|class-string<Rule>> */
    private array $extensions = [];

    /**
     * @param  array<string, mixed>  $config
     */
    public function __construct(
        private readonly Application $app,
        private readonly array $config,
    ) {}

    /**
     * Register an extra rule at runtime (e.g. from a service provider).
     *
     * @param  Rule|class-string<Rule>  $rule
     */
    public function extend(Rule|string $rule): self
    {
        $this->extensions[] = $rule;

        return $this;
    }

    /**
     * Every enabled rule, keyed by id.
     *
     * @return array<string, Rule>
     */
    public function rules(): array
    {
        $disabled = (array) ($this->config['rules']['disabled'] ?? []);
        $rules = [];

        foreach ([...self::BUILT_IN, ...(array) ($this->config['rules']['extra'] ?? []), ...$this->extensions] as $rule) {
            $rule = $this->resolve($rule);

            if (! in_array($rule->id(), $disabled, true)) {
                $rules[$rule->id()] = $rule;
            }
        }

        return $rules;
    }

    /**
     * Run the scan.
     *
     * @param  list<string>  $only  rule ids or category names to run
     * @param  list<string>  $skip  rule ids or category names to leave out
     * @param  list<string>|null  $files  restrict code rules to these relative paths
     * @param  string|false|null  $baseline  baseline path, false to ignore it, null for the configured one
     */
    public function scan(
        array $only = [],
        array $skip = [],
        ?bool $production = null,
        bool $offline = false,
        ?array $files = null,
        string|false|null $baseline = null,
        ?string $basePath = null,
    ): Report {
        $started = microtime(true);
        $production ??= $this->app->environment((array) ($this->config['production_environments'] ?? ['production']));

        $context = new ScanContext($this->app, $basePath ?? $this->app->basePath(), $this->config, $production, $offline, $files);
        $rules = $this->select($this->rules(), $only, $skip);
        $findings = [];

        $codeRules = array_values(array_filter($rules, fn (Rule $rule) => $rule instanceof CodeRule));

        try {
            array_push($findings, ...(new Analyzer)->analyse($context, $codeRules));
        } catch (Throwable $exception) {
            $findings[] = $this->ruleError('code-analysis', $exception);
        }

        foreach ($rules as $rule) {
            if (! $rule instanceof ProjectRule) {
                continue;
            }

            // File-scoped scans (--changed) only make sense for code rules.
            if ($files !== null && $rule->category() !== Category::Code) {
                continue;
            }

            try {
                foreach ($rule->run($context) as $finding) {
                    $findings[] = $finding;
                }
            } catch (Throwable $exception) {
                $findings[] = $this->ruleError($rule->id(), $exception);
            }
        }

        $findings = $this->finalise($findings, $baseline === false ? new Baseline : Baseline::load($this->baselinePath($baseline, $context)));

        return new Report($findings, $rules, microtime(true) - $started, $production);
    }

    public function baselinePath(?string $path = null, ?ScanContext $context = null): string
    {
        $path ??= (string) ($this->config['baseline'] ?? 'risk-analyzer-baseline.json');

        if (preg_match('#^([a-zA-Z]:)?[\\\\/]#', $path)) {
            return $path;
        }

        return $context?->basePath($path) ?? $this->app->basePath($path);
    }

    /**
     * @param  array<string, Rule>  $rules
     * @param  list<string>  $only
     * @param  list<string>  $skip
     * @return array<string, Rule>
     */
    private function select(array $rules, array $only, array $skip): array
    {
        $matches = fn (Rule $rule, array $selectors) => in_array($rule->id(), $selectors, true)
            || in_array($rule->category()->value, $selectors, true);

        foreach ([...$only, ...$skip] as $selector) {
            if (! array_any($rules, fn (Rule $rule) => $matches($rule, [$selector]))) {
                throw new InvalidArgumentException("Unknown rule or category [{$selector}]. Run php artisan risk-analyzer:rules to list them.");
            }
        }

        return array_filter($rules, fn (Rule $rule) => ($only === [] || $matches($rule, $only)) && ! $matches($rule, $skip));
    }

    /**
     * Applies severity overrides and the baseline, removes duplicates and sorts.
     *
     * @param  list<Finding>  $findings
     * @return list<Finding>
     */
    private function finalise(array $findings, Baseline $baseline): array
    {
        $overrides = (array) ($this->config['rules']['severity'] ?? []);
        $unique = [];

        foreach ($findings as $finding) {
            if (isset($overrides[$finding->rule])) {
                $finding->severity = Severity::fromLoose($overrides[$finding->rule]);
            }

            $finding->baselined = $baseline->contains($finding);
            $unique[$finding->fingerprint().':'.$finding->line] ??= $finding;
        }

        $findings = array_values($unique);

        usort($findings, fn (Finding $a, Finding $b) => [$b->severity->weight(), $a->file ?? '~', $a->line ?? 0, $a->rule]
            <=> [$a->severity->weight(), $b->file ?? '~', $b->line ?? 0, $b->rule]);

        return $findings;
    }

    /**
     * @param  Rule|class-string<Rule>  $rule
     */
    private function resolve(Rule|string $rule): Rule
    {
        if ($rule instanceof Rule) {
            return $rule;
        }

        $instance = $this->app->make($rule, $rule === Code\HardcodedSecret::class
            ? ['allow' => (array) ($this->config['secrets']['allow'] ?? [])]
            : []);

        if (! $instance instanceof Rule) {
            throw new InvalidArgumentException("[{$rule}] must implement ".Rule::class.'.');
        }

        if (! $instance instanceof CodeRule && ! $instance instanceof ProjectRule) {
            throw new InvalidArgumentException("[{$rule}] must implement ".CodeRule::class.' or '.ProjectRule::class.'.');
        }

        return $instance;
    }

    private function ruleError(string $rule, Throwable $exception): Finding
    {
        return new Finding(
            rule: 'scanner-error',
            severity: Severity::Info,
            message: "Rule {$rule} failed: ".$exception->getMessage(),
            snippet: $rule,
        );
    }
}

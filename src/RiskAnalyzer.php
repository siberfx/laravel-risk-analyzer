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
use Siberfx\RiskAnalyzer\Rules\Frontend;
use Siberfx\RiskAnalyzer\Rules\Infrastructure;
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
        Frontend\FrontendXss::class,
        Frontend\FrontendSecret::class,
        Frontend\FrontendCodeExecution::class,
        Frontend\FrontendOpenRedirect::class,
        Frontend\FrontendPostMessage::class,
        Frontend\FrontendTokenStorage::class,
        Frontend\FrontendDebug::class,
        Infrastructure\DockerfileHardening::class,
        Infrastructure\ComposeHardening::class,
        Infrastructure\ShellScriptRisks::class,
        Infrastructure\CiWorkflowRisks::class,
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
        Runtime\PhpConfiguration::class,
        Dependencies\VulnerableDependencies::class,
        Dependencies\AbandonedPackages::class,
        Dependencies\ComposerHardening::class,
        Dependencies\UnsupportedRuntime::class,
        Filesystem\PublicDirectoryExposure::class,
        Filesystem\SecretsInVersionControl::class,
        Filesystem\FilePermissions::class,
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
     * @param  list<string>|null  $frontend  limit the scan to frontend checks (null: no limit); folders that replace frontend.paths, or [] for the configured ones
     * @param  list<string>|null  $infrastructure  limit the scan to Docker/CI/script checks (null: no limit); folders that replace infrastructure.paths, or [] for the configured ones
     */
    public function scan(
        array $only = [],
        array $skip = [],
        ?bool $production = null,
        bool $offline = false,
        ?array $files = null,
        string|false|null $baseline = null,
        ?string $basePath = null,
        ?array $frontend = null,
        ?array $infrastructure = null,
    ): Report {
        $started = microtime(true);
        $production ??= $this->app->environment((array) ($this->config['production_environments'] ?? ['production']));

        $scopes = array_keys(array_filter(['frontend' => $frontend, 'infrastructure' => $infrastructure], fn (?array $folders) => $folders !== null));
        $context = new ScanContext($this->app, $basePath ?? $this->app->basePath(), $this->config, $production, $offline, $files,
            $frontend ?: null, $infrastructure ?: null, $scopes);

        foreach (['Frontend' => $frontend, 'Infrastructure' => $infrastructure] as $label => $folders) {
            foreach ($folders ?? [] as $folder) {
                if (! is_dir($context->basePath($folder))) {
                    throw new InvalidArgumentException("{$label} folder [{$folder}] does not exist.");
                }
            }
        }

        $rules = $this->select($this->rules(), $only, $skip, $scopes);
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
            if ($files !== null && ! in_array($rule->category(), [Category::Code, Category::Frontend, Category::Infrastructure], true)) {
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

        $scannedFrontend = array_any($rules, fn (Rule $rule) => $rule->category() === Category::Frontend)
            ? array_values(array_filter($context->frontendRoots(), fn (string $root) => is_dir($context->basePath($root))))
            : [];

        $scannedInfrastructure = array_any($rules, fn (Rule $rule) => $rule->category() === Category::Infrastructure)
            ? array_values(array_filter($context->infrastructureRoots(), fn (string $root) => is_dir($context->basePath($root))))
            : [];

        return new Report($findings, $rules, microtime(true) - $started, $production, $scannedFrontend,
            array_map(fn (string $root) => $root === '' ? '.' : $root, $scannedInfrastructure));
    }

    /**
     * The rules that belong to the requested scopes: each scope's category
     * plus the dependency rule that covers it (npm advisories for frontend
     * code, base image versions for infrastructure). All rules when unscoped.
     *
     * @param  array<string, Rule>  $rules
     * @param  list<string>  $scopes
     * @return array<string, Rule>
     */
    private function inScope(array $rules, array $scopes): array
    {
        if ($scopes === []) {
            return $rules;
        }

        $related = ['frontend' => 'vulnerable-dependency', 'infrastructure' => 'unsupported-runtime'];

        return array_filter($rules, fn (Rule $rule) => array_any($scopes, fn (string $scope) => $rule->category()->value === $scope || $rule->id() === $related[$scope]));
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
     * @param  list<string>  $scopes
     * @return array<string, Rule>
     */
    private function select(array $rules, array $only, array $skip, array $scopes = []): array
    {
        $matches = fn (Rule $rule, array $selectors) => in_array($rule->id(), $selectors, true)
            || in_array($rule->category()->value, $selectors, true);

        foreach ([...$only, ...$skip] as $selector) {
            if (! array_any($rules, fn (Rule $rule) => $matches($rule, [$selector]))) {
                throw new InvalidArgumentException("Unknown rule or category [{$selector}]. Run php artisan risk-analyzer:rules to list them.");
            }
        }

        $selected = array_filter($this->inScope($rules, $scopes), fn (Rule $rule) => ($only === [] || $matches($rule, $only)) && ! $matches($rule, $skip));

        if ($selected === [] && $only !== [] && $scopes !== []) {
            throw new InvalidArgumentException('None of ['.implode(', ', $only).'] belong to the --'.implode(' / --', $scopes).' scan.');
        }

        return $selected;
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

        $instance = $this->app->make($rule, in_array($rule, [Code\HardcodedSecret::class, Frontend\FrontendSecret::class], true)
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

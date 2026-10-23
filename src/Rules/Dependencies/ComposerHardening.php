<?php

namespace Siberfx\RiskAnalyzer\Rules\Dependencies;

use Siberfx\RiskAnalyzer\Category;
use Siberfx\RiskAnalyzer\Finding;
use Siberfx\RiskAnalyzer\Rules\AbstractProjectRule;
use Siberfx\RiskAnalyzer\ScanContext;
use Siberfx\RiskAnalyzer\Severity;

final class ComposerHardening extends AbstractProjectRule
{
    public function id(): string
    {
        return 'composer-hardening';
    }

    public function title(): string
    {
        return 'Composer supply-chain settings';
    }

    public function description(): string
    {
        return 'composer.json settings that weaken the supply chain: secure-http off, plain-HTTP repositories, "allow-plugins": true, installed Composer plugins that are not allow-listed, a missing lock file, dev stability without prefer-stable.';
    }

    public function category(): Category
    {
        return Category::Dependencies;
    }

    public function severity(): Severity
    {
        return Severity::High;
    }

    public function run(ScanContext $context): iterable
    {
        $composer = $context->readJson('composer.json');

        if ($composer === null) {
            return;
        }

        $config = (array) ($composer['config'] ?? []);

        if (($config['secure-http'] ?? true) === false) {
            yield $this->finding('"secure-http": false lets Composer download packages over plain HTTP.', null,
                'Remove the setting and use HTTPS repositories.', 'composer.json', anchor: 'secure-http');
        }

        foreach ((array) ($composer['repositories'] ?? []) as $repository) {
            $url = is_array($repository) ? (string) ($repository['url'] ?? '') : '';

            if (str_starts_with(strtolower($url), 'http://')) {
                yield $this->finding("Repository {$url} is served over plain HTTP.", null,
                    'Use the HTTPS URL of the repository.', 'composer.json', anchor: 'repo.'.$url);
            }
        }

        $allowPlugins = $config['allow-plugins'] ?? null;

        if ($allowPlugins === true) {
            yield $this->finding('"allow-plugins": true lets every installed package run code as a Composer plugin.', Severity::Medium,
                'List the plugins you trust: "allow-plugins": {"pestphp/pest-plugin": true}.', 'composer.json', anchor: 'allow-plugins');
        }

        if (! $context->exists('composer.lock')) {
            yield $this->finding('composer.lock is missing, so every install may resolve different (and unaudited) versions.', Severity::Medium,
                'Commit composer.lock for applications.', 'composer.json', anchor: 'lock-missing');
        } else {
            yield from $this->unlistedPlugins($context, is_array($allowPlugins) ? $allowPlugins : []);
        }

        if (($composer['minimum-stability'] ?? 'stable') === 'dev' && ! ($composer['prefer-stable'] ?? false)) {
            yield $this->finding('"minimum-stability": "dev" without "prefer-stable" installs development branches.', Severity::Low,
                'Add "prefer-stable": true.', 'composer.json', anchor: 'stability');
        }
    }

    /**
     * @param  array<string, bool>  $allowed
     * @return iterable<Finding>
     */
    private function unlistedPlugins(ScanContext $context, array $allowed): iterable
    {
        $lock = $context->readJson('composer.lock') ?? [];

        foreach (['packages', 'packages-dev'] as $section) {
            foreach ((array) ($lock[$section] ?? []) as $package) {
                if (($package['type'] ?? null) !== 'composer-plugin' || ! isset($package['name'])) {
                    continue;
                }

                $name = (string) $package['name'];
                $listed = array_any(array_keys($allowed), fn (string $pattern) => fnmatch($pattern, $name));

                if (! $listed && ! in_array($name, ['composer/installers', 'composer/package-versions-deprecated'], true)) {
                    yield $this->finding("Composer plugin {$name} is installed but not in allow-plugins.", Severity::Low,
                        'Decide explicitly: add it to config.allow-plugins as true (trusted) or false (never run).',
                        'composer.json', anchor: 'plugin.'.$name);
                }
            }
        }
    }
}

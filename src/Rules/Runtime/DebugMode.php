<?php

namespace Siberfx\RiskAnalyzer\Rules\Runtime;

use Siberfx\RiskAnalyzer\Category;
use Siberfx\RiskAnalyzer\Rules\AbstractProjectRule;
use Siberfx\RiskAnalyzer\ScanContext;
use Siberfx\RiskAnalyzer\Severity;

final class DebugMode extends AbstractProjectRule
{
    public function id(): string
    {
        return 'debug-mode';
    }

    public function title(): string
    {
        return 'Debug mode in production';
    }

    public function description(): string
    {
        return 'app.debug enabled while running in a production environment, which shows stack traces, environment variables and queries to visitors. Also flags a production log level of "debug".';
    }

    public function category(): Category
    {
        return Category::Runtime;
    }

    public function severity(): Severity
    {
        return Severity::Critical;
    }

    public function run(ScanContext $context): iterable
    {
        if (! $context->production) {
            return;
        }

        $config = $context->settings();

        if ($config->get('app.debug') === true) {
            yield $this->finding('APP_DEBUG is true in production.', null,
                'Set APP_DEBUG=false in the production environment and re-cache the config (php artisan config:cache).',
                anchor: 'app.debug');
        }

        $channel = $config->get('logging.default');
        $level = $config->get("logging.channels.{$channel}.level");

        if ($level === 'debug') {
            yield $this->finding("The '{$channel}' log channel records debug-level messages in production.", Severity::Low,
                'Use LOG_LEVEL=warning (or info) in production; debug logs tend to capture request payloads and secrets.',
                anchor: 'logging.level');
        }
    }
}

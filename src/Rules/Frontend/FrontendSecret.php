<?php

namespace Siberfx\RiskAnalyzer\Rules\Frontend;

use Siberfx\RiskAnalyzer\Finding;
use Siberfx\RiskAnalyzer\Frontend\FrontendSource;
use Siberfx\RiskAnalyzer\ScanContext;
use Siberfx\RiskAnalyzer\Severity;
use Siberfx\RiskAnalyzer\Support\Secrets;

final class FrontendSecret extends AbstractFrontendRule
{
    /** Env prefixes that bundlers copy into the browser build. */
    private const string PUBLIC_PREFIX = '(VITE|MIX|NG_APP|REACT_APP|VUE_APP|NEXT_PUBLIC|NUXT_PUBLIC|PUBLIC)_';

    private const string SECRET_ENV_NAME = '/(SECRET|PASSWORD|PASSWD|PRIVATE|ACCESS_KEY|AUTH_TOKEN|ACCESS_TOKEN|API_TOKEN|CREDENTIALS?)/';

    /** Names that are public by design. */
    private const string PUBLIC_NAME = '/(PUBLIC_KEY|PUBLISHABLE|_PK$|SITE_KEY|SITEKEY|CLIENT_ID|APP_ID)/';

    private const array ENV_FILES = ['.env', '.env.example', '.env.local', '.env.production', '.env.staging'];

    /** @var list<string> */
    private array $allow;

    /**
     * @param  list<string>  $allow  literal values that are fine to commit (secrets.allow)
     */
    public function __construct(array $allow = [])
    {
        $this->allow = $allow;
    }

    public function id(): string
    {
        return 'frontend-secret';
    }

    public function title(): string
    {
        return 'Secret in the frontend bundle';
    }

    public function description(): string
    {
        return 'Everything in frontend code ends up in the browser. Reports provider tokens (AWS, Stripe, GitHub, OpenAI...) and literal values assigned to password/secret/api_key names in JS, TS and Vue files, and VITE_/NG_APP_/REACT_APP_/MIX_ env variables named like secrets, which bundlers copy into the build.';
    }

    public function severity(): Severity
    {
        return Severity::Critical;
    }

    public function run(ScanContext $context): iterable
    {
        yield from parent::run($context);

        $folders = ['', ...array_filter($context->frontendRoots(), fn (string $root) => is_dir($context->basePath($root)))];

        foreach (array_unique($folders) as $folder) {
            foreach (self::ENV_FILES as $name) {
                $path = $folder === '' ? $name : $context->relative($context->basePath($folder).'/'.$name);
                $contents = $context->read($path);

                if ($contents !== null) {
                    yield from $this->inspectEnv($path, $contents);
                }
            }
        }
    }

    protected function inspect(FrontendSource $file): iterable
    {
        // Every string literal, for provider token formats.
        foreach ($file->matches('/([\'"`])((?:\\\\.|(?!\1)[^\\\\\n])*)\1/') as $match) {
            $value = $match['groups'][2];
            $label = Secrets::tokenFormat($value);

            if ($label === null || in_array($value, $this->allow, true)) {
                continue;
            }

            // Browser keys for Maps/Firebase are meant to be public, but must be restricted.
            yield $label === 'Google API key'
                ? $this->report($file, $match['line'], 'Google API key in frontend code.', Severity::Low,
                    'Browser keys are public by design: restrict this key to your HTTP referrers and to the APIs the page uses in the Google Cloud console.')
                : $this->report($file, $match['line'], "{$label} in frontend code is shipped to every visitor.", null,
                    'Revoke and rotate the credential. Keep it on the server and call it from a Laravel route instead of from the browser.',
                    ['type' => $label]);
        }

        // password: '...', const apiKey = "...", secret = `...`
        foreach ($file->matches('/(?<![\w$])([\w$]+)[\'"]?\s*[:=]\s*([\'"`])([^\'"`\n]+)\2/') as $match) {
            [, $name, , $value] = $match['groups'];

            // apiSecret -> api_Secret, so camelCase names match too.
            if (preg_match(Secrets::SECRET_NAME, (string) preg_replace('/([a-z\d])([A-Z])/', '$1_$2', $name))
                && ! preg_match('/(name|field|label|placeholder|type|rule|confirmation|url|route|path|header|key_name|input|error|message|text|title|hint)$/i', $name)
                && Secrets::tokenFormat($value) === null
                && Secrets::looksReal($value, $this->allow)) {
                yield $this->report($file, $match['line'], "A literal value is assigned to '{$name}' in frontend code.", Severity::High,
                    'Anything in the bundle is readable by visitors. Keep the secret on the server and proxy the call through Laravel.');
            }
        }

        // import.meta.env.VITE_STRIPE_SECRET, process.env.REACT_APP_API_SECRET
        foreach ($file->matches('/\b(?:import\s*\.\s*meta|process)\s*\.\s*env\s*\.\s*('.self::PUBLIC_PREFIX.'\w+)/') as $match) {
            $name = $match['groups'][1];

            if ($this->isSecretEnvName($name)) {
                yield $this->report($file, $match['line'], "{$name} is read in frontend code, so its value is built into the bundle.", Severity::Medium,
                    'Secrets must not have a public prefix. Move the call that needs it to a Laravel route.');
            }
        }
    }

    /**
     * @return iterable<Finding>
     */
    private function inspectEnv(string $path, string $contents): iterable
    {
        $file = new FrontendSource($path, $contents);

        foreach (preg_split('/\R/', $contents) ?: [] as $index => $line) {
            if (! preg_match('/^\s*(?:export\s+)?('.self::PUBLIC_PREFIX.'\w+)\s*=\s*(.*)$/', $line, $match) || ! $this->isSecretEnvName($match[1])) {
                continue;
            }

            $value = trim(trim($match[3]), '"\'');
            $template = str_ends_with($path, '.example');

            if ($file->isIgnored($this->id(), $index + 1)) {
                continue;
            }

            yield $this->finding(
                "{$match[1]} has a public prefix, so the bundler copies its value into the browser build".($template ? ' (from the template).' : '.'),
                $value !== '' && ! $template ? Severity::High : Severity::Medium,
                'Rename it without the '.explode('_', $match[1])[0].'_ prefix, keep it on the server and proxy the call through Laravel. Rotate it if a build with it was deployed.',
                $path,
                $index + 1,
                $match[1],
            );
        }
    }

    private function isSecretEnvName(string $name): bool
    {
        return preg_match(self::SECRET_ENV_NAME, $name) === 1 && preg_match(self::PUBLIC_NAME, $name) !== 1;
    }
}

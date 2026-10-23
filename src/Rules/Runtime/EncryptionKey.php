<?php

namespace Siberfx\RiskAnalyzer\Rules\Runtime;

use Illuminate\Encryption\Encrypter;
use Siberfx\RiskAnalyzer\Category;
use Siberfx\RiskAnalyzer\Rules\AbstractProjectRule;
use Siberfx\RiskAnalyzer\ScanContext;
use Siberfx\RiskAnalyzer\Severity;

final class EncryptionKey extends AbstractProjectRule
{
    public function id(): string
    {
        return 'encryption-key';
    }

    public function title(): string
    {
        return 'Encryption key';
    }

    public function description(): string
    {
        return 'APP_KEY missing, of the wrong length for app.cipher, a weak cipher, or a production key that is the same as the committed .env.example key.';
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
        $config = $context->settings();
        $key = (string) $config->get('app.key', '');
        $cipher = (string) $config->get('app.cipher', 'AES-256-CBC');

        if ($key === '') {
            yield $this->finding('APP_KEY is not set, so sessions, cookies and encrypted values are not protected.', null,
                'Run php artisan key:generate (and keep the key out of version control).', anchor: 'app.key');

            return;
        }

        if (! in_array(strtolower($cipher), ['aes-256-cbc', 'aes-256-gcm'], true)) {
            yield $this->finding("app.cipher is {$cipher}; AES-256 is recommended.", Severity::Medium,
                'Use AES-256-CBC (the default) or AES-256-GCM and generate a matching key.', anchor: 'app.cipher');
        }

        $raw = str_starts_with($key, 'base64:') ? base64_decode(substr($key, 7), true) : $key;

        if ($raw === false || ! Encrypter::supported($raw, $cipher)) {
            yield $this->finding("APP_KEY is not a valid key for {$cipher}.", Severity::High,
                'Generate a new key with php artisan key:generate --show.', anchor: 'app.key-length');
        }

        if ($context->production && $this->exampleKey($context) === $key) {
            yield $this->finding('The production APP_KEY is the key committed in .env.example.', null,
                'Generate a unique key for production and remove the real key from .env.example.', '.env.example', anchor: 'app.key-example');
        }
    }

    private function exampleKey(ScanContext $context): ?string
    {
        $example = $context->read('.env.example');

        if ($example !== null && preg_match('/^APP_KEY=("?)(.+?)\1\s*$/m', $example, $match)) {
            return $match[2];
        }

        return null;
    }
}

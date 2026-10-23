<?php

namespace Siberfx\RiskAnalyzer\Rules\Runtime;

use Siberfx\RiskAnalyzer\Category;
use Siberfx\RiskAnalyzer\Rules\AbstractProjectRule;
use Siberfx\RiskAnalyzer\ScanContext;
use Siberfx\RiskAnalyzer\Severity;

final class PasswordHashing extends AbstractProjectRule
{
    public function id(): string
    {
        return 'password-hashing';
    }

    public function title(): string
    {
        return 'Password hashing cost';
    }

    public function description(): string
    {
        return 'bcrypt rounds below 10, and Argon2 memory or time costs below the OWASP minimum (19 MiB, 2 iterations).';
    }

    public function category(): Category
    {
        return Category::Runtime;
    }

    public function severity(): Severity
    {
        return Severity::Medium;
    }

    public function run(ScanContext $context): iterable
    {
        $hashing = (array) $context->settings()->get('hashing', []);
        $driver = $hashing['driver'] ?? 'bcrypt';

        if ($driver === 'bcrypt') {
            $rounds = (int) ($hashing['bcrypt']['rounds'] ?? 12);

            if ($rounds < 10) {
                yield $this->finding("bcrypt uses {$rounds} rounds.", null, 'Use at least 12 rounds (BCRYPT_ROUNDS=12).', 'config/hashing.php', anchor: 'hashing.bcrypt');
            }

            return;
        }

        $argon = (array) ($hashing['argon'] ?? []);

        if ((int) ($argon['memory'] ?? 65536) < 19456 || (int) ($argon['time'] ?? 4) < 2) {
            yield $this->finding('Argon2 memory/time cost is below the OWASP minimum.', null,
                'Use memory >= 19456 (KiB) and time >= 2.', 'config/hashing.php', anchor: 'hashing.argon');
        }
    }
}

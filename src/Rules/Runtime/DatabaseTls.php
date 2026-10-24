<?php

namespace Siberfx\RiskAnalyzer\Rules\Runtime;

use Siberfx\RiskAnalyzer\Category;
use Siberfx\RiskAnalyzer\Rules\AbstractProjectRule;
use Siberfx\RiskAnalyzer\ScanContext;
use Siberfx\RiskAnalyzer\Severity;

final class DatabaseTls extends AbstractProjectRule
{
    /** Hostname suffixes of private networks (Docker, Kubernetes, mDNS, home and cloud internal DNS). */
    private const array PRIVATE_SUFFIXES = ['.local', '.localhost', '.internal', '.lan', '.home.arpa', '.svc', '.cluster.local'];

    public function id(): string
    {
        return 'database-tls';
    }

    public function title(): string
    {
        return 'Database connection without TLS';
    }

    public function description(): string
    {
        return 'MySQL/MariaDB connections to a public host without an SSL CA (Pdo\Mysql::ATTR_SSL_CA), and PostgreSQL connections with sslmode disable/allow/prefer (prefer is Laravel\'s default and falls back to plain text without verifying the server). Local, socket, private-range and single-label (Docker service) hosts are skipped.';
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
        if (! $context->production) {
            return;
        }

        foreach ((array) $context->settings()->get('database.connections', []) as $name => $connection) {
            if (! is_array($connection) || ! in_array($connection['driver'] ?? null, ['mysql', 'mariadb', 'pgsql'], true)) {
                continue;
            }

            $url = is_string($connection['url'] ?? null) && $connection['url'] !== '' ? $connection['url'] : null;
            parse_str((string) parse_url((string) $url, PHP_URL_QUERY), $query);
            $public = array_values(array_filter($this->hosts($connection, $url), $this->isPublic(...)));

            if ($public === []) {
                continue;
            }

            $host = $public[0];

            if ($connection['driver'] === 'pgsql') {
                $mode = strtolower((string) ($query['sslmode'] ?? $connection['sslmode'] ?? 'prefer'));

                if (in_array($mode, ['disable', 'allow', 'prefer'], true)) {
                    yield $this->finding("Database connection '{$name}' reaches {$host} with sslmode={$mode}, which allows an unencrypted, unverified connection.", null,
                        'Set DB_SSLMODE (sslmode) to verify-full, or at least require.', anchor: 'database-tls.'.$name, meta: ['connection' => $name, 'host' => $host, 'sslmode' => $mode]);
                }

                continue;
            }

            if (! $this->hasMysqlCa((array) ($connection['options'] ?? []))) {
                yield $this->finding("Database connection '{$name}' reaches {$host} without TLS (no SSL CA configured).", null,
                    'Set MYSQL_ATTR_SSL_CA to the server\'s CA bundle so the connection is encrypted and the server is verified.',
                    anchor: 'database-tls.'.$name, meta: ['connection' => $name, 'host' => $host]);
            }
        }
    }

    /**
     * @param  array<string, mixed>  $connection
     * @return list<string>
     */
    private function hosts(array $connection, ?string $url): array
    {
        $hosts = $url !== null ? [(string) parse_url($url, PHP_URL_HOST)] : [];

        foreach ([$connection, (array) ($connection['read'] ?? []), (array) ($connection['write'] ?? [])] as $section) {
            array_push($hosts, ...array_map('strval', (array) ($section['host'] ?? [])));
        }

        // A unix socket without a host never leaves the machine.
        if (($connection['unix_socket'] ?? '') !== '' && $url === null && ($connection['host'] ?? '') === '') {
            return [];
        }

        return array_values(array_unique(array_filter($hosts)));
    }

    private function isPublic(string $host): bool
    {
        $host = strtolower(trim($host, '[]'));

        if (filter_var($host, FILTER_VALIDATE_IP) !== false) {
            return filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) !== false;
        }

        if ($host === 'localhost' || ! str_contains($host, '.')) {
            return false; // Docker/Compose service names such as "mysql" or "db".
        }

        return array_find(self::PRIVATE_SUFFIXES, fn (string $suffix) => str_ends_with($host, $suffix)) === null;
    }

    /**
     * @param  array<array-key, mixed>  $options
     */
    private function hasMysqlCa(array $options): bool
    {
        $key = match (true) {
            defined('Pdo\Mysql::ATTR_SSL_CA') => constant('Pdo\Mysql::ATTR_SSL_CA'),
            defined('PDO::MYSQL_ATTR_SSL_CA') => constant('PDO::MYSQL_ATTR_SSL_CA'),
            default => 1008,
        };

        return is_string($options[$key] ?? null) && $options[$key] !== '';
    }
}

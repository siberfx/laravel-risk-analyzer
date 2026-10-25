<?php

namespace Siberfx\RiskAnalyzer\Rules\Infrastructure;

use Siberfx\RiskAnalyzer\Infrastructure\InfrastructureFile;
use Siberfx\RiskAnalyzer\ScanContext;
use Siberfx\RiskAnalyzer\Severity;
use Siberfx\RiskAnalyzer\Support\Secrets;

final class ComposeHardening extends AbstractInfrastructureRule
{
    /** Container ports of databases, caches, search engines and queues => service. */
    private const array DATA_PORTS = [
        '3306' => 'MySQL/MariaDB', '5432' => 'PostgreSQL', '6379' => 'Redis', '27017' => 'MongoDB', '11211' => 'Memcached',
        '9200' => 'Elasticsearch/OpenSearch', '7700' => 'Meilisearch', '8108' => 'Typesense', '5672' => 'RabbitMQ', '15672' => 'RabbitMQ management',
        '1433' => 'SQL Server', '8123' => 'ClickHouse', '9000' => 'MinIO/PHP-FPM',
    ];

    private const string SECRET_NAME = '/(PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY|ACCESS_KEY|PRIVATE_KEY|APP_KEY)/i';

    public function id(): string
    {
        return 'compose-hardening';
    }

    public function title(): string
    {
        return 'Docker Compose hardening';
    }

    public function description(): string
    {
        return 'Compose files: privileged containers and a mounted Docker socket (high, both give root on the host), network_mode: host, dangerous capabilities and unconfined seccomp/AppArmor, literal secrets in environment:, and database, cache and search ports published on every interface (medium in production compose files, low otherwise).';
    }

    public function severity(): Severity
    {
        return Severity::High;
    }

    protected function kinds(): array
    {
        return [InfrastructureFile::COMPOSE];
    }

    protected function inspect(InfrastructureFile $file, ScanContext $context): iterable
    {
        $production = $file->isProduction();

        foreach ($file->matches('/^\s*privileged:\s*["\']?(true|yes)\b/mi') as $match) {
            yield $this->report($file, $match['line'], 'A privileged container can take over the host.', Severity::High,
                'Remove privileged: true and add only the capabilities the service needs with cap_add.');
        }

        foreach ($file->matches('#/var/run/docker\.sock|(?<![\w/])docker\.sock\b#') as $match) {
            yield $this->report($file, $match['line'], 'The Docker socket is mounted into a container, which gives it root on the host.', Severity::High,
                'Drop the mount, or put a socket proxy (e.g. tecnativa/docker-socket-proxy) in between that only allows the API calls the service needs, read-only.');
        }

        foreach ($file->matches('/^\s*network_mode:\s*["\']?host\b/mi') as $match) {
            yield $this->report($file, $match['line'], 'network_mode: host shares the host network: every port the container opens is open on the host.', Severity::Medium,
                'Use the default bridge network and publish only the ports you need.');
        }

        foreach ($file->matches('/(seccomp|apparmor)[:=]\s*unconfined/i') as $match) {
            yield $this->report($file, $match['line'], "{$match['groups'][1]} is unconfined for this container.", Severity::Medium,
                'Remove the security_opt override so the default profile applies.');
        }

        foreach ($this->items($file, 'cap_add') as [$line, $item]) {
            if (in_array(strtoupper(trim($item, '"\' ')), ['ALL', 'SYS_ADMIN', 'SYS_PTRACE', 'SYS_MODULE', 'NET_ADMIN', 'DAC_READ_SEARCH'], true)) {
                yield $this->report($file, $line, 'cap_add grants '.strtoupper(trim($item, '"\' ')).', enough to escape the container in many setups.', Severity::Medium,
                    'Remove it, or grant a narrower capability (e.g. NET_BIND_SERVICE).');
            }
        }

        foreach ($this->items($file, 'ports') as [$line, $item]) {
            $port = $this->exposedDataPort(trim($item, '"\' '));

            if ($port !== null) {
                yield $this->report($file, $line, self::DATA_PORTS[$port]." port {$port} is published on every network interface.", $production ? Severity::Medium : Severity::Low,
                    'Bind it to localhost ("127.0.0.1:'.$port.':'.$port.'"), or drop the mapping and reach the service over the compose network.');
            }
        }

        foreach ($this->items($file, 'environment') as [$line, $item]) {
            // - KEY=value or KEY: value
            if (! preg_match('/^["\']?([A-Za-z_][\w.\-]*)\s*(?:=|:\s)\s*["\']?([^"\']*)["\']?$/', trim($item), $match)) {
                continue;
            }

            [, $name, $value] = $match;
            $value = trim($value);

            if (preg_match('/ALLOW_EMPTY_PASSWORD$/i', $name) && preg_match('/^(yes|true|1)$/i', $value)) {
                yield $this->report($file, $line, "{$name} lets anyone log in to the database without a password.", $production ? Severity::High : Severity::Low,
                    'Set a password from a secret instead.');
            } elseif (preg_match(self::SECRET_NAME, $name) && ! preg_match('/(_FILE|_PATH|_NAME|_URL|_HOST|_PORT|_USER)$/i', $name)
                && ! str_contains($value, '$') && (Secrets::tokenFormat($value) !== null || Secrets::looksReal($value, $this->allow))) {
                yield $this->report($file, $line, "{$name} is set to a literal secret in the compose file.", Severity::High,
                    'Reference it from the environment (${'.$name.'}) or an env_file that is not committed, or use compose secrets.');
            }
        }
    }

    /**
     * Entries of every "key:" block (list or mapping) and inline [a, b] list.
     *
     * @return list<array{int, string}> line number and raw entry
     */
    private function items(InfrastructureFile $file, string $key): array
    {
        $lines = $file->lines();
        $items = [];

        foreach ($lines as $index => $text) {
            if (! preg_match('/^(\s*)'.preg_quote($key, '/').':\s*(.*)$/', $text, $match)) {
                continue;
            }

            if (preg_match('/^\[(.*)\]\s*$/', trim($match[2]), $inline)) {
                foreach (explode(',', $inline[1]) as $entry) {
                    $items[] = [$index + 1, trim($entry)];
                }

                continue;
            }

            $indent = strlen($match[1]);

            for ($next = $index + 1; $next < count($lines); $next++) {
                if (trim($lines[$next]) === '') {
                    continue;
                }

                if (strlen($lines[$next]) - strlen(ltrim($lines[$next])) <= $indent) {
                    break;
                }

                $items[] = [$next + 1, (string) preg_replace('/^\s*-\s*/', '', $lines[$next])];
            }
        }

        return $items;
    }

    /**
     * The container port of a short-syntax mapping when it is a data service
     * published without a host IP (or on 0.0.0.0).
     */
    private function exposedDataPort(string $mapping): ?string
    {
        // Keep ${VAR:-3306} together while splitting on ":".
        preg_match_all('/\$\{[^}]*\}|[^:]+/', $mapping, $matches);
        $parts = $matches[0];

        if (count($parts) < 2) {
            return null;
        }

        $container = (string) preg_replace('#/(tcp|udp)$#', '', (string) end($parts));
        $hostIp = count($parts) >= 3 ? $parts[0] : null;

        return isset(self::DATA_PORTS[$container]) && ($hostIp === null || in_array($hostIp, ['0.0.0.0', '[::]', '::'], true)) ? $container : null;
    }
}

<?php

namespace Siberfx\RiskAnalyzer\Support;

use Siberfx\RiskAnalyzer\ScanContext;

/**
 * Reads PHP settings from the configuration files instead of ini_get(), which
 * reports the CLI's values (the CLI forces display_errors on, and PHP-FPM
 * often loads another php.ini). On Debian/Ubuntu layouts the FPM php.ini,
 * conf.d and pool overrides next to the CLI ones are used; public/.user.ini
 * and php_flag/php_value lines in public/.htaccess are applied on top.
 */
final class PhpIni
{
    /** Settings that a per-directory file (.user.ini, .htaccess) cannot change. */
    private const array SYSTEM_ONLY = ['expose_php', 'allow_url_include'];

    /**
     * @param  array<string, array{value: string, source: string}>  $settings
     * @param  list<string>  $files  every file that was read, in order
     */
    private function __construct(
        public readonly array $settings,
        public readonly array $files,
        public readonly bool $cliOnly,
    ) {}

    /**
     * @param  list<string>|null  $files  explicit php.ini files (config risk-analyzer.php.ini_files)
     */
    public static function read(ScanContext $context, ?array $files = null): self
    {
        $cliOnly = false;

        if ($files === null) {
            [$files, $cliOnly] = self::discover();
        }

        $settings = [];
        $read = [];

        foreach ($files as $file) {
            if (! is_file($file) || ! is_readable($file)) {
                continue;
            }

            $values = str_ends_with($file, '.conf') ? self::poolValues((string) file_get_contents($file)) : (@parse_ini_file($file, false, INI_SCANNER_RAW) ?: []);
            $read[] = $file;

            foreach ($values as $name => $value) {
                $settings[strtolower((string) $name)] = ['value' => trim((string) $value), 'source' => $file];
            }
        }

        $perDirectory = [
            'public/.user.ini' => @parse_ini_file($context->basePath('public/.user.ini'), false, INI_SCANNER_RAW) ?: [],
            'public/.htaccess' => self::htaccessValues((string) $context->read('public/.htaccess')),
        ];

        foreach ($perDirectory as $source => $values) {
            foreach ($values as $name => $value) {
                $name = strtolower((string) $name);

                if (! in_array($name, self::SYSTEM_ONLY, true)) {
                    $settings[$name] = ['value' => trim((string) $value), 'source' => $source];
                }
            }
        }

        return new self($settings, $read, $cliOnly);
    }

    /**
     * Whether a boolean-ish setting is on, using PHP's built-in default when no file sets it.
     */
    public function enabled(string $name, bool $default): bool
    {
        $value = $this->settings[$name]['value'] ?? null;

        if ($value === null) {
            return $default;
        }

        return in_array(strtolower(trim($value, "\"' ")), ['1', 'on', 'yes', 'true', 'stdout', 'stderr'], true);
    }

    public function value(string $name, string $default): string
    {
        return trim($this->settings[$name]['value'] ?? $default, "\"' ");
    }

    public function source(string $name): string
    {
        return $this->settings[$name]['source'] ?? 'PHP default, no php.ini sets it';
    }

    /**
     * The CLI's php.ini and conf.d files, or the PHP-FPM ones next to them when they exist.
     *
     * @return array{list<string>, bool} files, and whether they are the CLI's own
     */
    private static function discover(): array
    {
        $loaded = php_ini_loaded_file();
        $scanned = array_values(array_filter(array_map('trim', explode(',', (string) php_ini_scanned_files()))));
        $files = array_values(array_filter([is_string($loaded) ? $loaded : null, ...$scanned]));
        $normalized = is_string($loaded) ? str_replace('\\', '/', $loaded) : '';

        if (! str_contains($normalized, '/cli/')) {
            return [$files, false];
        }

        $fpm = str_replace('/cli/', '/fpm/', $normalized);

        if (! is_file($fpm)) {
            return [$files, true];
        }

        $directory = dirname($fpm);

        return [[
            $fpm,
            ...(glob($directory.'/conf.d/*.ini') ?: []),
            ...(glob($directory.'/pool.d/*.conf') ?: []),
        ], false];
    }

    /**
     * php_value[...] / php_admin_flag[...] lines of an FPM pool file.
     *
     * @return array<string, string>
     */
    private static function poolValues(string $contents): array
    {
        preg_match_all('/^\s*php_(?:admin_)?(?:value|flag)\[([^\]]+)\]\s*=\s*(.+?)\s*$/m', $contents, $matches, PREG_SET_ORDER);

        return array_column($matches, 2, 1);
    }

    /**
     * php_value / php_flag directives of an Apache .htaccess file.
     *
     * @return array<string, string>
     */
    private static function htaccessValues(string $contents): array
    {
        preg_match_all('/^\s*php_(?:admin_)?(?:value|flag)\s+(\S+)\s+(.+?)\s*$/mi', $contents, $matches, PREG_SET_ORDER);

        return array_column($matches, 2, 1);
    }
}

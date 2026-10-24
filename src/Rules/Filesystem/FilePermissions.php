<?php

namespace Siberfx\RiskAnalyzer\Rules\Filesystem;

use Closure;
use Siberfx\RiskAnalyzer\Category;
use Siberfx\RiskAnalyzer\Rules\AbstractProjectRule;
use Siberfx\RiskAnalyzer\ScanContext;
use Siberfx\RiskAnalyzer\Severity;

final class FilePermissions extends AbstractProjectRule
{
    /** Files holding secrets: readable by other users of the machine is too much. */
    private const array SECRETS = ['.env', 'auth.json', 'storage/oauth-private.key'];

    /** Directories Laravel writes to: 777 lets any local user plant cached code or views. */
    private const array WRITABLE = ['storage', 'bootstrap/cache'];

    /**
     * @param  (Closure(string): (int|false))|null  $permissions  reads a path's mode; fileperms() by default
     */
    public function __construct(private readonly ?Closure $permissions = null) {}

    public function id(): string
    {
        return 'file-permissions';
    }

    public function title(): string
    {
        return 'Loose file permissions';
    }

    public function description(): string
    {
        return '.env, auth.json and the Passport private key readable or writable by every user on the machine, and storage/ or bootstrap/cache writable by everyone (777). Skipped on Windows, which has no Unix modes.';
    }

    public function category(): Category
    {
        return Category::Filesystem;
    }

    public function severity(): Severity
    {
        return Severity::Medium;
    }

    public function run(ScanContext $context): iterable
    {
        if ($this->permissions === null && PHP_OS_FAMILY === 'Windows') {
            return;
        }

        foreach (self::SECRETS as $path) {
            $mode = $this->mode($context, $path);

            if ($mode === null) {
                continue;
            }

            if ($mode & 0o002) {
                yield $this->finding("{$path} is writable by every user on the machine (mode {$this->octal($mode)}).", Severity::High,
                    "chmod 640 {$path} (owner read/write, web server group read).", $path, anchor: 'perms.'.$path.'.world-writable');
            } elseif ($mode & 0o004) {
                yield $this->finding("{$path} is readable by every user on the machine (mode {$this->octal($mode)}).", null,
                    "chmod 640 {$path} (owner read/write, web server group read).", $path, anchor: 'perms.'.$path.'.world-readable');
            }
        }

        foreach (self::WRITABLE as $path) {
            $mode = $this->mode($context, $path);

            if ($mode !== null && ($mode & 0o002)) {
                yield $this->finding("{$path} is writable by every user on the machine (mode {$this->octal($mode)}).", Severity::Low,
                    "Make the web server user the owner or group and use 775 (chmod -R o-w {$path}).", $path, anchor: 'perms.'.$path.'.world-writable');
            }
        }
    }

    private function mode(ScanContext $context, string $path): ?int
    {
        $absolute = $context->basePath($path);

        if (! file_exists($absolute)) {
            return null;
        }

        $mode = $this->permissions !== null ? ($this->permissions)($absolute) : @fileperms($absolute);

        return $mode === false ? null : $mode & 0o777;
    }

    private function octal(int $mode): string
    {
        return sprintf('%03o', $mode);
    }
}

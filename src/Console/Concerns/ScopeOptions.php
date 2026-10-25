<?php

namespace Siberfx\RiskAnalyzer\Console\Concerns;

/**
 * --frontend and --infrastructure: given at all, they limit the scan to those
 * checks; given folders (repeatable or comma-separated), they also replace the
 * configured paths.
 */
trait ScopeOptions
{
    /**
     * @return list<string>|null null when the option is absent, [] when it has no folders
     */
    private function scopeOption(string $name): ?array
    {
        $values = (array) $this->option($name);

        if ($values === []) {
            return null;
        }

        $folders = [];

        foreach ($values as $value) {
            foreach (is_string($value) ? explode(',', $value) : [] as $item) {
                if (trim($item) !== '') {
                    $folders[] = trim($item);
                }
            }
        }

        return $folders;
    }
}

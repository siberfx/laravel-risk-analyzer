<?php

namespace Siberfx\RiskAnalyzer\Rules\Frontend;

use Siberfx\RiskAnalyzer\Frontend\FrontendSource;
use Siberfx\RiskAnalyzer\Severity;

final class FrontendPostMessage extends AbstractFrontendRule
{
    /** Lines after a message listener in which an origin check is looked for. */
    private const int HANDLER_LINES = 25;

    public function id(): string
    {
        return 'frontend-postmessage';
    }

    public function title(): string
    {
        return 'Unchecked cross-window messages';
    }

    public function description(): string
    {
        return 'postMessage() to the "*" origin, which hands the data to whatever page is loaded in the target window, and window "message" listeners that never look at event.origin, which accept messages from any site.';
    }

    public function severity(): Severity
    {
        return Severity::Medium;
    }

    protected function inspect(FrontendSource $file): iterable
    {
        foreach ($file->matches('/\.\s*postMessage\s*\([^\n]*,\s*([\'"`])\*\1/') as $match) {
            yield $this->report($file, $match['line'], 'postMessage() sends to any origin ("*").', null,
                'Pass the exact origin of the receiving window, e.g. postMessage(data, "https://app.example.com").');
        }

        // Web workers receive messages from their own page only.
        if (preg_match('/worker/i', basename($file->path))) {
            return;
        }

        $lines = preg_split('/\R/', $file->code) ?: [];

        // worker.onmessage and self.addEventListener('message') are not window listeners.
        $listeners = iterator_to_array($file->matches('/(?<![\w$.])(?:window\s*\.\s*)?(?:addEventListener\s*\(\s*([\'"`])message\1|onmessage\s*=)/'), false);

        foreach ($listeners as $index => $match) {
            // The handler ends at the next listener at the latest.
            $next = $listeners[$index + 1]['line'] ?? PHP_INT_MAX;
            $handler = implode("\n", array_slice($lines, $match['line'] - 1, max(1, min(self::HANDLER_LINES, $next - $match['line']))));

            if (! preg_match('/\.\s*origin\b|\borigin\s*[!=]==?/', $handler)) {
                yield $this->report($file, $match['line'], 'A window "message" listener does not check event.origin.', null,
                    'Return early unless event.origin is one you expect: if (event.origin !== "https://trusted.example.com") return;');
            }
        }
    }
}

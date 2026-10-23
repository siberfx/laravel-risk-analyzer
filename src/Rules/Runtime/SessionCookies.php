<?php

namespace Siberfx\RiskAnalyzer\Rules\Runtime;

use Siberfx\RiskAnalyzer\Category;
use Siberfx\RiskAnalyzer\Rules\AbstractProjectRule;
use Siberfx\RiskAnalyzer\ScanContext;
use Siberfx\RiskAnalyzer\Severity;

final class SessionCookies extends AbstractProjectRule
{
    public function id(): string
    {
        return 'session-cookies';
    }

    public function title(): string
    {
        return 'Session cookie flags';
    }

    public function description(): string
    {
        return 'Session cookies readable by JavaScript (http_only off), sent over plain HTTP in production (secure off), SameSite=None without Secure, and very long session lifetimes.';
    }

    public function category(): Category
    {
        return Category::Runtime;
    }

    public function severity(): Severity
    {
        return Severity::High;
    }

    public function run(ScanContext $context): iterable
    {
        $session = (array) $context->settings()->get('session', []);
        $sameSite = isset($session['same_site']) ? strtolower((string) $session['same_site']) : null;
        $secure = (bool) ($session['secure'] ?? false);

        if (($session['http_only'] ?? true) === false) {
            yield $this->finding('session.http_only is false, so scripts (and XSS payloads) can read the session cookie.', null,
                'Set session.http_only to true.', anchor: 'session.http_only');
        }

        if ($sameSite === 'none' && ! $secure) {
            yield $this->finding('SameSite=None is used without the Secure flag; browsers reject or downgrade such cookies.', null,
                'Enable SESSION_SECURE_COOKIE when using SameSite=None.', anchor: 'session.same_site');
        }

        if (! $context->production) {
            return;
        }

        if (! $secure) {
            yield $this->finding('session.secure is off, so the session cookie is also sent over plain HTTP.', Severity::Medium,
                'Set SESSION_SECURE_COOKIE=true in production (the site should be HTTPS-only anyway).', anchor: 'session.secure');
        }

        if ($sameSite === null || $sameSite === '') {
            yield $this->finding('session.same_site is not set.', Severity::Low,
                'Use "lax" (the default) or "strict".', anchor: 'session.same_site-null');
        }

        $lifetime = (int) ($session['lifetime'] ?? 120);

        if ($lifetime > 60 * 24 * 7) {
            yield $this->finding("Sessions stay valid for {$lifetime} minutes of inactivity.", Severity::Low,
                'Keep SESSION_LIFETIME short and use "remember me" for long-lived logins.', anchor: 'session.lifetime');
        }
    }
}

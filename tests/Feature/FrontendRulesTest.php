<?php

use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Http;
use Siberfx\RiskAnalyzer\Finding;
use Siberfx\RiskAnalyzer\Report;
use Siberfx\RiskAnalyzer\RiskAnalyzer;

function reactComponent(): string
{
    return <<<'JSX'
        import DOMPurify from 'dompurify';
        export function Comment({ body }) {
          const params = new URLSearchParams(window.location.search);
          return (
            <div>
              <div dangerouslySetInnerHTML={{ __html: params.get('msg') }} />
              <div dangerouslySetInnerHTML={{ __html: body }} />
              <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(body) }} />
              <div dangerouslySetInnerHTML={{ __html: '<b>static</b>' }} />
              {/* <div dangerouslySetInnerHTML={{ __html: commented }} /> */}
              <a href={params.get('next')}>next</a>
              {/* risk-analyzer-ignore xss-frontend -- rendered by our CMS */}
              <div dangerouslySetInnerHTML={{ __html: body }} />
            </div>
          );
        }
        JSX;
}

function vueComponent(): string
{
    return <<<'VUE'
        <template>
          <div v-html="$route.query.preview"></div>
          <div v-html="post.body"></div>
          <a href="javascript:void(0)" @click="go">x</a>
          <!-- <div v-html="old"></div> -->
          <a :href="'javascript:' + action">run</a>
        </template>
        <script setup>
        localStorage.setItem('auth_token', response.data.token)
        console.log(post)
        debugger;
        console.log(user) // risk-analyzer-ignore frontend-debug
        sessionStorage.password = form.password
        </script>
        VUE;
}

function angularComponent(): string
{
    return <<<'TS'
        import { Component } from '@angular/core';
        @Component({ selector: 'app-profile', templateUrl: './profile.component.html' })
        export class ProfileComponent {
          constructor(private sanitizer: DomSanitizer, private route: ActivatedRoute) {}
          ngOnInit() {
            this.trusted = this.sanitizer.bypassSecurityTrustHtml(this.route.snapshot.queryParamMap.get('html'));
            eval(this.route.snapshot.fragment);
            setTimeout("refresh()", 100);
            setTimeout(() => this.refresh(), 100);
            window.location.href = this.route.snapshot.queryParamMap.get('returnUrl');
            window.parent.postMessage(this.data, '*');
            window.addEventListener('message', (event) => { this.handle(event.data); });
            window.addEventListener('message', (event) => {
              if (event.origin !== 'https://app.example.com') return;
              this.handle(event.data);
            });
            worker.onmessage = (event) => this.handle(event.data);
          }
        }
        TS;
}

function frontendProject(array $extra = []): array
{
    return [
        'resources/js/components/Comment.jsx' => reactComponent(),
        'resources/js/Pages/Post.vue' => vueComponent(),
        'resources/js/node_modules/lib/index.js' => "eval(location.hash);\n",
        'resources/js/dist/app.js' => "eval(location.hash);\n",
        'resources/js/vendor.min.js' => "eval(location.hash);\n",
        'resources/js/Comment.spec.ts' => "eval(location.hash);\n",
        'client/src/app/profile.component.ts' => angularComponent(),
        'client/src/app/profile.component.html' => "<h1>{{ name }}</h1>\n<div [innerHTML]=\"bio\"></div>\n",
        ...$extra,
    ];
}

function scanFrontend(string $root, array $options = []): Report
{
    return app(RiskAnalyzer::class)->scan(...['only' => ['frontend'], 'baseline' => false, 'offline' => true, 'basePath' => $root, ...$options]);
}

/**
 * @return array<string, string> "rule@file:line" => severity
 */
function frontendFindings(Report $report): array
{
    return collect($report->findings)
        ->mapWithKeys(fn (Finding $f) => [$f->rule.'@'.$f->file.':'.$f->line => $f->severity->value])
        ->all();
}

it('finds HTML injection in React and Vue components', function () {
    $findings = frontendFindings(scanFrontend($this->project(frontendProject())));

    expect($findings)->toMatchArray([
        'xss-frontend@resources/js/components/Comment.jsx:6' => 'high',
        'xss-frontend@resources/js/components/Comment.jsx:7' => 'medium',
        'xss-frontend@resources/js/components/Comment.jsx:8' => 'low',
        'xss-frontend@resources/js/Pages/Post.vue:2' => 'high',
        'xss-frontend@resources/js/Pages/Post.vue:3' => 'medium',
    ])->not->toHaveKeys([
        // literal, comment, inline ignore
        'xss-frontend@resources/js/components/Comment.jsx:9',
        'xss-frontend@resources/js/components/Comment.jsx:10',
        'xss-frontend@resources/js/components/Comment.jsx:13',
        'xss-frontend@resources/js/Pages/Post.vue:5',
    ]);
});

it('only scans frontend.paths and skips dependencies, builds, minified files and tests', function () {
    $files = collect(scanFrontend($this->project(frontendProject()))->findings)->pluck('file')->unique()->sort()->values()->all();

    expect($files)->toBe(['resources/js/Pages/Post.vue', 'resources/js/components/Comment.jsx']);
});

it('reports redirects, javascript: URLs, storage and debug code', function () {
    $findings = frontendFindings(scanFrontend($this->project(frontendProject())));

    expect($findings)->toMatchArray([
        'frontend-open-redirect@resources/js/components/Comment.jsx:11' => 'medium',
        'frontend-open-redirect@resources/js/Pages/Post.vue:4' => 'low',
        'frontend-open-redirect@resources/js/Pages/Post.vue:6' => 'medium',
        'frontend-token-storage@resources/js/Pages/Post.vue:9' => 'low',
        'frontend-token-storage@resources/js/Pages/Post.vue:13' => 'medium',
        'frontend-debug@resources/js/Pages/Post.vue:10' => 'low',
        'frontend-debug@resources/js/Pages/Post.vue:11' => 'medium',
    ]);

    $console = collect(scanFrontend($this->project(frontendProject()))->findings)
        ->first(fn (Finding $f) => $f->rule === 'frontend-debug' && $f->severity->value === 'low');

    expect($console->message)->toBe('console call left in on line 10.');
});

it('scans the --frontend folders instead of frontend.paths', function () {
    $report = scanFrontend($this->project(frontendProject()), ['frontend' => ['client']]);
    $findings = frontendFindings($report);

    expect($report->frontend)->toBe(['client'])
        ->and(collect($report->findings)->pluck('file')->unique()->sort()->values()->all())
        ->toBe(['client/src/app/profile.component.html', 'client/src/app/profile.component.ts'])
        ->and($findings)->toMatchArray([
            'xss-frontend@client/src/app/profile.component.ts:6' => 'high',
            'xss-frontend@client/src/app/profile.component.html:2' => 'medium',
            'frontend-code-execution@client/src/app/profile.component.ts:7' => 'high',
            'frontend-code-execution@client/src/app/profile.component.ts:8' => 'medium',
            'frontend-open-redirect@client/src/app/profile.component.ts:10' => 'medium',
            'frontend-postmessage@client/src/app/profile.component.ts:11' => 'medium',
            'frontend-postmessage@client/src/app/profile.component.ts:12' => 'medium',
        ])
        ->not->toHaveKeys([
            'frontend-code-execution@client/src/app/profile.component.ts:9',
            'frontend-postmessage@client/src/app/profile.component.ts:13',
            'frontend-postmessage@client/src/app/profile.component.ts:17',
        ]);
});

it('accepts absolute and ./ frontend folders, and rejects missing ones', function () {
    $root = $this->project(frontendProject());
    $outside = $this->project(['src/app.ts' => "eval(location.hash);\n"]);

    expect(collect(scanFrontend($root, ['frontend' => ['./client']])->findings)->pluck('file')->unique()->count())->toBe(2)
        ->and(collect(scanFrontend($root, ['frontend' => [$outside]])->findings)->pluck('file')->all())->toBe([$outside.'/src/app.ts'])
        ->and(fn () => scanFrontend($root, ['frontend' => ['missing']]))->toThrow(InvalidArgumentException::class, 'Frontend folder [missing] does not exist.');
});

it('limits frontend rules to changed files', function () {
    $report = scanFrontend($this->project(frontendProject()), ['files' => ['resources/js/Pages/Post.vue']]);

    expect(collect($report->findings)->pluck('file')->unique()->values()->all())->toBe(['resources/js/Pages/Post.vue']);
});

it('finds secrets in frontend code and in public env variables', function () {
    $stripe = 'sk_'.'live_51HxQbXJk2cV9aBcDeFgHiJkLmNoP';
    $google = 'AIza'.'SyD3x4mpl3K3yF0rT3st1ngPurp0s3s0nly';

    $findings = frontendFindings(scanFrontend($this->project([
        'resources/js/config.js' => implode("\n", [
            "export const stripe = '{$stripe}';",
            "export const maps = '{$google}';",
            "const apiSecret = 'f9Kx2LmQ8vRt3ZpW7nYb';",
            "const passwordField = 'password_input_12';",
            'const key = import.meta.env.VITE_STRIPE_SECRET;',
            'const pusher = import.meta.env.VITE_PUSHER_APP_KEY;',
            '',
        ]),
        '.env' => "APP_KEY=\nVITE_PUSHER_APP_KEY=abc\nVITE_STRIPE_SECRET=sk_test_123456\nVITE_STRIPE_PUBLISHABLE_KEY=pk_test_1\nSTRIPE_SECRET=fine-on-the-server\n",
        '.env.example' => "VITE_API_SECRET=\n",
    ])));

    expect($findings)->toBe([
        'frontend-secret@resources/js/config.js:1' => 'critical',
        'frontend-secret@.env:3' => 'high',
        'frontend-secret@resources/js/config.js:3' => 'high',
        'frontend-secret@.env.example:1' => 'medium',
        'frontend-secret@resources/js/config.js:5' => 'medium',
        'frontend-secret@resources/js/config.js:2' => 'low',
    ]);
});

it('reports source maps in public/ once per folder', function () {
    $findings = app(RiskAnalyzer::class)->scan(only: ['public-exposure'], baseline: false, basePath: $this->project([
        'public/index.php' => '<?php',
        'public/build/assets/app-4f1c2a.js' => '',
        'public/build/assets/app-4f1c2a.js.map' => '{}',
        'public/build/assets/app-9e8d7c.css.map' => '{}',
        'public/js/admin.js.map' => '{}',
    ]))->findings;

    expect(collect($findings)->map(fn (Finding $f) => [$f->file, $f->severity->value, $f->message])->all())->toBe([
        ['public/build/assets/app-4f1c2a.js.map', 'low', 'public/build/assets holds 2 source maps (e.g. app-4f1c2a.js.map): they publish the original frontend source.'],
        ['public/js/admin.js.map', 'low', 'public/js/admin.js.map is a source map: it publishes the original frontend source.'],
    ]);
});

it('checks a lockfile inside a frontend folder for advisories', function () {
    Http::fake([
        'api.osv.dev/v1/querybatch' => Http::response(['results' => [['vulns' => [['id' => 'GHSA-8hc4-vh64-cxmj']]]]]),
        'api.osv.dev/v1/vulns/GHSA-8hc4-vh64-cxmj' => Http::response([
            'id' => 'GHSA-8hc4-vh64-cxmj',
            'summary' => 'Server-Side Request Forgery in axios',
            'database_specific' => ['severity' => 'HIGH'],
            'affected' => [['package' => ['ecosystem' => 'npm', 'name' => 'axios'], 'ranges' => [['events' => [['introduced' => '1.3.2'], ['fixed' => '1.7.4']]]]]],
        ]),
    ]);

    $root = $this->project([
        'client/package-lock.json' => json_encode(['lockfileVersion' => 3, 'packages' => ['' => ['name' => 'client'], 'node_modules/axios' => ['version' => '1.6.0']]]),
    ]);

    $findings = app(RiskAnalyzer::class)->scan(only: ['vulnerable-dependency'], baseline: false, basePath: $root, frontend: ['client'])->findings;

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->file)->toBe('client/package-lock.json')
        ->and($findings[0]->remediation)->toContain('(cd client && npm install axios@^1.7.4)');

    // Without the folder in frontend.paths or --frontend, its lockfile is not read.
    expect(app(RiskAnalyzer::class)->scan(only: ['vulnerable-dependency'], baseline: false, basePath: $root)->findings)->toBe([]);
});

it('takes --frontend on the scan command and names the folders', function () {
    $this->app->setBasePath($this->project(frontendProject()));

    $exitCode = Artisan::call('risk-analyzer:scan', ['--only' => ['frontend'], '--frontend' => ['client'], '--offline' => true, '--no-baseline' => true]);

    expect($exitCode)->toBe(1)
        ->and(Artisan::output())->toContain('frontend: client')
        ->toContain('HIGH     xss-frontend  client/src/app/profile.component.ts:6');

    $this->artisan('risk-analyzer:scan', ['--only' => ['frontend'], '--frontend' => ['nope']])
        ->expectsOutputToContain('Frontend folder [nope] does not exist.')
        ->assertExitCode(2);

    $this->artisan('risk-analyzer:baseline', ['--frontend' => ['nope'], '--offline' => true])->assertExitCode(2);
});

it('skips vendored libraries and build output', function () {
    $findings = scanFrontend($this->project([
        'resources/js/lib/jquery.mobile.js' => "/*! jQuery Mobile v1.4.5 | jquery.org/license */\neval(location.hash);\n",
        'resources/js/vendor-licensed.js' => "/**\n * @license MIT\n */\neval(location.hash);\n",
        'resources/js/app.bundle.js' => "eval(location.hash);\n",
        'resources/js/minified.js' => str_repeat('var a=1;', 400)."\neval(location.hash);\n",
        'resources/js/app.js' => "eval(location.hash);\n",
    ]))->findings;

    expect(collect($findings)->pluck('file')->unique()->values()->all())->toBe(['resources/js/app.js']);
});

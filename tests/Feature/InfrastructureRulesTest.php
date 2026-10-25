<?php

use Siberfx\RiskAnalyzer\Finding;
use Siberfx\RiskAnalyzer\Report;
use Siberfx\RiskAnalyzer\RiskAnalyzer;

function infrastructureProject(array $extra = []): array
{
    return [
        'docker/php/Dockerfile' => <<<'DOCKER'
            FROM node:20 AS assets
            RUN npm ci && npm run build
            FROM php:8.1-fpm
            ARG GITHUB_TOKEN
            ENV APP_ENV=production \
                DB_PASSWORD=Xk9vQ2mLp7Rt4Wz8
            ENV APP_KEY=$APP_KEY
            ADD https://example.com/tool.tar.gz /tmp/
            RUN curl -fsSL https://get.example.sh | bash \
             && chmod -R 777 /var/www
            COPY . /var/www
            # risk-analyzer-ignore dockerfile-hardening -- internal mirror with a private CA
            RUN curl -k https://mirror.internal/x
            DOCKER,
        'docker/redis/Dockerfile' => "FROM redis\nUSER redis\n",
        'docker-compose.yml' => <<<'YAML'
            services:
              app:
                build: .
                privileged: true
                volumes:
                  - /var/run/docker.sock:/var/run/docker.sock
                environment:
                  DB_PASSWORD: Xk9vQ2mLp7Rt4Wz8
                  APP_KEY: ${APP_KEY}
                  MYSQL_PASSWORD: secret
              mysql:
                image: mysql:8.0
                ports:
                  - "${FORWARD_DB_PORT:-3306}:3306"
                  - "127.0.0.1:6379:6379"
                environment:
                  - MYSQL_ALLOW_EMPTY_PASSWORD=yes
                cap_add: [SYS_ADMIN]
                security_opt:
                  - seccomp:unconfined
              web:
                network_mode: host
            YAML,
        'docker-compose.prod.yml' => "services:\n  db:\n    ports:\n      - \"5432:5432\"\n",
        'deploy.sh' => <<<'SH'
            #!/bin/bash
            set -e
            mysqldump -u root -pXk9vQ2mLp7Rt db > backup.sql
            export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMIK7MDENGbPxRfiCYzz12KEY
            git clone https://deploy:hunter2pass@github.com/acme/app.git
            curl -sSL https://install.example.com | sudo bash
            rm -rf "$RELEASE_DIR/"*
            rm -rf "${RELEASE_DIR:?}/"*
            eval "$CMD"
            wget --no-check-certificate https://example.com/x
            # curl https://example.com/x | sh
            echo "token=${TOKEN}"
            SH,
        'Makefile' => "deploy:\n\tchmod 777 storage\n\trm -rf $(BUILD_DIR)/\n\trm -rf $(CURDIR)/tmp\n",
        'vendor/acme/pkg/Dockerfile' => "FROM php\nENV DB_PASSWORD=Xk9vQ2mLp7Rt4Wz8\n",
        'node_modules/pkg/install.sh' => "curl https://x.example | sh\n",
        ...$extra,
    ];
}

function workflow(): string
{
    return <<<'YAML'
        on:
          pull_request_target:
            types: [opened]
        permissions: write-all
        jobs:
          test:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v4
                with:
                  ref: ${{ github.event.pull_request.head.sha }}
              - uses: shivammathur/setup-php@v2
              - uses: shivammathur/setup-php@0f7f1d08e3e32076e51cae65eb0b0c871405b16e
              - run: echo "${{ github.event.pull_request.title }}"
              - name: Greet
                run: |
                  echo "Branch ${{ github.head_ref }}"
                  echo "${{ github.event.pull_request.number }}"
              - uses: actions/github-script@v7
                with:
                  script: |
                    console.log("${{ github.event.issue.body }}")
              - name: Safe
                env:
                  TITLE: ${{ github.event.pull_request.title }}
                run: echo "$TITLE"
        YAML;
}

function scanInfrastructure(string $root, array $options = []): Report
{
    return app(RiskAnalyzer::class)->scan(...['only' => ['infrastructure'], 'baseline' => false, 'offline' => true, 'basePath' => $root, ...$options]);
}

/**
 * @return array<string, string> "rule@file:line" => severity
 */
function infrastructureFindings(Report $report): array
{
    return collect($report->findings)
        ->mapWithKeys(fn (Finding $f) => [$f->rule.'@'.$f->file.':'.$f->line => $f->severity->value])
        ->all();
}

it('finds secrets, remote downloads, root users and unpinned images in Dockerfiles', function () {
    $findings = infrastructureFindings(scanInfrastructure($this->project(infrastructureProject())));
    $docker = array_filter($findings, fn ($key) => str_starts_with($key, 'dockerfile-hardening@'), ARRAY_FILTER_USE_KEY);

    expect($docker)->toBe([
        'dockerfile-hardening@docker/php/Dockerfile:5' => 'high',
        'dockerfile-hardening@docker/php/Dockerfile:4' => 'medium',
        'dockerfile-hardening@docker/php/Dockerfile:7' => 'medium',
        'dockerfile-hardening@docker/php/Dockerfile:8' => 'medium',
        'dockerfile-hardening@docker/php/Dockerfile:9' => 'medium',
        'dockerfile-hardening@docker/php/Dockerfile:10' => 'medium',
        'dockerfile-hardening@docker/php/Dockerfile:11' => 'medium',
        'dockerfile-hardening@docker/php/Dockerfile:3' => 'low',
        'dockerfile-hardening@docker/redis/Dockerfile:1' => 'low',
    ]);
});

it('judges COPY . by the .dockerignore', function () {
    $dockerfile = ['Dockerfile' => "FROM php:8.4-fpm\nCOPY . /var/www\nUSER www-data\n", '.env' => 'APP_KEY=x'];
    $copy = fn (array $files) => collect(scanInfrastructure($this->project($files))->findings)
        ->map(fn (Finding $f) => $f->severity->value.' '.$f->message)->all();

    expect($copy($dockerfile))->toBe(['medium COPY . copies the whole build context and there is no .dockerignore, so .env, .git and logs can end up in the image.'])
        ->and($copy([...$dockerfile, '.dockerignore' => "vendor\nnode_modules\n"]))->toBe(['high COPY . copies .env into the image: .dockerignore does not exclude it.'])
        ->and($copy([...$dockerfile, '.dockerignore' => "vendor\n.env\n"]))->toBe([]);
});

it('finds privileged containers, socket mounts, open ports and secrets in compose files', function () {
    $findings = infrastructureFindings(scanInfrastructure($this->project(infrastructureProject())));
    $compose = array_filter($findings, fn ($key) => str_starts_with($key, 'compose-hardening@'), ARRAY_FILTER_USE_KEY);

    expect($compose)->toBe([
        'compose-hardening@docker-compose.yml:4' => 'high',
        'compose-hardening@docker-compose.yml:6' => 'high',
        'compose-hardening@docker-compose.yml:8' => 'high',
        'compose-hardening@docker-compose.prod.yml:4' => 'medium',
        'compose-hardening@docker-compose.yml:18' => 'medium',
        'compose-hardening@docker-compose.yml:20' => 'medium',
        'compose-hardening@docker-compose.yml:22' => 'medium',
        'compose-hardening@docker-compose.yml:14' => 'low',
        'compose-hardening@docker-compose.yml:17' => 'low',
    ]);
});

it('finds risky commands in shell scripts and Makefiles', function () {
    $token = 'ghp_'.str_repeat('a1B2c3D4e5', 4);
    $findings = infrastructureFindings(scanInfrastructure($this->project(infrastructureProject([
        'scripts/release.sh' => "#!/bin/sh\ngh release create --token \"{$token}\"\n",
    ]))));
    $shell = array_filter($findings, fn ($key) => str_starts_with($key, 'shell-script-risks@'), ARRAY_FILTER_USE_KEY);

    expect($shell)->toBe([
        'shell-script-risks@scripts/release.sh:2' => 'critical',
        'shell-script-risks@deploy.sh:3' => 'high',
        'shell-script-risks@deploy.sh:4' => 'high',
        'shell-script-risks@deploy.sh:5' => 'high',
        'shell-script-risks@Makefile:2' => 'medium',
        'shell-script-risks@deploy.sh:6' => 'medium',
        'shell-script-risks@deploy.sh:9' => 'medium',
        'shell-script-risks@deploy.sh:10' => 'medium',
        'shell-script-risks@Makefile:3' => 'low',
        'shell-script-risks@deploy.sh:7' => 'low',
    ]);
});

it('finds script injection, pull_request_target checkouts and unpinned actions in workflows', function () {
    $findings = infrastructureFindings(scanInfrastructure($this->project(['.github/workflows/ci.yml' => workflow()])));

    expect($findings)->toBe([
        'ci-workflow-risks@.github/workflows/ci.yml:11' => 'high',
        'ci-workflow-risks@.github/workflows/ci.yml:14' => 'high',
        'ci-workflow-risks@.github/workflows/ci.yml:17' => 'high',
        'ci-workflow-risks@.github/workflows/ci.yml:22' => 'high',
        'ci-workflow-risks@.github/workflows/ci.yml:4' => 'medium',
        'ci-workflow-risks@.github/workflows/ci.yml:12' => 'low',
    ]);
});

it('skips vendor and node_modules, and follows --changed', function () {
    $root = $this->project(infrastructureProject());
    $files = collect(scanInfrastructure($root)->findings)->pluck('file')->unique();

    expect($files->filter(fn ($file) => str_starts_with($file, 'vendor/') || str_starts_with($file, 'node_modules/'))->all())->toBe([])
        ->and(collect(scanInfrastructure($root, ['files' => ['Makefile']])->findings)->pluck('file')->unique()->values()->all())->toBe(['Makefile']);
});

it('reads extra infrastructure folders from config', function () {
    $outside = $this->project(['deploy/release.sh' => "chmod 777 /srv/app\n"]);
    config()->set('risk-analyzer.infrastructure.paths', ['.', $outside]);
    app()->forgetInstance(RiskAnalyzer::class);

    expect(collect(scanInfrastructure($this->project([]))->findings)->pluck('file')->all())->toBe([$outside.'/deploy/release.sh']);
});

it('flags unsupported PHP base images', function () {
    $findings = app(RiskAnalyzer::class)->scan(only: ['unsupported-runtime'], baseline: false, offline: true, basePath: $this->project(infrastructureProject()))->findings;
    $images = collect($findings)->filter(fn (Finding $f) => str_contains($f->message, 'base image'))->values();

    expect($images)->toHaveCount(1)
        ->and($images[0]->file)->toBe('docker/php/Dockerfile')
        ->and($images[0]->line)->toBe(3)
        ->and($images[0]->message)->toStartWith('PHP 8.1 (base image) stopped receiving security fixes');
});

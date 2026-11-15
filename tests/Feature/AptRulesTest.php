<?php

use Siberfx\RiskAnalyzer\Finding;
use Siberfx\RiskAnalyzer\RiskAnalyzer;
use Siberfx\RiskAnalyzer\Severity;
use Siberfx\RiskAnalyzer\Support\AptSettings;

const UBUNTU_2204 = ['ID' => 'ubuntu', 'VERSION_ID' => '22.04', 'PRETTY_NAME' => 'Ubuntu 22.04 LTS'];
const DEBIAN_11 = ['ID' => 'debian', 'VERSION_ID' => '11', 'PRETTY_NAME' => 'Debian GNU/Linux 11'];

/**
 * @return list<string> "rule@file:line" => severity, for the apt-hardening rule
 */
function aptFindings(array $project): array
{
    $root = test()->project($project);
    app()->forgetInstance(RiskAnalyzer::class);

    return collect(app(RiskAnalyzer::class)->scan(only: ['infrastructure'], baseline: false, offline: true, basePath: $root)->findings)
        ->filter(fn (Finding $f) => $f->rule === 'apt-hardening')
        ->mapWithKeys(fn (Finding $f) => [$f->file.':'.$f->line => $f->severity->value])
        ->all();
}

it('flags trusted, insecure and plain-HTTP APT sources in Dockerfiles and scripts', function () {
    expect(aptFindings([
        'docker/Dockerfile' => <<<'DOCKER'
            FROM debian:12
            RUN echo "deb [trusted=yes] http://packages.example.com stable main" >> /etc/apt/sources.list
            RUN apt-get -o Acquire::AllowInsecureRepositories=true update
            RUN echo "deb https://deb.debian.org/debian bookworm main" > /etc/apt/sources.list
            # RUN echo "deb http://old.example.com stable main"
            DOCKER,
        'scripts/provision.sh' => "#!/bin/sh\napt-get -o Acquire::https::Verify-Peer=false update\ndeb http://archive.ubuntu.com/ubuntu jammy main\n",
    ]))->toBe([
        'docker/Dockerfile:2' => 'high',
        'docker/Dockerfile:3' => 'high',
        'scripts/provision.sh:2' => 'high',
        'scripts/provision.sh:3' => 'medium',
    ]);
});

it('leaves https sources and enabled checks alone', function () {
    expect(aptFindings([
        'docker/Dockerfile' => "FROM ubuntu:24.04\nRUN apt-get -o Acquire::AllowInsecureRepositories=false update\nRUN apt-get install -y ca-certificates\n",
    ]))->toBe([]);
});

it('judges the retry condition from the host files', function () {
    $http = "Types: deb\nURIs: http://archive.ubuntu.com/ubuntu/\nSuites: jammy\nComponents: main\n";

    expect(AptSettings::assess(['sources.list.d/ubuntu.sources' => $http], UBUNTU_2204))
        ->toHaveCount(1)
        ->and(AptSettings::assess(['sources.list.d/ubuntu.sources' => $http], UBUNTU_2204)[0]['severity'])->toBe(Severity::Medium)
        ->and(AptSettings::assess(['sources.list.d/ubuntu.sources' => $http], UBUNTU_2204)[0]['message'])->toContain('Acquire::Retries 3, the default for Ubuntu 22.04 LTS')
        // Older releases do not retry by default, so the same source is not the advisory's setup.
        ->and(AptSettings::assess(['sources.list' => 'deb http://deb.debian.org/debian buster main'], DEBIAN_11))->toBe([])
        // An explicit zero turns retries off.
        ->and(AptSettings::assess(['apt.conf.d/80retries' => 'Acquire::Retries "0";', 'sources.list' => 'deb http://deb.debian.org/debian bookworm main'], ['ID' => 'debian', 'VERSION_ID' => '12']))->toBe([])
        // A config file can turn retries on for an older release.
        ->and(AptSettings::assess(['apt.conf.d/80retries' => 'Acquire::Retries "2";', 'sources.list' => 'deb http://deb.debian.org/debian buster main'], DEBIAN_11))
        ->toHaveCount(1);
});

it('ignores HTTPS sources, disabled stanzas and comments on the host', function () {
    $files = [
        'sources.list' => "# deb http://commented.example.com stable main\ndeb https://deb.debian.org/debian bookworm main\n",
        'sources.list.d/extra.sources' => "Types: deb\nURIs: http://disabled.example.com\nSuites: stable\nEnabled: no\n",
    ];

    expect(AptSettings::assess($files, ['ID' => 'debian', 'VERSION_ID' => '12']))->toBe([]);
});

it('flags trusted and insecure settings on the host', function () {
    $issues = AptSettings::assess([
        'apt.conf.d/99unsafe' => "Acquire::AllowInsecureRepositories \"true\";\nAcquire::https::Verify-Peer \"false\";\n",
        'sources.list.d/vendor.list' => "deb [trusted=yes] https://repo.example.com/ubuntu jammy main\n",
    ], UBUNTU_2204);

    expect(array_map(fn ($issue) => $issue['severity']->value, $issues))->toBe(['high', 'high'])
        ->and(array_column($issues, 'anchor'))->toBe(['apt.insecure.apt.conf.d/99unsafe', 'apt.trusted.sources.list.d/vendor.list']);
});

<?php

namespace Siberfx\RiskAnalyzer\Tests;

use Illuminate\Filesystem\Filesystem;
use Illuminate\Support\Facades\Http;
use Orchestra\Testbench\TestCase as Orchestra;
use Siberfx\RiskAnalyzer\RiskAnalyzerServiceProvider;

abstract class TestCase extends Orchestra
{
    /** @var list<string> */
    private array $projects = [];

    protected function getPackageProviders($app): array
    {
        return [RiskAnalyzerServiceProvider::class];
    }

    protected function setUp(): void
    {
        parent::setUp();

        // No test talks to OSV, endoflife.date or php.net unless it fakes them.
        Http::preventStrayRequests();
    }

    protected function defineEnvironment($app): void
    {
        $app['config']->set('app.key', 'base64:'.base64_encode(str_repeat('k', 32)));
        $app['config']->set('cache.default', 'array');
        // Keep scans independent of the Node installed on the machine running the tests.
        $app['config']->set('risk-analyzer.runtime.node_binary', false);
    }

    /**
     * Writes a throwaway project to disk and returns its root.
     *
     * @param  array<string, string>  $files  relative path => contents
     */
    public function project(array $files): string
    {
        $root = sys_get_temp_dir().'/risk-analyzer-'.bin2hex(random_bytes(6));

        foreach ($files as $path => $contents) {
            $target = $root.'/'.$path;
            @mkdir(dirname($target), 0777, true);
            file_put_contents($target, $contents);
        }

        @mkdir($root, 0777, true);

        return $this->projects[] = str_replace('\\', '/', $root);
    }

    protected function tearDown(): void
    {
        foreach ($this->projects as $project) {
            (new Filesystem)->deleteDirectory($project);
        }

        parent::tearDown();
    }
}

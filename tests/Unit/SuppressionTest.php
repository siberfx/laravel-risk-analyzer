<?php

use Siberfx\RiskAnalyzer\Baseline;
use Siberfx\RiskAnalyzer\Finding;
use Siberfx\RiskAnalyzer\Severity;

it('honours risk-analyzer-ignore on the same line or the line above', function (string $body, int $expected) {
    expect(findingsFor('sql-injection', controllerAction($body)))->toHaveCount($expected);
})->with([
    'same line' => ['DB::select("select $request->id"); // risk-analyzer-ignore sql-injection -- trusted', 0],
    'line above' => ["// risk-analyzer-ignore sql-injection -- id is validated upstream\nDB::select(\"select \$request->id\");", 0],
    'bare ignores every rule' => ["/* risk-analyzer-ignore */\nDB::select(\"select \$request->id\");", 0],
    'other rule id does not apply' => ["// risk-analyzer-ignore ssrf\nDB::select(\"select \$request->id\");", 1],
    'two lines above does not apply' => ["// risk-analyzer-ignore\n\nDB::select(\"select \$request->id\");", 1],
]);

it('keeps fingerprints stable when code moves to another line', function () {
    $make = fn (int $line) => new Finding('sql-injection', Severity::Critical, 'msg', 'app/A.php', $line, '   DB::select($sql);');

    expect($make(10)->fingerprint())->toBe($make(42)->fingerprint())
        ->and($make(10)->fingerprint())->not->toBe((new Finding('ssrf', Severity::High, 'msg', 'app/A.php', 10, 'DB::select($sql);'))->fingerprint());
});

it('round-trips a baseline file', function () {
    $finding = new Finding('debug-leftover', Severity::Low, 'dd() left in application code.', 'app/A.php', 3, 'dd($x);');
    $path = sys_get_temp_dir().'/risk-analyzer-baseline-'.uniqid().'.json';

    Baseline::fromFindings([$finding])->save($path);
    $loaded = Baseline::load($path);
    @unlink($path);

    expect($loaded->count())->toBe(1)
        ->and($loaded->contains($finding))->toBeTrue()
        ->and($loaded->contains(new Finding('debug-leftover', Severity::Low, 'x', 'app/B.php', 3, 'dd($x);')))->toBeFalse();
});

it('treats a missing baseline as empty', function () {
    expect(Baseline::load('/definitely/not/here.json')->count())->toBe(0);
});

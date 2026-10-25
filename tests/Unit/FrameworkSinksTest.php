<?php

use Siberfx\RiskAnalyzer\Finding;

/**
 * Wraps statements in a Symfony-style action that receives the request.
 */
function symfonyAction(string $body): string
{
    return "<?php\nuse Symfony\\Component\\HttpFoundation\\Request;\n\nfunction action(Request \$request, \$conn, \$em, \$qb)\n{\n{$body}\n}\n";
}

it('reports SQL built from input in PDO, mysqli, Doctrine and Yii2', function (string $code, ?string $severity) {
    $findings = findingsFor('sql-injection', $code);

    expect(array_map(fn (Finding $f) => $f->severity->value, $findings))->toBe($severity === null ? [] : [$severity]);
})->with([
    'pdo query concat' => ["<?php\n\$pdo->query('SELECT * FROM users WHERE id = ' . \$_GET['id']);", 'critical'],
    'pdo prepared' => ["<?php\n\$stmt = \$pdo->prepare('SELECT * FROM users WHERE id = ?');\n\$stmt->execute([\$_GET['id']]);", null],
    'pdo exec runtime' => ["<?php\nfunction drop(\$pdo, \$table) { \$pdo->exec(\"DELETE FROM {\$table}\"); }", 'medium'],
    'mysqli function' => ["<?php\nmysqli_query(\$link, \"SELECT * FROM t WHERE name = '\" . \$_POST['name'] . \"'\");", 'critical'],
    'mysqli object via variable' => ["<?php\n\$sql = 'SELECT * FROM t WHERE id = ' . \$_GET['id'];\n\$mysqli->query(\$sql);", 'critical'],
    'pg_query single argument' => ["<?php\npg_query('SELECT * FROM t WHERE id = ' . \$_GET['id']);", 'critical'],
    'dbal fetch' => [symfonyAction("    return \$conn->fetchAllAssociative(\"SELECT * FROM t WHERE name = '{\$request->query->get('n')}'\");"), 'critical'],
    'dbal bound parameters' => [symfonyAction("    return \$conn->executeQuery('SELECT * FROM t WHERE id = ?', [\$request->query->get('id')]);"), null],
    'dql createQuery' => [symfonyAction("    return \$em->createQuery(\"SELECT u FROM App\\\\Entity\\\\User u WHERE u.name = '\" . \$request->get('n') . \"'\");"), 'critical'],
    'querybuilder where concat' => [symfonyAction("    \$qb->where('u.id = ' . \$request->query->get('id'));"), 'critical'],
    'querybuilder where placeholder' => [symfonyAction("    \$qb->where('u.id = :id')->setParameter('id', \$request->query->get('id'));"), null],
    'yii2 createCommand' => ["<?php\nYii::\$app->db->createCommand('SELECT * FROM user WHERE id=' . Yii::\$app->request->get('id'))->queryAll();", 'critical'],
    'yii2 createCommand params' => ["<?php\nYii::\$app->db->createCommand('SELECT * FROM user WHERE id=:id', [':id' => Yii::\$app->request->get('id')])->queryAll();", null],
    'yii2 findBySql' => ["<?php\nCustomer::findBySql('SELECT * FROM customer WHERE id=' . \$_GET['id'])->all();", 'critical'],
    'yii2 where string' => ["<?php\n\$status = Yii::\$app->request->get('s');\nCustomer::find()->andWhere(\"status = \$status\")->all();", 'critical'],
    'yii2 where hash' => ["<?php\nCustomer::find()->where(['status' => Yii::\$app->request->get('s')])->all();", null],
    'laravel where column is not a condition' => ["<?php\nUser::where(\"name = {\$x}\")->get();\nDB::table('users')->where(\"name = {\$x}\")->get();", null],
    'laravel request query is not sql' => ["<?php\nfunction f(\\Illuminate\\Http\\Request \$request) { return \$request->query('page'); }", null],
    'http client query' => ["<?php\n\$http->query(['q' => \$_GET['q']]);", null],
]);

it('reports Symfony and Yii2 redirects to input', function (string $code, bool $reported) {
    expect(findingsFor('open-redirect', $code))->toHaveCount($reported ? 1 : 0);
})->with([
    'symfony RedirectResponse' => [symfonyAction("    return new \\Symfony\\Component\\HttpFoundation\\RedirectResponse(\$request->query->get('next'));"), true],
    'symfony controller redirect' => ["<?php\nclass C { public function a(\\Symfony\\Component\\HttpFoundation\\Request \$request) { return \$this->redirect(\$request->get('url')); } }", true],
    'symfony redirect to current uri' => ["<?php\nclass C { public function a(\\Symfony\\Component\\HttpFoundation\\Request \$request) { return \$this->redirect(\$request->getUri()); } }", false],
    'yii2 controller route array' => ["<?php\nclass C { public function a() { return \$this->redirect(['site/index']); } }", false],
    'yii2 response redirect' => ["<?php\nYii::\$app->response->redirect(Yii::\$app->request->get('return'));", true],
]);

it('reports echo and print of input', function (string $code, bool $reported) {
    expect(findingsFor('xss-echo', $code, 'views/site/index.php'))->toHaveCount($reported ? 1 : 0);
})->with([
    'echo superglobal' => ["<?php\necho \$_GET['q'];", true],
    // Templates open and close a PHP tag first, because the helper prepends one otherwise.
    'short echo tag' => ["<?php ?>\n<h1>Search</h1>\n<?= \$_GET['q'] ?>\n", true],
    'print post' => ["<?php\nprint \$_POST['name'];", true],
    'yii2 request in view' => ["<?php ?>\n<?= Yii::\$app->request->get('q') ?>", true],
    'htmlspecialchars' => ["<?php\necho htmlspecialchars(\$_GET['q'], ENT_QUOTES);", false],
    'yii2 Html::encode' => ["<?php ?>\n<?= Html::encode(Yii::\$app->request->get('q')) ?>", false],
    'cli argv' => ["<?php\necho \$_SERVER['argv'][1];", false],
    'plain variable' => ["<?php\necho \$title;", false],
]);

it('tracks Symfony and Yii2 request accessors as input', function (string $code) {
    expect(findingsFor('xss-echo', $code))->toHaveCount(1);
})->with([
    'yii2 getBodyParam' => ["<?php\necho Yii::\$app->request->getBodyParam('name');"],
    'yii2 getRequest()' => ["<?php\necho Yii::\$app->getRequest()->getQueryParam('q');"],
    'yii2 raw body' => ["<?php\necho Yii::\$app->request->getRawBody();"],
    'symfony request stack' => ["<?php\nfunction f(\$stack) { echo \$stack->getCurrentRequest()->query->get('q'); }"],
    'symfony toArray' => [symfonyAction("    echo \$request->toArray()['name'];")],
]);

<?php

use Siberfx\RiskAnalyzer\Finding;

/*
 * Each case: rule id, statements inside a controller action that receives
 * Request $request, and the expected severity (null = must not be reported).
 */
dataset('cases', [
    // SQL injection
    'sql: input interpolated' => ['sql-injection', '$id = $request->input("id"); DB::select("select * from users where id = $id");', 'critical'],
    'sql: input concatenated in whereRaw' => ['sql-injection', 'User::query()->whereRaw("name = \'" . request("name") . "\'")->get();', 'critical'],
    'sql: flows through helpers' => ['sql-injection', '$q = trim(strtolower($request->query("q"))); DB::statement("delete from t where x = " . $q);', 'critical'],
    'sql: runtime but not input' => ['sql-injection', '$table = $this->table(); DB::select("select * from {$table}");', 'medium'],
    'sql: bindings are fine' => ['sql-injection', 'DB::select("select * from users where id = ?", [$request->input("id")]);', null],
    'sql: literal-only variable is fine' => ['sql-injection', '$sql = "select 1"; DB::select($sql);', null],
    'sql: int cast is fine' => ['sql-injection', 'DB::select("select * from t where id = " . (int) $request->input("id"));', null],
    'sql: user-chosen orderBy column' => ['sql-injection', 'User::orderBy($request->input("sort"))->get();', 'medium'],
    'sql: validated orderBy column' => ['sql-injection', '$data = $request->validated(); $sort = $data["sort"] ?? "id"; User::orderBy($sort)->get();', null],
    'sql: in_array allow-list ternary' => ['sql-injection', '$by = in_array($request->input("by"), ["id", "name"]) ? $request->input("by") : "id"; User::orderBy($by)->get();', null],
    'sql: allow-list with cast' => ['sql-injection', '$by = in_array($request->input("by"), ["id"], true) ? (string) $request->input("by") : null; User::orderBy($by)->get();', null],
    'sql: inside in_array guard' => ['sql-injection', '$by = $request->query("by"); if (in_array($by, ["id", "name"])) { $q->orderBy($by); }', null],
    'sql: after negated guard' => ['sql-injection', '$by = $request->query("by"); if (! in_array($by, ["id"])) { abort(400); } $q->orderBy($by);', null],
    'sql: guard does not leak' => ['sql-injection', '$by = $request->query("by"); if (in_array($by, ["id"])) { } $q->orderBy($by);', 'medium'],
    'sql: mail from() is not a builder' => ['sql-injection', '$message->to($request->email)->from($request->from);', null],
    'sql: DB::table(input)' => ['sql-injection', 'DB::table($request->input("t"))->get();', 'medium'],
    'sql: enum from() is not a builder' => ['sql-injection', 'Role::from((string) $request->input("role"));', null],
    'sql: runtime sql with bindings' => ['sql-injection', '$q->whereRaw($sql, $bindings);', null],
    'sql: DB::table()->select() is a builder' => ['sql-injection', 'DB::table("users")->select("name")->get();', null],
    'sql: overwritten variable is clean' => ['sql-injection', '$v = $request->input("v"); $v = "fixed"; DB::select("select $v");', null],

    // Command injection
    'cmd: exec with input' => ['command-injection', 'exec("convert " . $request->file("f")->getClientOriginalName());', 'critical'],
    'cmd: backticks' => ['command-injection', '$h = $request->host; $out = `ping $h`;', 'critical'],
    'cmd: Process::run string' => ['command-injection', '\Illuminate\Support\Facades\Process::run("git log " . $request->input("ref"));', 'critical'],
    'cmd: escapeshellarg' => ['command-injection', 'exec("convert " . escapeshellarg($request->input("f")));', null],
    'cmd: array form' => ['command-injection', '\Illuminate\Support\Facades\Process::run(["git", "log", $request->input("ref")]);', null],

    // Code execution
    'eval of input' => ['code-execution', 'eval($request->input("code"));', 'critical'],
    'include of input' => ['code-execution', 'include $request->input("page") . ".php";', 'critical'],
    'call_user_func of input' => ['code-execution', 'call_user_func($request->input("fn"));', 'high'],

    // Deserialization
    'unserialize input' => ['insecure-deserialization', 'unserialize($request->cookie("cart"));', 'critical'],
    'unserialize restricted' => ['insecure-deserialization', 'unserialize($request->cookie("cart"), ["allowed_classes" => false]);', null],
    'unserialize runtime value' => ['insecure-deserialization', 'unserialize($payload);', 'medium'],

    // Path traversal
    'path: file_get_contents' => ['path-traversal', 'return file_get_contents(storage_path("docs/" . $request->input("file")));', 'high'],
    'path: Storage::download' => ['path-traversal', 'return Storage::download($request->query("path"));', 'high'],
    'path: client file name' => ['path-traversal', '$f = $request->file("avatar"); $f->storeAs("avatars", $f->getClientOriginalName());', 'high'],
    'path: basename' => ['path-traversal', 'return Storage::get("docs/" . basename($request->input("file")));', null],
    'path: store() random name' => ['path-traversal', '$request->file("avatar")->store("avatars");', null],

    // SSRF
    'ssrf: Http::get' => ['ssrf', 'Http::get($request->input("url"));', 'high'],
    'ssrf: chained Http' => ['ssrf', 'Http::withToken("x")->timeout(5)->post($request->input("webhook"), []);', 'high'],
    'ssrf: curl' => ['ssrf', '$ch = curl_init(); curl_setopt($ch, CURLOPT_URL, $request->url);', 'high'],
    'ssrf: fixed url' => ['ssrf', 'Http::get("https://api.example.com/" . (int) $request->input("id"));', null],

    // Open redirect
    'redirect()->away' => ['open-redirect', 'return redirect()->away($request->input("next"));', 'high'],
    'redirect(input)' => ['open-redirect', 'return redirect($request->query("return_to"));', 'high'],
    'Location header' => ['open-redirect', 'header("Location: " . $_GET["u"]);', 'high'],
    'redirect to current url' => ['open-redirect', 'return redirect($request->fullUrl());', null],
    'redirect to route' => ['open-redirect', 'return redirect()->route("home");', null],

    // XXE
    'xxe: LIBXML_NOENT on input' => ['xxe', 'simplexml_load_string($request->getContent(), "SimpleXMLElement", LIBXML_NOENT);', 'high'],
    'xxe: flag on runtime xml' => ['xxe', '$doc = new \DOMDocument; $doc->loadXML($xml, LIBXML_DTDLOAD | LIBXML_NONET);', 'medium'],
    'xxe: plain parse' => ['xxe', 'simplexml_load_string($request->getContent());', null],

    // Mass assignment
    'mass: create(all)' => ['mass-assignment', 'User::create($request->all());', 'medium'],
    'mass: forceFill(input)' => ['mass-assignment', '$user->forceFill(request()->all())->save();', 'high'],
    'mass: validated' => ['mass-assignment', 'User::create($request->validated());', null],
    'mass: Validator::make is not a write' => ['mass-assignment', 'Validator::make($request->all(), ["a" => "required"]);', null],
    'mass: only()' => ['mass-assignment', 'User::create($request->only("name", "email"));', null],

    // TLS
    'tls: withoutVerifying' => ['tls-verification-disabled', 'Http::withoutVerifying()->get("https://x.test");', 'high'],
    'tls: guzzle verify false' => ['tls-verification-disabled', 'new \GuzzleHttp\Client(["verify" => false]);', 'high'],
    'tls: curl verifypeer 0' => ['tls-verification-disabled', 'curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);', 'high'],
    'tls: verify true' => ['tls-verification-disabled', 'new \GuzzleHttp\Client(["verify" => true]);', null],

    // Weak crypto
    'crypto: md5 password' => ['weak-cryptography', '$user->password = md5($request->input("password"));', 'high'],
    'crypto: ecb' => ['weak-cryptography', 'openssl_encrypt($data, "aes-128-ecb", $key);', 'high'],
    'crypto: == on signature' => ['weak-cryptography', 'if ($signature == $request->header("X-Signature")) {}', 'medium'],
    'crypto: md5 cache key' => ['weak-cryptography', '$key = md5($request->fullUrl());', null],

    // Randomness
    'rng: token from mt_rand' => ['insecure-randomness', '$token = md5(mt_rand());', 'high'],
    'rng: otp property' => ['insecure-randomness', '$user->otp_code = rand(100000, 999999);', 'high'],
    'rng: random_int' => ['insecure-randomness', '$user->otp_code = random_int(100000, 999999);', null],
    'rng: unrelated name' => ['insecure-randomness', '$color = mt_rand(0, 5);', null],

    // Debug
    'debug: dd' => ['debug-leftover', 'dd($request->all());', 'low'],
    'debug: query ->dd()' => ['debug-leftover', 'User::where("a", 1)->dd();', 'low'],
    'debug: phpinfo' => ['debug-leftover', 'phpinfo();', 'high'],
    'debug: print_r return' => ['debug-leftover', 'logger(print_r($data, true));', null],

    // Secrets
    'secret: stripe key' => ['hardcoded-secret', '$stripe = new \Stripe\StripeClient("sk_'.'live_51HxQbXJk2cV9aBcDeFgHiJkLmNoP");', 'critical'],
    'secret: aws key' => ['hardcoded-secret', '$c = ["key" => "AKIA'.'IOSFODNN7EXAMPLQ"];', 'critical'],
    'secret: password literal' => ['hardcoded-secret', '$client->login(password: "Xk9#mP2vL!qR7");', 'high'],
    'secret: placeholder' => ['hardcoded-secret', '$c = ["password" => "your-password-here"];', null],
    'secret: field name' => ['hardcoded-secret', '$c = ["password_field" => "user_password_input"];', null],
]);

it('reports or ignores', function (string $rule, string $body, ?string $severity) {
    $findings = findingsFor($rule, controllerAction($body));

    if ($severity === null) {
        expect($findings)->toBeEmpty();
    } else {
        expect($findings)->not->toBeEmpty()
            ->and($findings[0]->severity->value)->toBe($severity);
    }
})->with('cases');

it('reports the line of the sink and the source snippet', function () {
    $findings = findingsFor('sql-injection', controllerAction("        \$id = \$request->id;\n        DB::select(\"select * from t where id = \$id\");"));

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->line)->toBe(12)
        ->and($findings[0]->snippet)->toContain('DB::select')
        ->and($findings[0]->file)->toBe('app/Http/Controllers/DemoController.php');
});

it('tracks request objects passed as typed FormRequest parameters', function () {
    $code = <<<'PHP'
    <?php
    class OrderController {
        public function store(StoreOrderRequest $input) {
            DB::select('select * from orders where ref = "' . $input->get('ref') . '"');
        }
    }
    PHP;

    expect(findingsFor('sql-injection', $code))->toHaveCount(1);
});

it('keeps taint inside the function it belongs to', function () {
    $code = <<<'PHP'
    <?php
    class A {
        public function one(Request $request) { $q = $request->input('q'); }
        public function two() { DB::select("select $q"); }
    }
    PHP;

    $findings = findingsFor('sql-injection', $code);

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity->value)->toBe('medium');
});

it('carries taint into closures and foreach loops', function () {
    $closure = controllerAction('$name = $request->input("n"); collect([1])->each(function () use ($name) { DB::select("select $name"); });');
    $loop = controllerAction('foreach ($request->input("ids") as $id) { DB::delete("delete from t where id = $id"); }');

    expect(findingsFor('sql-injection', $closure)[0]->severity->value)->toBe('critical')
        ->and(findingsFor('sql-injection', $loop)[0]->severity->value)->toBe('critical');
});

it('flags empty $guarded and #[Unguarded] on models', function () {
    $code = <<<'PHP'
    <?php
    use Illuminate\Database\Eloquent\Model;
    use Illuminate\Database\Eloquent\Attributes\Unguarded;

    class Post extends Model { protected $guarded = []; }

    #[Unguarded]
    class Comment extends Model {}

    class Plain { protected $guarded = []; }
    PHP;

    expect(findingsFor('mass-assignment', $code, 'app/Models/Post.php'))->toHaveCount(2);
});

it('flags hard-coded env() fallbacks in config files', function () {
    $code = "<?php\nreturn ['secret' => env('STRIPE_SECRET', 'whsec_"."9fKq2LmZp8XcVb7nRt'), 'name' => env('APP_NAME', 'Laravel')];";

    $findings = findingsFor('hardcoded-secret', $code, 'config/services.php');

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->message)->toContain('STRIPE_SECRET');
});

it('ignores verify => false in config files', function () {
    expect(findingsFor('tls-verification-disabled', "<?php\nreturn ['verify' => false];", 'config/mail.php'))->toBeEmpty();
});

it('reports files that do not parse instead of crashing', function () {
    $findings = analyse('<?php function (');

    expect($findings)->toHaveCount(1)
        ->and($findings[0])->toBeInstanceOf(Finding::class)
        ->and($findings[0]->rule)->toBe('parse-error');
});

it('does not mistake validation rules, casts or table names for secrets', function () {
    $code = <<<'PHP'
    <?php
    $request->validate(['api_key' => 'nullable|string|max:255', 'password' => 'required|current_password']);
    $casts = ['api_credentials' => 'encrypted:array'];
    return ['table' => env('AUTH_PASSWORD_RESET_TOKEN_TABLE', 'password_reset_tokens'), 'password' => 'secret-password'];
    PHP;

    expect(findingsFor('hardcoded-secret', $code))->toBeEmpty()
        ->and(findingsFor('hardcoded-secret', "<?php\nreturn ['password' => env('DB_PASSWORD', '14396Oem0012443')];", 'config/database.php'))->toHaveCount(1);
});

it('only treats request-derived $_SERVER keys as input', function () {
    expect(findingsFor('path-traversal', "<?php\nglob(\$_SERVER['HOME'].'/bin/*');"))->toBeEmpty()
        ->and(findingsFor('path-traversal', "<?php\nreadfile(\$_SERVER['HTTP_X_FILE']);"))->toHaveCount(1);
});

it('only reports input-built SQL in migrations', function () {
    $migration = "<?php\nDB::statement(sprintf('ALTER TABLE %s CONVERT TO CHARACTER SET utf8mb4', \$table));";

    expect(findingsFor('sql-injection', $migration, 'database/migrations/2026_01_01_000000_convert.php'))->toBeEmpty()
        ->and(findingsFor('sql-injection', $migration, 'app/Console/Commands/Convert.php'))->toHaveCount(1);
});

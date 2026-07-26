# pii-protect/monolog-handler

A [Monolog](https://github.com/Seldaek/monolog) handler and processor that anonymize PII (Personally Identifiable Information) in log records before they are written, by calling the [PII Protect](https://github.com/pii-protect) engine API.

---

## Requirements

- PHP 8.1+
- `monolog/monolog` ^3.0
- `guzzlehttp/guzzle` ^7.0

---

## Installation

```bash
composer require pii-protect/monolog-handler
```

---

## Quick Start

### Option A — Handler (wraps another handler)

```php
use Monolog\Handler\StreamHandler;
use Monolog\Level;
use Monolog\Logger;
use PiiProtect\Monolog\PiiProtectHandler;

$fileHandler = new StreamHandler(storage_path('logs/laravel.log'), Level::Debug);

$piiHandler = new PiiProtectHandler(
    engineUrl: env('PII_PROTECT_ENGINE_URL', 'http://localhost:8000'),
    apiKey:    env('PII_PROTECT_API_KEY'),
    inner:     $fileHandler,
    level:     Level::Debug,
    bubble:    true,
    timeoutMs: 500,   // max time to wait for the engine (fail-safe: uses original text on timeout)
);

$logger = new Logger('app', [$piiHandler]);
$logger->info('User mario@example.com logged in from 192.168.1.1');
// Written as: "User [EMAIL] logged in from [IP_ADDRESS]"
```

### Option B — Processor (stack on any handler)

```php
use Monolog\Handler\StreamHandler;
use Monolog\Level;
use Monolog\Logger;
use PiiProtect\Monolog\PiiProtectProcessor;

$processor = new PiiProtectProcessor(
    engineUrl: env('PII_PROTECT_ENGINE_URL', 'http://localhost:8000'),
    apiKey:    env('PII_PROTECT_API_KEY'),
    timeoutMs: 500,
    skipKeys:  ['password', 'token'],   // never anonymize these context keys
);

$logger = new Logger('app');
$logger->pushHandler(new StreamHandler('php://stdout', Level::Debug));
$logger->pushProcessor($processor);

$logger->info('Login attempt', [
    'email'    => 'mario@example.com',   // anonymized
    'password' => 's3cr3t',              // skipped
]);
// message:  "Login attempt"  (no PII here)
// context:  ['email' => '[EMAIL]', 'password' => 's3cr3t']
```

The processor batches all strings in the message + context + extra into a **single** API call per log record, minimizing latency.

---

## Laravel Integration

### 1. Add to `config/logging.php`

```php
use Monolog\Handler\StreamHandler;
use Monolog\Level;
use PiiProtect\Monolog\PiiProtectHandler;

'channels' => [
    'pii_safe' => [
        'driver' => 'monolog',
        'handler' => PiiProtectHandler::class,
        'handler_with' => [
            'engineUrl' => env('PII_PROTECT_ENGINE_URL', 'http://localhost:8000'),
            'apiKey'    => env('PII_PROTECT_API_KEY'),
            'inner'     => new StreamHandler(storage_path('logs/laravel.log'), Level::Debug),
        ],
    ],

    // Or as a stack with the processor:
    'pii_stack' => [
        'driver' => 'stack',
        'channels' => ['single'],
        'ignore_exceptions' => false,
    ],
],
```

### 2. Using a tap (recommended for processor approach)

```php
// config/logging.php
'channels' => [
    'single' => [
        'driver' => 'single',
        'path'   => storage_path('logs/laravel.log'),
        'level'  => env('LOG_LEVEL', 'debug'),
        'tap'    => [App\Logging\AddPiiProcessor::class],
    ],
],
```

```php
// app/Logging/AddPiiProcessor.php
namespace App\Logging;

use Illuminate\Log\Logger;
use PiiProtect\Monolog\PiiProtectProcessor;

class AddPiiProcessor
{
    public function __invoke(Logger $logger): void
    {
        $logger->pushProcessor(new PiiProtectProcessor(
            engineUrl: config('services.pii_protect.url'),
            apiKey:    config('services.pii_protect.key'),
            skipKeys:  ['password', 'password_confirmation', '_token'],
        ));
    }
}
```

---

## Symfony Integration

```yaml
# config/packages/monolog.yaml
monolog:
  handlers:
    pii_protect:
      type:    service
      id:      PiiProtect\Monolog\PiiProtectHandler

    main:
      type:    stream
      path:    "%kernel.logs_dir%/%kernel.environment%.log"
      level:   debug
      members: [pii_protect]
```

```yaml
# config/services.yaml
services:
  PiiProtect\Monolog\PiiProtectHandler:
    arguments:
      $engineUrl: '%env(PII_PROTECT_ENGINE_URL)%'
      $apiKey:    '%env(PII_PROTECT_API_KEY)%'
      $level:     !php/const Monolog\Level::Debug
```

---

## API Client

You can use `PiiProtectClient` directly:

```php
use PiiProtect\Monolog\PiiProtectClient;

$client = new PiiProtectClient(
    engineUrl: 'http://localhost:8000',
    apiKey:    'my-key',
    timeoutMs: 300,
);

$clean = $client->anonymize('Call me at +39 02 1234 5678');
// "Call me at [PHONE]"

$results = $client->anonymizeBatch([
    'Mario Rossi',
    'mario@example.com',
    'RSSMRA80A01H501U',
]);
// ['[NAME]', '[EMAIL]', '[FISCAL_CODE]']
```

Both methods **never throw**. On any network or API error, the original text is returned so your application keeps running.

---

## Running Tests

```bash
composer install
./vendor/bin/phpunit tests/
```

---

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `PII_PROTECT_ENGINE_URL` | `http://localhost:8000` | Base URL of the PII Protect engine |
| `PII_PROTECT_API_KEY` | — | API key for authentication |

---

## License

MIT

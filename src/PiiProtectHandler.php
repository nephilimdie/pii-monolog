<?php

declare(strict_types=1);

namespace PiiProtect\Monolog;

use Monolog\Handler\AbstractProcessingHandler;
use Monolog\Handler\HandlerInterface;
use Monolog\Handler\StreamHandler;
use Monolog\Level;
use Monolog\LogRecord;

/**
 * Monolog handler that anonymizes PII from log messages before forwarding
 * records to an inner handler.
 *
 * Usage:
 *
 *   $innerHandler = new StreamHandler('/var/log/app.log', Level::Debug);
 *   $handler = new PiiProtectHandler(
 *       engineUrl: 'https://pii-engine.example.com',
 *       apiKey:    'your-api-key',
 *       inner:     $innerHandler,
 *   );
 *   $logger = new Logger('app', [$handler]);
 */
class PiiProtectHandler extends AbstractProcessingHandler
{
    private PiiProtectClient $client;
    private PiiProtectProcessor $processor;
    private HandlerInterface $inner;

    /**
     * @param string           $engineUrl  Base URL of the PII Protect engine.
     * @param string           $apiKey     API key for authentication.
     * @param HandlerInterface|null $inner  Inner handler that receives the sanitized record.
     *                                     When null, a StreamHandler writing to stderr is used.
     * @param Level|int        $level      Minimum log level this handler processes.
     * @param bool             $bubble     Whether records bubble up to other handlers.
     * @param int              $timeoutMs  HTTP request timeout in milliseconds.
     */
    public function __construct(
        string $engineUrl,
        string $apiKey,
        ?HandlerInterface $inner = null,
        Level|int $level = Level::Debug,
        bool $bubble = false,
        int $timeoutMs = 30000,
    ) {
        if ($bubble) {
            throw new \InvalidArgumentException('Use a logger-level processor for multiple handlers; bubbling original records is unsafe.');
        }
        parent::__construct($level, false);

        $this->client = new PiiProtectClient($engineUrl, $apiKey, $timeoutMs);
        $this->processor = new PiiProtectProcessor($engineUrl, $apiKey, $timeoutMs);
        $this->processor->setClient($this->client);
        $this->inner  = $inner ?? new StreamHandler('php://stderr', $level);
    }

    /**
     * Allow injecting a pre-built PiiProtectClient (useful for testing).
     */
    public function setClient(PiiProtectClient $client): void
    {
        $this->client = $client;
        $this->processor->setClient($client);
    }

    /**
     * {@inheritdoc}
     *
     * Anonymizes the log message (and formatted output) then forwards the
     * sanitized record to the inner handler.
     */
    protected function write(LogRecord $record): void
    {
        $this->inner->handle(($this->processor)($record));
    }

    /**
     * Convenience: anonymize a string using the configured client.
     */
    public function anonymize(string $text): string
    {
        return $this->client->anonymize($text);
    }

    /**
     * {@inheritdoc}
     */
    public function close(): void
    {
        $this->inner->close();
        parent::close();
    }
}

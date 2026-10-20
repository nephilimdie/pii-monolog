<?php

declare(strict_types=1);

namespace PiiProtect\Monolog;

use Monolog\LogRecord;
use Monolog\Processor\ProcessorInterface;

/** Protects message and nested context/extra values before any sink. */
class PiiProtectProcessor implements ProcessorInterface
{
    private PiiProtectClient $client;

    public function __construct(
        string $engineUrl,
        string $apiKey,
        int $timeoutMs = 30000,
        private array $skipKeys = [],
    ) {
        $this->client = new PiiProtectClient($engineUrl, $apiKey, $timeoutMs);
    }

    public function setClient(PiiProtectClient $client): void
    {
        $this->client = $client;
    }

    public function __invoke(LogRecord $record): LogRecord
    {
        return new LogRecord(
            datetime: $record->datetime,
            channel: $record->channel,
            level: $record->level,
            message: $this->client->anonymize($record->message),
            context: $this->protectArray($record->context),
            extra: $this->protectArray($record->extra),
        );
    }

    private function protectArray(array $data): array
    {
        foreach ($data as $key => $value) {
            if (in_array($key, $this->skipKeys, true)) {
                // Excluded secrets must not be sent to the API or to log sinks.
                $data[$key] = '[REDACTED]';
            } elseif (is_string($value)) {
                $data[$key] = $this->client->anonymize($value);
            } elseif (is_array($value)) {
                $data[$key] = $this->protectArray($value);
            } elseif (is_object($value) || is_resource($value)) {
                // Exception messages and arbitrary object properties may contain PII.
                $data[$key] = '[REDACTED]';
            }
        }
        return $data;
    }
}

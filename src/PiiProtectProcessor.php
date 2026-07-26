<?php

declare(strict_types=1);

namespace PiiProtect\Monolog;

use Monolog\LogRecord;
use Monolog\Processor\ProcessorInterface;

/**
 * Monolog processor that anonymizes PII in the message, context, and extra
 * fields of every log record passing through the logger.
 *
 * Processors are cheaper to attach than handlers: add this processor to a
 * logger and pair it with any standard handler (file, syslog, Slack…).
 *
 * Usage:
 *
 *   $processor = new PiiProtectProcessor(
 *       engineUrl: 'https://pii-engine.example.com',
 *       apiKey:    'your-api-key',
 *   );
 *   $logger->pushProcessor($processor);
 */
class PiiProtectProcessor implements ProcessorInterface
{
    private PiiProtectClient $client;

    /** Context/extra keys that must never be anonymized. */
    private array $skipKeys;

    /**
     * @param string   $engineUrl  Base URL of the PII Protect engine.
     * @param string   $apiKey     API key for authentication.
     * @param int      $timeoutMs  HTTP request timeout in milliseconds.
     * @param string[] $skipKeys   Array of context/extra key names to skip.
     */
    public function __construct(
        string $engineUrl,
        string $apiKey,
        int $timeoutMs = 500,
        array $skipKeys = [],
    ) {
        $this->client   = new PiiProtectClient($engineUrl, $apiKey, $timeoutMs);
        $this->skipKeys = $skipKeys;
    }

    /**
     * Allow injecting a pre-built PiiProtectClient (useful for testing).
     */
    public function setClient(PiiProtectClient $client): void
    {
        $this->client = $client;
    }

    /**
     * {@inheritdoc}
     *
     * Collects all string values that need anonymization, sends them as a
     * single batch request to minimize latency, then rebuilds the record.
     */
    public function __invoke(LogRecord $record): LogRecord
    {
        // ---- Collect all texts to anonymize in one batch ----
        $texts   = [];
        $mapping = []; // maps a "slot key" to the batch index

        // 1. The message itself
        $texts[]           = $record->message;
        $mapping['message'] = array_key_last($texts);

        // 2. String values in context
        foreach ($record->context as $key => $value) {
            if (is_string($value) && !in_array($key, $this->skipKeys, true)) {
                $texts[]                       = $value;
                $mapping['context.' . $key]   = array_key_last($texts);
            }
        }

        // 3. String values in extra
        foreach ($record->extra as $key => $value) {
            if (is_string($value) && !in_array($key, $this->skipKeys, true)) {
                $texts[]                     = $value;
                $mapping['extra.' . $key]   = array_key_last($texts);
            }
        }

        // ---- Batch anonymize ----
        $anonymized = $this->client->anonymizeBatch($texts);

        // ---- Rebuild fields ----
        $newMessage = $anonymized[$mapping['message']] ?? $record->message;

        $newContext = $record->context;
        foreach ($record->context as $key => $value) {
            $slot = 'context.' . $key;
            if (isset($mapping[$slot])) {
                $newContext[$key] = $anonymized[$mapping[$slot]] ?? $value;
            }
        }

        $newExtra = $record->extra;
        foreach ($record->extra as $key => $value) {
            $slot = 'extra.' . $key;
            if (isset($mapping[$slot])) {
                $newExtra[$key] = $anonymized[$mapping[$slot]] ?? $value;
            }
        }

        return new LogRecord(
            datetime: $record->datetime,
            channel:  $record->channel,
            level:    $record->level,
            message:  $newMessage,
            context:  $newContext,
            extra:    $newExtra,
        );
    }
}

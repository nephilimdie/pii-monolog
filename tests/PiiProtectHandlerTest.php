<?php

declare(strict_types=1);

namespace PiiProtect\Monolog\Tests;

use GuzzleHttp\Client;
use GuzzleHttp\Exception\ConnectException;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;
use Monolog\Handler\TestHandler;
use Monolog\Level;
use Monolog\Logger;
use Monolog\LogRecord;
use PHPUnit\Framework\TestCase;
use PiiProtect\Monolog\PiiProtectClient;
use PiiProtect\Monolog\PiiProtectHandler;
use PiiProtect\Monolog\PiiProtectProcessor;

class PiiProtectHandlerTest extends TestCase
{
    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    /**
     * Build a PiiProtectClient backed by a Guzzle MockHandler.
     *
     * @param  Response[]|\Throwable[] $responses  Queue of responses/exceptions.
     */
    private function buildClient(array $responses): PiiProtectClient
    {
        $mock    = new MockHandler($responses);
        $stack   = HandlerStack::create($mock);
        $guzzle  = new Client(['handler' => $stack]);

        // Reach into PiiProtectClient and swap the internal Guzzle client.
        $clientRef = new PiiProtectClient('http://engine.test', 'test-key');

        // setAccessible() is a no-op since PHP 8.1 and deprecated in 8.5.
        $reflection = new \ReflectionProperty(PiiProtectClient::class, 'httpClient');
        $reflection->setValue($clientRef, $guzzle);

        return $clientRef;
    }

    private function makeRecord(string $message, array $context = [], array $extra = []): LogRecord
    {
        return new LogRecord(
            datetime: new \DateTimeImmutable(),
            channel:  'test',
            level:    Level::Info,
            message:  $message,
            context:  $context,
            extra:    $extra,
        );
    }

    // ------------------------------------------------------------------
    // PiiProtectClient tests
    // ------------------------------------------------------------------

    public function testAnonymizeReturnsAnonymizedText(): void
    {
        $client = $this->buildClient([
            new Response(200, [], json_encode(['anonymized_text' => 'Hello [REDACTED]'])),
        ]);

        $result = $client->anonymize('Hello Mario Rossi');

        self::assertSame('Hello [REDACTED]', $result);
    }

    public function testAnonymizeReturnsOriginalOnHttpError(): void
    {
        $client = $this->buildClient([
            new Response(500, [], 'Internal Server Error'),
        ]);

        $result = $client->anonymize('sensitive data');

        self::assertSame('sensitive data', $result);
    }

    public function testAnonymizeReturnsOriginalOnConnectionError(): void
    {
        $request = new Request('POST', '/v1/anonymize');
        $client  = $this->buildClient([
            new ConnectException('Connection refused', $request),
        ]);

        $result = $client->anonymize('sensitive data');

        self::assertSame('sensitive data', $result);
    }

    public function testAnonymizeReturnsEmptyStringUnchanged(): void
    {
        // No HTTP call should be made for empty strings
        $client = $this->buildClient([]); // no queued responses

        $result = $client->anonymize('');

        self::assertSame('', $result);
    }

    public function testAnonymizeBatchReturnsAnonymizedTexts(): void
    {
        $client = $this->buildClient([
            new Response(200, [], json_encode([
                'items' => [
                    ['id' => '0', 'status' => 'processed', 'output' => 'Hello [NAME]', 'error_code' => null],
                    ['id' => '1', 'status' => 'processed', 'output' => 'email [EMAIL]', 'error_code' => null],
                ],
            ])),
        ]);

        $result = $client->anonymizeBatch(['Hello Mario', 'email mario@example.com']);

        self::assertSame(['Hello [NAME]', 'email [EMAIL]'], $result);
    }

    public function testAnonymizeBatchFallsBackOnError(): void
    {
        $client = $this->buildClient([
            new Response(500),
        ]);

        $input  = ['text one', 'text two'];
        $result = $client->anonymizeBatch($input);

        self::assertSame($input, $result);
    }

    public function testAnonymizeBatchEmptyArrayReturnsImmediately(): void
    {
        $client = $this->buildClient([]); // no responses queued

        $result = $client->anonymizeBatch([]);

        self::assertSame([], $result);
    }

    // ------------------------------------------------------------------
    // PiiProtectHandler tests
    // ------------------------------------------------------------------

    public function testHandlerAnonymizesMessageBeforeForwarding(): void
    {
        $innerHandler = new TestHandler();
        $handler      = new PiiProtectHandler(
            engineUrl: 'http://engine.test',
            apiKey:    'test-key',
            inner:     $innerHandler,
        );

        $mockedClient = $this->buildClient([
            new Response(200, [], json_encode(['anonymized_text' => 'User [NAME] logged in'])),
        ]);
        $handler->setClient($mockedClient);

        $logger = new Logger('test', [$handler]);
        $logger->info('User Mario Rossi logged in');

        $records = $innerHandler->getRecords();
        self::assertCount(1, $records);
        self::assertSame('User [NAME] logged in', $records[0]->message);
    }

    public function testHandlerForwardsOriginalMessageOnApiError(): void
    {
        $innerHandler = new TestHandler();
        $handler      = new PiiProtectHandler(
            engineUrl: 'http://engine.test',
            apiKey:    'test-key',
            inner:     $innerHandler,
        );

        $mockedClient = $this->buildClient([new Response(503)]);
        $handler->setClient($mockedClient);

        $logger = new Logger('test', [$handler]);
        $logger->info('Original message');

        $records = $innerHandler->getRecords();
        self::assertSame('Original message', $records[0]->message);
    }

    // ------------------------------------------------------------------
    // PiiProtectProcessor tests
    // ------------------------------------------------------------------

    public function testProcessorAnonymizesMessageAndContext(): void
    {
        $processor = new PiiProtectProcessor('http://engine.test', 'test-key');

        $mockedClient = $this->buildClient([
            new Response(200, [], json_encode([
                'items' => [
                    ['id' => '0', 'status' => 'processed', 'output' => 'User [NAME] logged in', 'error_code' => null],
                    ['id' => '1', 'status' => 'processed', 'output' => '[EMAIL]', 'error_code' => null],
                ],
            ])),
        ]);
        $processor->setClient($mockedClient);

        $record    = $this->makeRecord('User Mario Rossi logged in', ['email' => 'mario@example.com']);
        $processed = $processor($record);

        self::assertSame('User [NAME] logged in', $processed->message);
        self::assertSame('[EMAIL]', $processed->context['email']);
    }

    public function testProcessorSkipsSpecifiedContextKeys(): void
    {
        $processor = new PiiProtectProcessor('http://engine.test', 'test-key', skipKeys: ['password']);

        // Only one text is sent to the API (the message), password is skipped
        $mockedClient = $this->buildClient([
            new Response(200, [], json_encode([
                'items' => [
                    ['id' => '0', 'status' => 'processed', 'output' => 'login attempt', 'error_code' => null],
                ],
            ])),
        ]);
        $processor->setClient($mockedClient);

        $record    = $this->makeRecord('login attempt', ['password' => 'secret123']);
        $processed = $processor($record);

        self::assertSame('login attempt', $processed->message);
        // Password must not be touched
        self::assertSame('secret123', $processed->context['password']);
    }

    public function testProcessorPreservesNonStringContextValues(): void
    {
        $processor = new PiiProtectProcessor('http://engine.test', 'test-key');

        $mockedClient = $this->buildClient([
            new Response(200, [], json_encode([
                'items' => [
                    ['id' => '0', 'status' => 'processed', 'output' => 'message', 'error_code' => null],
                ],
            ])),
        ]);
        $processor->setClient($mockedClient);

        $record    = $this->makeRecord('message', ['count' => 42, 'flag' => true]);
        $processed = $processor($record);

        self::assertSame(42, $processed->context['count']);
        self::assertTrue($processed->context['flag']);
    }
}

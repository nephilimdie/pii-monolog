<?php

declare(strict_types=1);

namespace PiiProtect\Monolog\Tests;

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
    private function client(): PiiProtectClient
    {
        $client = $this->createMock(PiiProtectClient::class);
        $client->method('anonymize')->willReturnCallback(fn (string $text) => '[' . strtoupper($text) . ']');
        return $client;
    }

    public function testHandlerProtectsNestedValuesAndDoesNotBubble(): void
    {
        $inner = new TestHandler();
        $other = new TestHandler();
        $handler = new PiiProtectHandler('https://engine.test', 'key', $inner);
        $handler->setClient($this->client());
        $logger = new Logger('app', [$handler, $other]);
        $logger->info('alice', ['nested' => ['email' => 'a@b.test']]);
        self::assertCount(1, $inner->getRecords());
        self::assertSame('[ALICE]', $inner->getRecords()[0]->message);
        self::assertSame('[A@B.TEST]', $inner->getRecords()[0]->context['nested']['email']);
        self::assertCount(0, $other->getRecords());
    }

    public function testFailureNeverReachesAnySink(): void
    {
        $inner = new TestHandler();
        $other = new TestHandler();
        $handler = new PiiProtectHandler('https://engine.test', 'key', $inner);
        $client = $this->createMock(PiiProtectClient::class);
        $client->method('anonymize')->willThrowException(new \RuntimeException('Protection failed'));
        $handler->setClient($client);
        try {
            (new Logger('app', [$handler, $other]))->info('private-value');
            self::fail('Expected failure');
        } catch (\RuntimeException) {
            self::assertCount(0, $inner->getRecords());
            self::assertCount(0, $other->getRecords());
        }
    }

    public function testProcessorProtectsNestedContextExtraAndRedactsSecretsAndObjects(): void
    {
        $processor = new PiiProtectProcessor('https://engine.test', 'key', skipKeys: ['password']);
        $processor->setClient($this->client());
        $record = new LogRecord(new \DateTimeImmutable(), 'app', Level::Info, 'alice',
            ['password' => 'secret', 'a.b' => 'literal', 'a' => ['b' => 'nested'], 'count' => 42],
            ['nested' => ['email' => 'a@b.test'], 'error' => new \RuntimeException('private-value')]);
        $result = $processor($record);
        self::assertSame('[REDACTED]', $result->context['password']);
        self::assertSame('[LITERAL]', $result->context['a.b']);
        self::assertSame('[NESTED]', $result->context['a']['b']);
        self::assertSame(42, $result->context['count']);
        self::assertSame('[A@B.TEST]', $result->extra['nested']['email']);
        self::assertSame('[REDACTED]', $result->extra['error']);
        self::assertSame('alice', $record->message);
    }

    public function testBubblingCannotLeakTheOriginalRecord(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new PiiProtectHandler('https://engine.test', 'key', bubble: true);
    }
}

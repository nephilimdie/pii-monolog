<?php

declare(strict_types=1);

namespace PiiProtect\Monolog\Tests;

use GuzzleHttp\Client;
use GuzzleHttp\Exception\ConnectException;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;
use PiiProtect\Monolog\PiiProtectClient;

class ClientSafetyTest extends TestCase
{
    private function client(MockHandler|array $responses): PiiProtectClient
    {
        $stack = HandlerStack::create($responses instanceof MockHandler ? $responses : new MockHandler($responses));
        $client = new PiiProtectClient('https://engine.test/api', 'key');
        (new \ReflectionProperty($client, 'httpClient'))->setValue($client, new Client([
            'base_uri' => 'https://engine.test/api/', 'handler' => $stack, 'allow_redirects' => false,
        ]));
        return $client;
    }

    public function testValidatedResultAndBasePath(): void
    {
        $mock = new MockHandler([new Response(200, [], '{"safe":true,"anonymized_text":"[PERSON_1]"}')]);
        $client = $this->client($mock);
        self::assertSame('[PERSON_1]', $client->anonymize('Mario Rossi'));
        self::assertSame('/api/v1/anonymize', $mock->getLastRequest()?->getUri()->getPath());
    }

    public function testRejectsUnsafeMissingMalformedAndErrorResponsesWithoutLeakingData(): void
    {
        $responses = [
            new Response(200, [], '{"safe":false,"anonymized_text":"private-value"}'),
            new Response(200, [], '{"anonymized_text":"private-value"}'),
            new Response(200, [], '{"safe":true}'),
            new Response(200, [], '{"safe":true,"anonymized_text":123}'),
            new Response(200, [], '{"safe":"true","anonymized_text":"private-value"}'),
            new Response(200, [], 'private-value'),
            new Response(200, [], 'null'),
            new Response(302, ['Location' => 'https://attacker.test'], 'private-value'),
            new Response(500, [], 'private-value'),
            new ConnectException('private-value', new Request('POST', 'https://engine.test')),
        ];
        foreach ($responses as $response) {
            try {
                $this->client([$response])->anonymize('private-value');
                self::fail('Unsafe response was accepted');
            } catch (\RuntimeException $error) {
                self::assertSame('PII protection failed; original data was not released.', $error->getMessage());
                self::assertNull($error->getPrevious());
            }
        }
    }

    public function testBatchPreservesKeysAndEmptyValues(): void
    {
        $client = $this->client([
            new Response(200, [], '{"safe":true,"anonymized_text":"[A]"}'),
            new Response(200, [], '{"safe":true,"anonymized_text":"[B]"}'),
        ]);
        self::assertSame(['x' => '[A]', 4 => ' ', 9 => '[B]'], $client->anonymizeBatch(['x' => 'Alice', 4 => ' ', 9 => 'Bob']));
        self::assertSame([], $client->anonymizeBatch([]));
    }

    public function testBatchDoesNotReleaseAPartialResult(): void
    {
        $client = $this->client([
            new Response(200, [], '{"safe":true,"anonymized_text":"[A]"}'),
            new Response(200, [], '{"safe":false,"anonymized_text":"Bob"}'),
        ]);
        $this->expectException(\RuntimeException::class);
        $client->anonymizeBatch(['Alice', 'Bob']);
    }

    public function testBatchValidatesBeforeSendingAnyItem(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->client([])->anonymizeBatch(['Alice', new \stdClass()]);
    }

    public function testHttpsRequiredOutsideLoopback(): void
    {
        foreach (['http://remote.test', 'ftp://localhost', 'https://user:secret@remote.test', 'not-a-url'] as $url) {
            try {
                new PiiProtectClient($url, 'key');
                self::fail('Unsafe URL accepted');
            } catch (\InvalidArgumentException $error) {
                self::assertStringNotContainsString('secret', $error->getMessage());
            }
        }
        self::assertInstanceOf(PiiProtectClient::class, new PiiProtectClient('http://localhost:8000', 'key'));
    }
}

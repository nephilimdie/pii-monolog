<?php

declare(strict_types=1);

namespace PiiProtect\Monolog;

use GuzzleHttp\Client;
use GuzzleHttp\RequestOptions;
use RuntimeException;

/** Validates protection results; errors never include upstream bodies or PII. */
class PiiProtectClient
{
    private Client $httpClient;

    public function __construct(string $engineUrl, string $apiKey, int $timeoutMs = 30000)
    {
        $url = parse_url($engineUrl);
        $local = in_array($url['host'] ?? '', ['localhost', '127.0.0.1', '[::1]'], true);
        if (!is_array($url) || empty($url['host']) || isset($url['user']) || isset($url['pass'])
            || isset($url['query']) || isset($url['fragment'])
            || (($url['scheme'] ?? '') !== 'https' && !(($url['scheme'] ?? '') === 'http' && $local))) {
            throw new \InvalidArgumentException('Use HTTPS, or HTTP on loopback for local development.');
        }
        if ($timeoutMs <= 0) {
            throw new \InvalidArgumentException('Timeout must be positive.');
        }
        $this->httpClient = new Client([
            'base_uri' => rtrim($engineUrl, '/') . '/',
            RequestOptions::TIMEOUT => $timeoutMs / 1000.0,
            RequestOptions::ALLOW_REDIRECTS => false,
            RequestOptions::HEADERS => [
                'X-API-Key' => $apiKey,
                'Content-Type' => 'application/json',
                'Accept' => 'application/json',
            ],
        ]);
    }

    public function anonymize(string $text): string
    {
        if (trim($text) === '') {
            return $text;
        }
        try {
            $response = $this->httpClient->post('v1/anonymize', [
                RequestOptions::JSON => [
                    'text' => $text,
                    'context_id' => 'monolog_' . bin2hex(random_bytes(16)),
                    'context_type' => 'generic',
                ],
            ]);
            $body = json_decode((string) $response->getBody(), true, 512, JSON_THROW_ON_ERROR);
            if ($response->getStatusCode() !== 200 || !is_array($body)
                || ($body['safe'] ?? null) !== true || !is_string($body['anonymized_text'] ?? null)) {
                throw new RuntimeException('Invalid protection result.');
            }
            return $body['anonymized_text'];
        } catch (\Throwable) {
            throw new RuntimeException('PII protection failed; original data was not released.');
        }
    }

    /** No partial result is returned if any item fails. Keys are preserved. */
    public function anonymizeBatch(array $texts): array
    {
        foreach ($texts as $text) {
            if (!is_string($text)) {
                throw new \InvalidArgumentException('Only strings are accepted.');
            }
        }
        $result = [];
        foreach ($texts as $key => $text) {
            $result[$key] = $this->anonymize($text);
        }
        return $result;
    }

}

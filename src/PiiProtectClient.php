<?php

declare(strict_types=1);

namespace PiiProtect\Monolog;

use GuzzleHttp\Client;
use GuzzleHttp\Exception\GuzzleException;
use GuzzleHttp\RequestOptions;

/**
 * Shared HTTP client for the PII Protect engine API.
 *
 * All methods are intentionally non-throwing: on any network or API error
 * the original text is returned so logging never breaks the application.
 */
class PiiProtectClient
{
    private Client $httpClient;
    private string $engineUrl;
    private string $apiKey;

    public function __construct(
        string $engineUrl,
        string $apiKey,
        int $timeoutMs = 500,
    ) {
        $this->engineUrl = rtrim($engineUrl, '/');
        $this->apiKey    = $apiKey;

        $this->httpClient = new Client([
            'base_uri'              => $this->engineUrl,
            RequestOptions::TIMEOUT => $timeoutMs / 1000.0,
            RequestOptions::HEADERS => [
                'X-API-Key'    => $this->apiKey,
                'Content-Type' => 'application/json',
                'Accept'       => 'application/json',
            ],
        ]);
    }

    /**
     * Anonymize a single text string.
     *
     * @param  string $text Raw text that may contain PII.
     * @return string       Anonymized text, or the original text on error.
     */
    public function anonymize(string $text): string
    {
        if (trim($text) === '') {
            return $text;
        }

        try {
            $response = $this->httpClient->post('/v1/anonymize', [
                RequestOptions::JSON => [
                    'text'         => $text,
                    'context_id'   => uniqid('monolog_', true),
                    'context_type' => 'generic',
                ],
            ]);

            $body = json_decode((string) $response->getBody(), true, 512, JSON_THROW_ON_ERROR);

            return $body['anonymized_text'] ?? $text;
        } catch (\Throwable $e) {
            $this->logError('anonymize', $e);
            return $text;
        }
    }

    /**
     * Anonymize multiple texts in a single batch request.
     *
     * @param  array<string> $texts Raw texts.
     * @return array<string>        Anonymized texts in the same order.
     *                              Falls back to original texts on error.
     */
    public function anonymizeBatch(array $texts): array
    {
        if (empty($texts)) {
            return $texts;
        }

        // Filter out empty strings but keep track of original indices
        $indexedTexts = [];
        foreach ($texts as $idx => $text) {
            if (trim((string) $text) !== '') {
                $indexedTexts[$idx] = $text;
            }
        }

        if (empty($indexedTexts)) {
            return $texts;
        }

        try {
            $items = [];
            foreach ($indexedTexts as $idx => $text) {
                $items[] = ['id' => (string) $idx, 'text' => $text];
            }

            $response = $this->httpClient->post('/v1/anonymize/batch', [
                RequestOptions::JSON => [
                    'items'        => $items,
                    'context_type' => 'generic',
                ],
            ]);

            $body = json_decode((string) $response->getBody(), true, 512, JSON_THROW_ON_ERROR);

            $anonymizedById = [];
            foreach ($body['items'] ?? [] as $item) {
                if (isset($item['id'], $item['output']) && $item['error_code'] === null) {
                    $anonymizedById[$item['id']] = $item['output'];
                }
            }

            $result = $texts;
            foreach ($indexedTexts as $idx => $text) {
                $id = (string) $idx;
                if (isset($anonymizedById[$id])) {
                    $result[$idx] = $anonymizedById[$id];
                }
            }

            return $result;
        } catch (\Throwable $e) {
            $this->logError('anonymizeBatch', $e);
            return $texts;
        }
    }

    // ------------------------------------------------------------------
    // Internals
    // ------------------------------------------------------------------

    private function logError(string $method, \Throwable $e): void
    {
        $msg = sprintf(
            '[PiiProtect] %s() failed: %s (%s:%d)' . PHP_EOL,
            $method,
            $e->getMessage(),
            $e->getFile(),
            $e->getLine(),
        );
        fwrite(STDERR, $msg);
    }
}

<?php

namespace QUI\OAuth;

final class ClientConfiguration
{
    /**
     * @param array<int, string> $redirectUris
     * @return array<int, string>
     */
    public static function validateRedirectUris(array $redirectUris): array
    {
        return self::validateUris($redirectUris, true);
    }

    /**
     * @param array<int, string> $resources
     * @return array<int, string>
     */
    public static function validateResources(array $resources): array
    {
        return self::validateUris($resources, false);
    }

    /**
     * @param mixed $value
     * @return array<int, string>
     */
    public static function decodeResources(mixed $value): array
    {
        if (!is_string($value) || trim($value) === '') {
            return [];
        }

        $decoded = json_decode($value, true);

        if (!is_array($decoded)) {
            return [];
        }

        return array_values(array_filter(
            $decoded,
            static fn(mixed $resource): bool => is_string($resource) && $resource !== ''
        ));
    }

    /**
     * @param array<int, string> $uris
     * @return array<int, string>
     */
    private static function validateUris(array $uris, bool $allowLoopbackHttp): array
    {
        $validated = [];

        foreach ($uris as $uri) {
            if (!is_string($uri)) {
                throw new \InvalidArgumentException('OAuth URI values must be strings.');
            }

            $uri = trim($uri);
            $parts = parse_url($uri);

            if (
                $uri === ''
                || !is_array($parts)
                || empty($parts['scheme'])
                || empty($parts['host'])
                || isset($parts['fragment'])
                || isset($parts['user'])
                || isset($parts['pass'])
            ) {
                throw new \InvalidArgumentException('OAuth URIs must be absolute and must not contain userinfo or fragments.');
            }

            $scheme = strtolower((string)$parts['scheme']);
            $host = strtolower((string)$parts['host']);
            $isLoopback = in_array($host, ['127.0.0.1', '::1', 'localhost'], true);

            if ($scheme !== 'https' && !($allowLoopbackHttp && $scheme === 'http' && $isLoopback)) {
                throw new \InvalidArgumentException('OAuth URIs must use HTTPS, except loopback redirect URIs.');
            }

            $validated[] = $uri;
        }

        return array_values(array_unique($validated));
    }
}

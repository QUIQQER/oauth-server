<?php

namespace QUI\OAuth;

final class ClientConfiguration
{
    private const DYNAMIC_REGISTRATION_KEY = 'dynamic_registration';
    private const RESOURCES_KEY = 'resources';

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

        if (
            isset($decoded[self::RESOURCES_KEY])
            && is_array($decoded[self::RESOURCES_KEY])
        ) {
            $decoded = $decoded[self::RESOURCES_KEY];
        }

        return array_values(array_filter(
            $decoded,
            static fn(mixed $resource): bool => is_string($resource) && $resource !== ''
        ));
    }

    /**
     * @param array<int, string> $resources
     */
    public static function encodeResources(
        array $resources,
        bool $dynamicRegistration = false
    ): string {
        $resources = self::validateResources($resources);
        $data = $dynamicRegistration
            ? [
                self::DYNAMIC_REGISTRATION_KEY => true,
                self::RESOURCES_KEY => $resources
            ]
            : $resources;

        return json_encode(
            $data,
            JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR
        );
    }

    public static function isDynamicRegistration(mixed $value): bool
    {
        if (!is_string($value) || trim($value) === '') {
            return false;
        }

        $decoded = json_decode($value, true);

        return is_array($decoded)
            && ($decoded[self::DYNAMIC_REGISTRATION_KEY] ?? false) === true;
    }

    public static function validateDynamicResource(
        string $resource,
        string $issuer
    ): string {
        return DynamicResourceTrustPolicy::validate($resource, $issuer);
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

    public static function hasSameOrigin(string $first, string $second): bool
    {
        $firstParts = parse_url($first);
        $secondParts = parse_url($second);

        if (!is_array($firstParts) || !is_array($secondParts)) {
            return false;
        }

        $firstScheme = strtolower((string)($firstParts['scheme'] ?? ''));
        $secondScheme = strtolower((string)($secondParts['scheme'] ?? ''));
        $firstHost = strtolower((string)($firstParts['host'] ?? ''));
        $secondHost = strtolower((string)($secondParts['host'] ?? ''));
        $firstPort = $firstParts['port'] ?? self::getDefaultPort($firstScheme);
        $secondPort = $secondParts['port'] ?? self::getDefaultPort($secondScheme);

        return $firstScheme === $secondScheme
            && $firstHost === $secondHost
            && $firstPort === $secondPort;
    }

    private static function getDefaultPort(string $scheme): ?int
    {
        return match ($scheme) {
            'http' => 80,
            'https' => 443,
            default => null
        };
    }
}

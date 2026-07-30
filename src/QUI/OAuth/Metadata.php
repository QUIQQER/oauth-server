<?php

namespace QUI\OAuth;

use QUI;
use QUI\REST\Server as RestServer;

final class Metadata
{
    /**
     * @return array<string, mixed>
     */
    public static function authorizationServer(
        RestServer $Server,
        ?string $requestOrigin = null
    ): array {
        $baseUrl = self::baseUrl($Server, $requestOrigin);

        $metadata = [
            'issuer' => rtrim($baseUrl, '/'),
            'authorization_endpoint' => $baseUrl . 'oauth/authorize',
            'token_endpoint' => $baseUrl . 'oauth/token',
            'revocation_endpoint' => $baseUrl . 'oauth/revoke',
            'response_types_supported' => ['code'],
            'response_modes_supported' => ['query'],
            'grant_types_supported' => [
                'authorization_code',
                'refresh_token',
                'client_credentials'
            ],
            'token_endpoint_auth_methods_supported' => [
                'client_secret_basic',
                'client_secret_post',
                'none'
            ],
            'revocation_endpoint_auth_methods_supported' => [
                'client_secret_basic',
                'client_secret_post',
                'none'
            ],
            'code_challenge_methods_supported' => ['S256'],
            'scopes_supported' => self::scopes($Server),
            'resource_parameter_supported' => true
        ];

        if (DynamicClientRegistrationEndpoint::isEnabled()) {
            $metadata['registration_endpoint'] = $baseUrl . 'oauth/register';
        }

        return $metadata;
    }

    /**
     * @return array<string, mixed>
     */
    public static function protectedResource(
        RestServer $Server,
        ?string $requestOrigin = null
    ): array {
        $resource = self::resource($Server, $requestOrigin);

        return [
            'resource' => $resource,
            'authorization_servers' => [$resource],
            'bearer_methods_supported' => ['header'],
            'scopes_supported' => self::scopes($Server),
            'resource_name' => 'QUIQQER REST API'
        ];
    }

    public static function resource(
        RestServer $Server,
        ?string $requestOrigin = null
    ): string {
        return rtrim(self::baseUrl($Server, $requestOrigin), '/');
    }

    private static function baseUrl(
        RestServer $Server,
        ?string $requestOrigin = null
    ): string {
        $configuredBaseUrl = rtrim(
            $Server->getBasePathWithHost(),
            '/'
        );

        if (self::isAbsoluteHttpUrl($configuredBaseUrl)) {
            return $configuredBaseUrl . '/';
        }

        if ($requestOrigin === null) {
            try {
                $requestOrigin = QUI::getRequest()->getSchemeAndHttpHost();
            } catch (\Throwable) {
                $requestOrigin = null;
            }
        }

        if (
            !is_string($requestOrigin)
            || !self::isAbsoluteHttpUrl($requestOrigin)
        ) {
            throw new \RuntimeException(
                'OAuth metadata requires an absolute HTTP(S) origin.'
            );
        }

        return rtrim($requestOrigin, '/') . $Server->getBasePath();
    }

    private static function isAbsoluteHttpUrl(string $url): bool
    {
        $parts = parse_url($url);

        if (!is_array($parts)) {
            return false;
        }

        $scheme = strtolower((string)($parts['scheme'] ?? ''));

        return in_array($scheme, ['http', 'https'], true)
            && !empty($parts['host'])
            && !isset($parts['user'])
            && !isset($parts['pass'])
            && !isset($parts['query'])
            && !isset($parts['fragment']);
    }

    /**
     * @return array<int, string>
     */
    private static function scopes(RestServer $Server): array
    {
        $scopes = $Server->getEntryPoints();
        sort($scopes);

        return array_values(array_unique($scopes));
    }
}

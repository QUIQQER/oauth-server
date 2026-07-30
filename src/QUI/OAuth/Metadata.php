<?php

namespace QUI\OAuth;

use QUI\REST\Server as RestServer;

final class Metadata
{
    /**
     * @return array<string, mixed>
     */
    public static function authorizationServer(RestServer $Server): array
    {
        $baseUrl = self::baseUrl($Server);

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
    public static function protectedResource(RestServer $Server): array
    {
        $resource = self::resource($Server);

        return [
            'resource' => $resource,
            'authorization_servers' => [$resource],
            'bearer_methods_supported' => ['header'],
            'scopes_supported' => self::scopes($Server),
            'resource_name' => 'QUIQQER REST API'
        ];
    }

    public static function resource(RestServer $Server): string
    {
        return rtrim(self::baseUrl($Server), '/');
    }

    private static function baseUrl(RestServer $Server): string
    {
        return rtrim($Server->getBasePathWithHost(), '/') . '/';
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
